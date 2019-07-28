#include "config.h"

#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/packet.h>
#include <string.h>
#include <wsutil/wsgcrypt.h>

#define WOWWW_DEFAULT_PORT 8085

#define WOWWW_SERVER_TO_CLIENT pinfo->srcport  == pinfo->match_uint
#define WOWWW_CLIENT_TO_SERVER pinfo->destport == pinfo->match_uint

static int proto_woww = -1;

static int hf_woww_pdu_size = -1;
static int hf_woww_pdu_opcode = -1;
static int hf_woww_pdu_opcode_string = -1;

static gint ett_woww = -1;

static gchar* server_key = "";
static gchar* client_key = "";
static gchar* opcode_file = "";
static gcry_cipher_hd_t rc4_handle_server;
static gcry_cipher_hd_t rc4_handle_client;

static wmem_map_t *decryptedHeadersMap = NULL;
static GHashTable *opcodeMap = NULL;

static gboolean serverDecryptionReady = FALSE;
static gboolean clientDecryptionReady = FALSE;

struct WowwContext {
    guint expectedSize;
    guint32 lastNum;
    guint packet_counter;
};

struct WowwStruct {
    guint frameNumber;
    guint pduIndexInFrame;
    struct WowwContext* serverContext;
    struct WowwContext* clientContext;
};

// from packet-aoe.c
static guint
ata_cmd_hash_matched(gconstpointer k)
{
    return GPOINTER_TO_UINT(k);
}

static gint
ata_cmd_equal_matched(gconstpointer k1, gconstpointer k2)
{
    return k1 == k2;
}

static gboolean
init_rc4(const guint8 *decryption_key, gboolean isServer)
{
    gcry_cipher_hd_t* rc4_handle;
    if (isServer)
        rc4_handle = &rc4_handle_server;
    else
        rc4_handle = &rc4_handle_client;

    if (gcry_cipher_open(rc4_handle, GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM, 0)) {
        return FALSE;
    }
    if (gcry_cipher_setkey(*rc4_handle, decryption_key, 20)) {
        gcry_cipher_close(*rc4_handle);
        return FALSE;
    }

    // Drop first 1024 bytes, as WoW uses ARC4-drop1024.
    guint8 dummy[1024] = { 0 };
    gcry_cipher_decrypt(*rc4_handle, dummy, 1024, NULL, 0);
    return TRUE;
}

static gboolean
prepare_decryption(gboolean isServer)
{
    gchar* key;
    if (isServer)
        key = server_key;
    else
        key = client_key;

    // parse the keys
    int tokenCount = 0;
    guint8 decryption_key[20];

    char * key_copy = malloc(strlen(key) + 1);
    strcpy(key_copy, key);

    for (char *p = strtok(key_copy, " "); p != NULL; p = strtok(NULL, " "))
    {
        decryption_key[tokenCount] = (guint8)strtol(p, NULL, 0);
        tokenCount++;
    }

    if (tokenCount != 20) {
        return FALSE;
    }

    free(key_copy);

    // initialize rc4 state vector to be ready to decrypt
    return init_rc4(decryption_key, isServer);
}

static void
load_opcode_file()
{
    opcodeMap = g_hash_table_new(NULL, NULL);

    FILE* file = fopen(opcode_file, "r");
    char fileLine[256];

    if (!file) {
        g_log(NULL, G_LOG_LEVEL_WARNING, "Could not find wow Opcodes.h file");
        return;
    }

    const char *line_regex = "[CSU]?MSG_.*= 0x\\w+";
    const char *name_regex = "[CSU]?MSG_\\w*";
    const char *value_regex = "0x\\w+";

    GRegex *lineRegex = g_regex_new(line_regex, G_REGEX_RAW, (GRegexMatchFlags)0, NULL);
    GRegex *nameRegex = g_regex_new(name_regex, G_REGEX_RAW, (GRegexMatchFlags)0, NULL);
    GRegex *valueRegex = g_regex_new(value_regex, G_REGEX_RAW, (GRegexMatchFlags)0, NULL);

    if (!lineRegex || !nameRegex || !valueRegex) {
        g_log(NULL, G_LOG_LEVEL_WARNING, "Failed to compile regex to parse wow opcodes");
        exit(EXIT_FAILURE);
    }

    while (fgets(fileLine, sizeof(fileLine), file)) {

        GMatchInfo *match = NULL;
        g_regex_match(lineRegex, fileLine, (GRegexMatchFlags)0, &match);
        if (!g_match_info_matches(match))
            continue;

        // a line containing a (name, value) opcode pair has been found
        gchar* lineResult = g_match_info_fetch(match, 0);

        // get the name of the opcode
        GMatchInfo *nameMatch = NULL;
        g_regex_match(nameRegex, lineResult, (GRegexMatchFlags)0, &nameMatch);
        gchar* nameResult = g_match_info_fetch(nameMatch, 0);

        // get the value of the opcode
        GMatchInfo *valueMatch = NULL;
        g_regex_match(valueRegex, lineResult, (GRegexMatchFlags)0, &valueMatch);
        gchar* valueResult = g_match_info_fetch(valueMatch, 0);
        guint16 opcodeValue = (guint16) strtol(valueResult, NULL, 0);

        // do basic validation on the opcode found
        if (opcodeValue == 0) {
            g_free(lineResult);
            g_free(valueResult);
            g_free(nameResult);

            continue;
        }

        // add the pair (name, value) to the table
        g_hash_table_insert(opcodeMap, GUINT_TO_POINTER(opcodeValue), (void*)nameResult);

        g_free(lineResult);
        g_free(valueResult);
    }

    fclose(file);
}

static void
initialize_protocol(void)
{
    serverDecryptionReady = prepare_decryption(TRUE);
    clientDecryptionReady = prepare_decryption(FALSE);
    decryptedHeadersMap = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), ata_cmd_hash_matched, ata_cmd_equal_matched);
    load_opcode_file();
}

static struct WowwStruct*
initialize_conversation_data(conversation_t* conv)
{
    struct WowwStruct* wowwStruct = malloc(sizeof(struct WowwStruct));
    wowwStruct->frameNumber = 0;
    wowwStruct->pduIndexInFrame = 0;

    wowwStruct->clientContext = malloc(sizeof(struct WowwContext));
    wowwStruct->clientContext->expectedSize = 0;
    wowwStruct->clientContext->lastNum = 0;
    wowwStruct->clientContext->packet_counter = 0;

    wowwStruct->serverContext = malloc(sizeof(struct WowwContext));
    wowwStruct->serverContext->expectedSize = 0;
    wowwStruct->serverContext->lastNum = 0;
    wowwStruct->serverContext->packet_counter = 0;

    conversation_add_proto_data(conv, proto_woww, wowwStruct); //todo: malloc without free here!

    return wowwStruct;
}

static guint8*
decrypt_rc4(const guint8 *encrypted_keydata, guint encrypted_keydata_len, gboolean isServer)
{
    gcry_cipher_hd_t* rc4_handle;
    if (isServer)
        rc4_handle = &rc4_handle_server;
    else
        rc4_handle = &rc4_handle_client;

    guint8 *decrypted_key = wmem_alloc_array(wmem_file_scope(), guint8, encrypted_keydata_len);
    if (!decrypted_key) {
        return NULL;
    }

    gcry_cipher_decrypt(*rc4_handle, decrypted_key, encrypted_keydata_len, encrypted_keydata, encrypted_keydata_len);
    return decrypted_key;
}

static void
close_rc4(gboolean isServer)
{
    gcry_cipher_hd_t* rc4_handle;
    if (isServer)
        rc4_handle = &rc4_handle_server;
    else
        rc4_handle = &rc4_handle_client;

    gcry_cipher_close(*rc4_handle);
}

void
proto_register_woww(void)
{
    module_t *woww_module; /* For our preferences */

    static hf_register_info hf[] = {
        { &hf_woww_pdu_size,
            { "Size (opcode + payload)", "woww.size",
            FT_UINT24, BASE_HEX_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_woww_pdu_opcode,
            { "Opcode value", "woww.opcode.value",
            FT_UINT16, BASE_HEX_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_woww_pdu_opcode_string,
            { "Opcode name", "woww.opcode.name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_woww
    };

    proto_woww = proto_register_protocol (
        "WOWW Protocol", /* name       */
        "WOWW",      /* short name */
        "woww"       /* abbrev     */
        );

    proto_register_field_array(proto_woww, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    woww_module = prefs_register_protocol(proto_woww, NULL);
    prefs_register_string_preference(woww_module, "server_key", "server encryption key", NULL, &server_key);
    prefs_register_string_preference(woww_module, "client_key", "client encryption key", NULL, &client_key);
    prefs_register_filename_preference(woww_module, "opcodes_file", "Opcodes file (Opcodes.h)", NULL, &opcode_file, FALSE);
    register_init_routine(initialize_protocol);
}

/*
    Read and decrypt the header of the packet

    - read the header: first N bytes (4-5 from server, 6 from client).
    - then decrypt those N bytes (an exception is made for the first packet on each direction since these two are not encrypted.
*/
static guint8*
get_decrypted_header(tvbuff_t *tvb, packet_info *pinfo _U_, int offset)
{
    conversation_t* conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
    struct WowwStruct* wowwStruct = (struct WowwStruct*) conversation_get_proto_data(conv, proto_woww);
    struct WowwContext* context = WOWWW_SERVER_TO_CLIENT ? wowwStruct->serverContext : wowwStruct->clientContext;

    guint8* decryptedHeader;
    context->packet_counter++;

    if (WOWWW_SERVER_TO_CLIENT) { // packet from server to client

        // the header fits into 4 or 5 bytes. the exact length can only be determined after decryption, by looking at the first bit. if that bit is set, then the header length is 5 bytes. Otherwise, it's 4 bytes.
        guint8 header[5];
        for (int i = 0; i < 4; i++) {
            header[i] = tvb_get_guint8(tvb, offset + i);
        }

        // the first packet on each direction is uncrypted
        if (context->packet_counter == 1) {
            decryptedHeader = wmem_alloc_array(wmem_file_scope(), guint8, 4);
            memcpy(decryptedHeader, header, 4);
        }
        else {
            // decrypt first byte
            guint8* decryptedFirstByte = decrypt_rc4(header, 1, TRUE);
            guint8* remainingHeader;
            decryptedHeader = wmem_alloc_array(wmem_file_scope(), guint8, 5);
            decryptedHeader[0] = *decryptedFirstByte;
            if (*decryptedFirstByte & 0x80) {
                header[4] = tvb_get_guint8(tvb, offset + 4); // todo: this is so ugly. come on man. start cleaning up this code.
                remainingHeader = decrypt_rc4(header +1 , 4, TRUE);
                memcpy(decryptedHeader + 1, remainingHeader, 4);
            }
            else {
                remainingHeader = decrypt_rc4(header + 1, 3, TRUE);
                memcpy(decryptedHeader + 1, remainingHeader, 3);
            }
        }
    }
    else { // packet from client to server

        // the header fits into 6 bytes
        guint8 header[6];
        for (int i = 0; i < 6; i++) {
            header[i] = tvb_get_guint8(tvb, offset + i);
        }

        // the first packet on each direction is uncrypted
        if (context->packet_counter == 1) {
            decryptedHeader = wmem_alloc_array(wmem_file_scope(), guint8, 6);
            memcpy(decryptedHeader, header, 6);
        }
        else {
            decryptedHeader = decrypt_rc4(header, 6, FALSE);
        }
    }

    return decryptedHeader;
}

static void
insert_element_in_map_list(guint32 frame_number, guint8* decryptedHeader)
{
    GList* list = (GList*)wmem_map_lookup(decryptedHeadersMap, GUINT_TO_POINTER(frame_number));
    list = g_list_append(list, decryptedHeader);
    wmem_map_insert(decryptedHeadersMap, GUINT_TO_POINTER(frame_number), list);
}

static guint8*
get_nth_element_in_map_list(guint32 frame_number, guint n)
{
    GList* list = (GList*)wmem_map_lookup(decryptedHeadersMap, GUINT_TO_POINTER(frame_number));
    return (guint8 *) g_list_nth_data(list, n);
}

static guint8*
get_last_element_in_map_list(guint32 frame_number)
{
    GList* list = (GList*)wmem_map_lookup(decryptedHeadersMap, GUINT_TO_POINTER(frame_number));
    return (guint8*) g_list_last(list)->data;
}

static guint
get_length_of_map_list(guint32 frame_number)
{
    GList* list = (GList*)wmem_map_lookup(decryptedHeadersMap, GUINT_TO_POINTER(frame_number));
    return g_list_length(list);
}

/* determine PDU length of protocol woww */
static guint
get_woww_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    conversation_t* conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
    struct WowwStruct* wowwStruct = (struct WowwStruct*) conversation_get_proto_data(conv, proto_woww);
    if (wowwStruct == NULL) {
        wowwStruct = initialize_conversation_data(conv);
    }

    struct WowwContext* context = WOWWW_SERVER_TO_CLIENT ? wowwStruct->serverContext : wowwStruct->clientContext;

        
    guint8* decryptedHeader;
    if (!pinfo->fd->visited) {

        if (context->expectedSize) {
            if ((gint)tvb_captured_length(tvb) >= context->expectedSize) {
                // we have enough data now to restruct at least one PDU now.
                // dissect_woww_message will be called next
                // we need to prepare the map lookup

                guint retValue = context->expectedSize;
                context->expectedSize = 0;
                guint8* decryptedHeader = get_last_element_in_map_list(context->lastNum);
                insert_element_in_map_list(pinfo->num, decryptedHeader);

                return retValue;
            }
            else {
                g_assert_not_reached();
            }
        }

        decryptedHeader = get_decrypted_header(tvb, pinfo, offset);
        // decryptedHeadersMap maps between pinfo->num and a queue that contains all decrypted headers found in that frame. multiple PDU can be contained in a single TCP segment or re-assembled TCP segments.
        insert_element_in_map_list(pinfo->num, decryptedHeader);
        context->lastNum = pinfo->num;
    }
    else {
        if (wowwStruct->frameNumber != pinfo->num) {
            wowwStruct->frameNumber = pinfo->num;
            wowwStruct->pduIndexInFrame = 0;
        }
        else {
            wowwStruct->pduIndexInFrame = (wowwStruct->pduIndexInFrame + 1) % get_length_of_map_list(pinfo->num);
        }

        decryptedHeader = get_nth_element_in_map_list(pinfo->num, wowwStruct->pduIndexInFrame);
    }

    guint pduSize; // = length of the size field + length of the opcode field + length of the payload
    if (WOWWW_SERVER_TO_CLIENT && decryptedHeader[0] & 0x80) { // this flag indicate that the size will be encoded in 3 bytes instead of just 2.
        pduSize = ((decryptedHeader[0] & 0x7F) << 16) + (decryptedHeader[1] << 8) + decryptedHeader[2] + 3; // +3 is needed to take into account the size value itself.
    }
    else {
        pduSize = (decryptedHeader[0] << 8) + decryptedHeader[1] + 2; // +2 is needed to take into account the size value itself.
    }

    guint capturedLength = tvb_captured_length(tvb);
    if (pduSize > capturedLength) {
        context->expectedSize = pduSize;
    }

    return pduSize;
}

/* This method dissects fully reassembled messages */
static int
dissect_woww_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
    conversation_t* conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
    struct WowwStruct* wowwStruct = (struct WowwStruct*) conversation_get_proto_data(conv, proto_woww);
    guint8* decryptedHeader = decryptedHeader = pinfo->fd->visited ? get_nth_element_in_map_list(pinfo->num, wowwStruct->pduIndexInFrame) : get_last_element_in_map_list(pinfo->num);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WOWW");
    col_clear(pinfo->cinfo, COL_INFO);

    guint16 sizeLength; // length of the "size" portion of the PDU. for ServerToClient packets: 2 or 3 bytes ; for ClientToServer packets: 2 bytes.
    guint32 reportedSize; // = content of the "size" portion of the PDU. it is equal to size of the payload + the opcode.
    guint16 opcodeLength; // length of the "opcode" portion of the PDU. for ServerToClient packets: 2 bytes ; for ClientToServer packets: 4 bytes but the value fits into 2 bytes.
    guint16 opcode;
    if (WOWWW_SERVER_TO_CLIENT) {
        opcodeLength = 2;
        if (decryptedHeader[0] & 0x80) { // this flag indicate that the size will be encoded in 3 bytes instead of just 2.
            sizeLength = 3;
            reportedSize = ((decryptedHeader[0] & 0x7F) << 16) + (decryptedHeader[1] << 8) + decryptedHeader[2];
            opcode = decryptedHeader[3] + (decryptedHeader[4] << 8);
        }
        else {
            sizeLength = 2;
            reportedSize = (decryptedHeader[0] << 8) + decryptedHeader[1];
            opcode = decryptedHeader[2] + (decryptedHeader[3] << 8);
        }
    }
    else {
        opcodeLength = 4;
        sizeLength = 2;
        reportedSize = (decryptedHeader[0] << 8) + decryptedHeader[1];
        opcode = decryptedHeader[2] + (decryptedHeader[3] << 8);
    }

    guint32 pduSize = reportedSize + sizeLength;
    guint32 payloadSize = reportedSize - opcodeLength; // the 2 is the opcode length
    guint16 headerSize = sizeLength + opcodeLength;

    guint8 *buffer = (guint8*)wmem_alloc(wmem_packet_scope(), pduSize);
    memcpy(buffer, decryptedHeader, headerSize);
    memcpy(buffer + headerSize, tvb_get_ptr(tvb, headerSize, payloadSize), payloadSize);
    tvbuff_t *next_tvb = tvb_new_child_real_data(tvb, buffer, pduSize, pduSize);
    add_new_data_source(pinfo, next_tvb, "Decrypted Data");

    if (opcode < g_hash_table_size(opcodeMap) && opcode > 0) {
        gchar* nameResult = (gchar*)g_hash_table_lookup(opcodeMap, GUINT_TO_POINTER(opcode));

        proto_item *ti = proto_tree_add_item(tree, proto_woww, next_tvb, 0, -1, ENC_NA);
        proto_tree *woww_tree = proto_item_add_subtree(ti, ett_woww);

        col_set_str(pinfo->cinfo, COL_INFO, nameResult);
        proto_tree_add_uint(woww_tree, hf_woww_pdu_size, next_tvb, 0, sizeLength, reportedSize);
        proto_tree_add_uint(woww_tree, hf_woww_pdu_opcode, next_tvb, sizeLength, opcodeLength, opcode);
        proto_tree_add_string(woww_tree, hf_woww_pdu_opcode_string, next_tvb, sizeLength, opcodeLength, nameResult);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_woww(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    if (WOWWW_SERVER_TO_CLIENT && serverDecryptionReady) {
        tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, get_woww_message_len, dissect_woww_message, data);
        return tvb_captured_length(tvb);
    }
    else if(WOWWW_CLIENT_TO_SERVER && clientDecryptionReady) {
        tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 6, get_woww_message_len, dissect_woww_message, data);
        return tvb_captured_length(tvb);
    }

    return tvb_captured_length(tvb);
}

void
proto_reg_handoff_woww(void)
{
    static dissector_handle_t woww_handle;

    woww_handle = create_dissector_handle(dissect_woww, proto_woww);
    dissector_add_uint_with_preference("tcp.port", WOWWW_DEFAULT_PORT, woww_handle);
}
