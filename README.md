# World of Warcraft Wireshark dissector

This project is a World of Warcraft Wireshark dissector for the version 3.3.5a (build 12340) of the game. The protocol name displayed in Wireshark is "WOWW" for "World of Warcraft **World**". This name has been chosen to avoid a naming conflict with another dissector in Wireshark named WOW, which dissects the communication between a client and a World Of Warcraft **Authentication** server. WOWW however dissects the communication between a client and a World of Warcraft **World** server.

## How to install

The dissector is bundled as a Wireshark plugin. More information can be found here: https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html

### On Windows:
Download the woww.dll DLL file from the release tab. Then copy the DDL file to either:

* the personal plugin folder: %APPDATA%\Wireshark\plugins\3.0\epan.
* the global plugin folder: WIRESHARK\plugins\3.0\epan. 

where #APPDATA# and WIRESHARK are defined here: https://www.wireshark.org/docs/wsug_html_chunked/ChConfigurationPluginFolders.html

The DLL has been tested with Wireshark 3.0.2 64bits on Windows 10. For a different version, you may need to compile the dissector yourself (see "How to compile" section below).

### On Linux 
Linux is also supported but you need to compile the dissector from source and generate the "woww.so" file by yourself. Instruction provided in the official Wireshark documentation and the "How to compile" section below. 

## How to use

WoW uses an symmetric encryption cypher called RC4 to encrypt and decrypt the header (size and opcode) of each packet. RC4 is a stream cypher that gets initialized by a secret key (also called session key because the key will only be used during one session). In order for the dissector to work, we need to provide it with two keys:

key a, the key that will initialize the RC4 internal state that:

* the server will use to encrypt the packets it sends. 
* the client will use to decrypt the packets it receives.

key b, the key that will initialize the RC4 internal state that:

* the client will use to encrypt the packets it sends.
* the server will use to decrypt the packets it receives. 

Even though the server and the client will both have both keys, by convention in this project, we will call key a "the server key" (because the server uses it encrypt and therefore we will use that key to decrypt the packets coming from the server) and key b "the client key" (because the client uses it to encrypt and therefore we will use that key to decrypt the packets coming from the clients).

Now the question is: How do we get these 2 keys? Without going much into the details, the 2 RC4 keys are the result of the key exchange mechanism that WoW uses (SPR6) when the client authenticate itself with the server. In order to obtain these 2 keys, I wrote a LUA script (located in the folder "cheat engine script") that runs on [Cheat Engine](https://github.com/cheat-engine/cheat-engine). This script hooks into the client and print into a file the 2 session keys. These 2 session keys can then be given to Wireshark to enable the decryption of the WoW packets. 

The location to the file has to be specified by changing the value of the variable "session\_keys\_file" in the LUA script!

The output should look like this:
```
06/16/19 21:26:39
SERVER_ENCRYPTION_KEY: 0x8a 0x98 0x6f 0xf3 0xde 0xd8 0x87 0x2e 0x58 0x1e 0x9a 0x98 0x7e 0xd6 0x44 0x17 0x80 0x4e 0xd7 0xc0 
CLIENT_ENCRYPTION_KEY: 0xb4 0x7d 0x9e 0x3 0xa4 0xb7 0x98 0x92 0xb2 0x3c 0xfb 0x31 0x5f 0xbc 0x7e 0x37 0x9 0x81 0xbc 0x14 
```

Once we have this, then copy paste each key to Wireshark preferences (Edit → Preferences -> Protocol -> WOWW). Be careful to remove any trailing white space. In our case,

* What should be copied for the "server encryption key" is exactly "0x8a 0x98 0x6f 0xf3 0xde 0xd8 0x87 0x2e 0x58 0x1e 0x9a 0x98 0x7e 0xd6 0x44 0x17 0x80 0x4e 0xd7 0xc0".
* What should be copied for the "client encryption key" is exactly "0xb4 0x7d 0x9e 0x3 0xa4 0xb7 0x98 0x92 0xb2 0x3c 0xfb 0x31 0x5f 0xbc 0x7e 0x37 0x9 0x81 0xbc 0x14".

Once last thing: In order to display the name of each opcode, the path to the file "Opcodes.h" from the [TrinityCore project](https://github.com/TrinityCore/TrinityCore) (branch 3.3.5) should be provided in the "Preferences" menu. 

Once this is done, Wireshark should be able to decrypt the communications between the client and the server. 

## How to compile

Clone the Wireshark project from their official git repository into one empty folder. Then, in that folder, copy paste the content of the folder "wireshark plugin". Then follow Wireshark official documentation to build the project. You should have a protocol named "WOWW" in the preferences menu.

## Screenshots

Here is the dissector in action (with the IP addresses blurred):
![screeenshot wireshark dissector](https://user-images.githubusercontent.com/6612710/59569546-6e7c3b00-908b-11e9-92d0-4038ec53ff5e.png)

Here is what the preferences menu should look like:
![screeenshot wireshark dissector 2](https://user-images.githubusercontent.com/6612710/59569550-776d0c80-908b-11e9-8815-db929f755557.png)

## Known limitations

- For now, the dissector only gets the opcode name and the size of each PDU. The complete parsing of each packet based on the opcode is not done. It can be however added. Pull requests are welcome.
- TCP segments reassembly is still buggy. The handling of WoW PDU that are spread on multiple TCP segments is implemented but buggy. Same for a TCP segment that contains multiple WoW PDUs: implemented but still buggy.
- The code needs quite a lot of clean up and there are most likely memory leaks to fix. In advance: Pardon me for my C skills!

Planned to be added:

- Modify the dissector to directly read the session keys from file in order to avoid having to manually copy paste the session keys between Cheat Engine and the Wireshark preferences menu.

## Disclaimers

This dissector is provided for educational and troubleshooting purposes only. No guarantees are provided.
