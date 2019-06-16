local session_keys_file = "PUT_PATH_TO_WRITABLE_FILE_HERE"

function debugger_onBreakpoint()
	f = io.open(session_keys_file,"a");
	f:write(os.date(), "\n");

	table = readBytes(EDI, 20, true)
	serverKey=""
	for i, v in ipairs(table) do serverKey = serverKey .. string.format("0x%x", v) .. " " end
	f:write("SERVER_ENCRYPTION_KEY: ");
	f:write(serverKey, "\n");

    table = readBytes(ESI, 20, true)
	clientKey=""
	for i, v in ipairs(table) do clientKey = clientKey .. string.format("0x%x", v) .. " " end
	f:write("CLIENT_ENCRYPTION_KEY: ");
	f:write(clientKey, "\n");

  	f:close();

	debug_continueFromBreakpoint(co_run)
	return 1
end

print("--------")
print("--------")
openProcess("Wow.exe")
debugProcess()
debug_setBreakpoint(0x00466D64)