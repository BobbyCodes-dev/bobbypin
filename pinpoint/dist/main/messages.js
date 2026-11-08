export const MCP_CONNECTION_LOST = "Retry the tool call once only when it is safe to repeat or known not to have started. If it may already have changed the target, or it fails again, tell the user PINPOINT lost its MCP client connection and ask them to restart the MCP client.";
export const MCP_CONNECTION_START_FAILED = "Retry once. If it fails again, tell the user PINPOINT could not start its MCP connection and ask them to restart the MCP client, then run `pinpoint doctor`.";
export const MCP_SHUTDOWN_FAILED = "PINPOINT could not close cleanly. End the PINPOINT process before starting it again.";
export const SERVER_START_FAILED = "Do not repeat this startup. Tell the user PINPOINT could not start and ask them to restart the MCP client, then run `pinpoint doctor`.";
export const MCP_HTTP_LISTEN_FAILED = "PINPOINT could not listen for MCP HTTP connections on the selected host and port. Choose another --port or stop the process using it.";
