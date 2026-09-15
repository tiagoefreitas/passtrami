# Session protocol

Passtrami's Swift app owns a native engine that runs the session code in JavaScriptCore. Swift handles the browser process, downloads, timers, Unix socket, and loopback WebSocket. The CLI sends one request per connection over a Unix socket in `~/Library/Application Support/io.zats.Passtrami/`. The directory is mode `0700`; the socket is mode `0600`.

The engine starts an isolated headless browser and loads a temporary copy of Apple's extension with Passtrami's bridge appended. The bridge connects to a loopback WebSocket with a token generated for that browser session. Apple's extension communicates with the system password helper through native messaging.

## Pairing and lock

The bridge reports changes from the extension's `setGlobalState` function:

| Extension state | Passtrami behavior |
| --- | --- |
| `NotInSession` | Locked; pairing can start. |
| `ChallengeSent` | Wait for Apple's pairing challenge. |
| `MSG1Set` | Show the PIN field. |
| `SessionKeySet` | Accept password requests while this bridge remains connected. |
| `CheckEngine` | Stop treating the session as unlocked. |
| `NativeSupportNotInstalled` or `IncompatibleOS` | Report a helper connection error. |

A PIN submission is not proof of unlock. Passtrami waits for `SessionKeySet`. The app disables the PIN field while checking and clears it on an error or dismissal.

Lock closes the bridge, stops the owned browser, rejects pending requests, and removes the temporary profile. The next unlock starts a new browser session and pairing flow. This does not lock the system Keychain or the Passwords app.

## Account and password requests

The engine serializes requests and waits for unlock. For `list`, the bridge sends native command 4 with `ACT: 5` and the requested domain in `URL`. Passtrami filters the returned accounts by domain and returns unique usernames without passwords.

For `get`, the bridge sends native command 5 with an encrypted body containing `ACT: 2`, the requested domain in `URL`, and the exact username in `USR`. Passtrami checks returned records against both values before returning the password to the CLI.

Apple's helper controls authentication. A paired session can still require system authentication; a request does not guarantee a new Touch ID prompt.

Pending work belongs to the current browser session. A disconnect, lock, or failed or cancelled native request ends that session before another request can use it. This prevents a late native reply from being assigned to a later request.

State events and errors must not contain PINs, session tokens, encrypted payloads, passwords, or full credential responses. Ordinary `get` returns the password through the requesting CLI connection. MCP requests use a separate engine response path: `MCPBroker` converts the credential to a temporary pipe and returns only its metadata. The reserved `mcp:` connection prefix prevents a late password reply from reaching the ordinary CLI reply path. The app alone controls MCP enablement through its private stdin connection to the engine. See [MCP access](mcp.md).
