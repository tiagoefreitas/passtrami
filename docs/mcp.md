# MCP access

Use Passtrami when a user-authorized task needs a password saved in Apple Passwords, whether it uses a browser, application, command-line tool, or script. The agent can select Passtrami without the user naming it. Use only the intended service and account; never ask the user to paste a password into the conversation.

Enable **Settings → Tools → MCP → Enable MCP**, then select **Copy Configuration**. Add that JSON to a client that supports stdio MCP. The helper is `passtrami-mcp` inside the current app's Resources folder. It starts Passtrami by bundle identifier when needed. It does not need the CLI shortcut, a network port, or a second password engine.

MCP is disabled until enabled in the app. The helper cannot change this setting. Initialization and static documentation remain available while disabled, but account and password access is rejected by the engine. `status` reports the setting without starting authentication.

## Tools

| Tool | Arguments | Result |
| --- | --- | --- |
| `status` | None | MCP enabled state and password session state. |
| `list_accounts` | `domain` | Account names for the domain; no passwords. |
| `prepare_password` | `domain`, `username` | `lease_id`, `path`, `expires_at`, `format: "utf8"`, `single_use: true`. |
| `revoke_password` | `lease_id` | Removes an unused pipe owned by this MCP session. |

`prepare_password` uses the same domain matching, username check, and approval flow as the CLI. Enter Apple's unlock code on the Mac when required. If iPhone approval is enabled in **Settings → Devices**, approve the request on the paired iPhone. Otherwise, Apple handles local authentication. The tool returns only after it has prepared the password for delivery.

The helper uses the official Swift MCP SDK. It supplies initialization instructions and the static resource `passtrami://docs/credential-access`. Resource reads cannot access a password pipe. MCP errors use fixed messages, not raw native credential responses.

## Agent flow

1. Read `passtrami://docs/credential-access`.
2. Call `status`. If disabled, ask the user to enable MCP in Settings.
3. Call `list_accounts` if the account is not known. Do not guess which account the user wants.
4. Prepare the program that will use the password before requesting it. The program must read the pipe internally, perform the intended task, and return only a nonsecret result.
5. Call `prepare_password` with the domain and exact username. Let the user complete the Mac PIN prompt and the selected approval flow.
6. Immediately start the prepared program with only the returned path as its password input. Keep the password out of agent tool arguments, output, and logs.
7. If the operation is cancelled before use, call `revoke_password`.

A Python consumer can receive the path as an argument and pass the value directly to its login implementation:

```python
import sys
from pathlib import Path

# The path is metadata. The password stays in this program.
password = Path(sys.argv[1]).read_bytes().decode("utf-8")
if not password:
    raise SystemExit("Password access was cancelled. Request a new pipe.")
# Call the application's login function with password here.
# Return only the nonsecret outcome. Do not print password or exception payloads.
```

This example only shows consumption. Each application must supply its actual login operation. Do not run this consumer just to inspect the value: that would consume the one-use pipe without completing the requested operation.

## Delivery and limits

These tools provide saved passwords. Verification codes are not supported.

The engine creates a mode `0600` FIFO in its mode `0700` `password-pipes` directory. It retains the value only in memory until a reader connects. It opens the writer without blocking, checks the FIFO identity, removes the path, and writes the UTF-8 password once, with no newline. Credentials larger than `PIPE_BUF` (512 bytes on macOS) are rejected so delivery fits one atomic write.

An unused pipe expires after 60 seconds. At most 16 pipes and 16 pending MCP account/password requests are allowed. A read attempt consumes the lease, including a reader that closes early. Revocation releases a waiting reader without sending a password; the consumer must treat an empty read as failure. There is no retry of that lease; request a new one if needed.

Lock, loss of the unlocked state, browser shutdown, MCP disable, and app shutdown revoke unused pipes. Explicit lock and MCP disable cancel pending MCP requests. A normal helper shutdown revokes its session's leases. If the helper is killed, the 60-second expiry still applies. Engine restart removes stale FIFO paths. A failed metadata response also revokes its pipe.

Once a value is delivered, Passtrami cannot remove it from the consumer's memory. FIFO permissions do not isolate two processes running as the same user. Multiple readers must not open one lease. This design keeps passwords out of normal MCP messages; it does not stop unrestricted local code from reading a pipe, running `passtrami get`, or printing a password. Never send the pipe contents to an agent tool result, log, or transcript.

## Remembered approval

Settings → Tools → MCP → Remember iPhone Approval defaults to **2 hours**. Choose Never or a duration up to 24 hours. A verified iPhone approval applies to the same normalized domain and exact username on the same MCP connection until its original deadline; reuse does not extend it. Other connections, accounts and CLI requests require their own approval.

Only the approval is retained in engine memory. Each use validates the current phone pairing and retrieves a fresh password into a new single-use pipe. Apple authentication and the guarded access window still apply. Disconnecting the MCP session, locking/restarting Passtrami, disabling MCP, unpairing, or changing approval settings clears remembered approvals. Pipe lifetime remains 60 seconds.
