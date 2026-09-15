// SPDX-License-Identifier: GPL-3.0-or-later
// Adapted from APW 1.1.1 ext/bridge.js. Runs after Apple's original background.js.
(function passtramiBridge() {
  const { port, token } = self.PASSTRAMI_CONFIG;
  let ws, pending, nativeReady = false;
  const send = (value) => ws?.readyState === WebSocket.OPEN && ws.send(JSON.stringify(value));
  const state = () => send({ type: "nativeState", state:
    !nativeReady && ["NotInSession", "CheckEngine"].includes(g_theState) ? "Connecting" : g_theState });
  const originalSetState = setGlobalState;
  setGlobalState = function (...args) {
    const result = originalSetState.apply(this, args);
    state();
    return result;
  };
  function request(message) {
    try {
      if (message.op === "unlock") { ChallengePIN(); return state(); }
      if (message.op === "pin") { PINSet(message.pin); return; }
      if (g_theState !== "SessionKeySet") return send({ id: message.id, status: 9 });
      pending = { id: message.id, cmd: message.cmd };
      const SMSG = g_secretSession.createSMSG(JSON.stringify(message.body));
      g_nativeAppPort.postMessage({ cmd: message.cmd, tabId: message.tabId, frameId: message.frameId,
        url: message.url, payload: JSON.stringify({ QID: message.qid, SMSG }) });
    } catch (_) {
      pending = null;
      send({ id: message.id, status: 100 });
    }
  }
  function reply(message) {
    if (message.cmd === 14) nativeReady = true;
    state();
    if (!pending || message.cmd !== pending.cmd) return;
    const id = pending.id;
    pending = null;
    try {
      const data = message.payload ? JSON.parse(g_secretSession.parseSMSG(message.payload.SMSG)) : { STATUS: message.STATUS ?? 0 };
      send({ id, data });
    } catch (_) { send({ id, status: 100 }); }
  }
  function attachNative() {
    if (!g_nativeAppPort) connectToBackgroundNativeAppAndSetUpListeners();
    g_nativeAppPort?.onMessage?.addListener(reply);
  }
  // Apple replaces this port when its native host exits. Attach to each new port.
  const originalConnect = connectToBackgroundNativeAppAndSetUpListeners;
  connectToBackgroundNativeAppAndSetUpListeners = function (...args) {
    nativeReady = false;
    const result = originalConnect.apply(this, args);
    g_nativeAppPort?.onMessage?.addListener(reply);
    return result;
  };
  function connect() {
    ws = new WebSocket(`ws://127.0.0.1:${port}`);
    ws.onopen = () => { send({ token }); state(); };
    ws.onmessage = ({ data }) => request(JSON.parse(data));
    ws.onerror = () => ws.close();
    ws.onclose = () => { pending = null; setTimeout(connect, 1000); };
  }
  attachNative();
  connect();
})();
