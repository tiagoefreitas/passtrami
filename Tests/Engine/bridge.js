(() => {

function assert(value, message) {
  if (!value) throw new Error(message);
}

function bridgeFixture() {
  // Execute the actual bridge with local objects. No sockets or native host are created.
  return new Function(`
    const states = [], events = [];
    const self = { PASSTRAMI_CONFIG: { port: 1, token: "test-only" } };
    let g_theState = "NotInSession", socket;
    function setGlobalState(state) { g_theState = state; }
    function STATUSErrorReturned(status) { setGlobalState("NotInSession"); return "original-result"; }
    function makeNativePort() {
      // Apple's existing listener runs before the bridge listener.
      const listeners = new Set([(message) => {
        if (message.cmd === 14) setGlobalState("NotInSession");
      }]);
      return { listeners, onMessage: { addListener: (listener) => listeners.add(listener) } };
    }
    let g_nativeAppPort = makeNativePort();
    function connectToBackgroundNativeAppAndSetUpListeners() {
      g_nativeAppPort = makeNativePort();
      setGlobalState("CheckEngine");
    }
    function ChallengePIN() { throw new Error("This test must not request a challenge"); }
    function PINSet() { throw new Error("This test must not submit a PIN"); }
    class WebSocket {
      static OPEN = 1;
      readyState = 0;
      constructor() { socket = this; }
      send(text) {
        const message = JSON.parse(text);
        events.push(message);
        if (message.type === "nativeState") states.push(message.state);
      }
    }
    ${__bridgeSource}
    return {
      states, events,
      appleError(status) { return STATUSErrorReturned(status); },
      open() { socket.readyState = WebSocket.OPEN; socket.onopen(); },
      setState(state) { setGlobalState(state); },
      reply(cmd) { for (const listener of g_nativeAppPort.listeners) listener({ cmd }); },
      reconnect() { connectToBackgroundNativeAppAndSetUpListeners(); }
    };
  `)();
}

test("bridge waits for native capabilities before reporting unlock-ready state", () => {
  const fixture = bridgeFixture();
  fixture.open();
  fixture.setState("CheckEngine");
  fixture.setState("NotInSession");
  fixture.reply(3);
  assert(fixture.states.length === 4, "Missing early state reports");
  assert([...fixture.states].every((state) => state === "Connecting"), "The bridge became unlock-ready before cmd 14");

  fixture.reply(14);
  assert(fixture.states.at(-2) === "Connecting", "Apple's state reset bypassed the readiness gate");
  assert(fixture.states.at(-1) === "NotInSession", "The capability reply did not enable unlock");
});

test("bridge waits for fresh capabilities when the native port is replaced", () => {
  const fixture = bridgeFixture();
  fixture.open();
  fixture.reply(14);
  assert(fixture.states.at(-1) === "NotInSession", "The initial native port did not become ready");
  fixture.states.length = 0;

  fixture.reconnect();
  fixture.setState("NotInSession");
  fixture.reply(3);
  assert([...fixture.states].every((state) => state === "Connecting"), "The replacement port inherited readiness");
  fixture.reply(14);
  assert(fixture.states.at(-1) === "NotInSession", "The replacement port did not become ready after cmd 14");
});

test("bridge records Apple's error before the state reset without changing its handler", () => {
  const fixture = bridgeFixture();
  fixture.open(); fixture.reply(14); fixture.setState("SessionKeySet");
  fixture.events.length = 0;
  assert(fixture.appleError(9) === "original-result", "The diagnostic hook changed Apple's return value");
  assert(JSON.stringify(fixture.events[0]) === JSON.stringify({type:"diagnostic", name:"apple_error", value:9}),
         "Diagnostics did not precede the reset or contained extra fields");
  assert(fixture.events[1].state === "NotInSession", "Diagnostics suppressed Apple's reset");
});

})();
