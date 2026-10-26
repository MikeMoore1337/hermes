// An independent YFC Root session runs only inside the YFC-owned popup.
// No bearer, persistent credential or publication privilege crosses origins.
const PROTOCOL = "yfc-owner-editorial-bridge-v1";
const ORIGIN = "https://app.your-fitness-coach.ru";
const URL = ORIGIN + "/admin/hermes-bridge";
const TIMEOUT = 15000;
const ID = /^[0-9a-f]{32}$/;
const randomHex = (bytes) =>
  Array.from(crypto.getRandomValues(new Uint8Array(bytes)), x => x.toString(16).padStart(2, "0")).join("");

export function createYfcEditorialBridge({onGranted, onDisconnected}) {
  let popup = null;
  let nonce = null;
  let granted = false;
  let destroyed = false;
  const pending = new Map();

  function rejectAll() {
    for (const item of pending.values()) {
      clearTimeout(item.timer);
      item.signal?.removeEventListener("abort", item.abort);
      item.reject(Error("yfc_request_unavailable"));
    }
    pending.clear();
  }
  function send(value) {
    if (!popup || popup.closed) throw Error("yfc_popup_unavailable");
    popup.postMessage({protocol: PROTOCOL, nonce, ...value}, ORIGIN);
  }
  function receive(event) {
    if (destroyed || event.origin !== ORIGIN || event.source !== popup ||
        !event.data || typeof event.data !== "object" ||
        event.data.protocol !== PROTOCOL) return;
    const message = event.data;
    if (message.kind === "ready" && nonce) {
      try { send({kind: "hello"}); } catch { disconnect(false); }
      return;
    }
    if (!nonce || message.nonce !== nonce) return;
    if (message.kind === "granted") {
      if (!granted) { granted = true; onGranted?.(); }
      return;
    }
    if (message.kind !== "response" || !ID.test(message.request_id)) return;
    const task = pending.get(message.request_id);
    if (!task) return;
    pending.delete(message.request_id);
    clearTimeout(task.timer);
    task.signal?.removeEventListener("abort", task.abort);
    if (message.ok === true && "data" in message) task.resolve(message.data);
    else task.reject(Error("yfc_request_unavailable"));
  }
  window.addEventListener("message", receive);

  function connect() {
    if (destroyed) throw Error("yfc_popup_unavailable");
    if (popup && !popup.closed) { popup.focus(); return; }
    rejectAll();
    nonce = randomHex(32);
    granted = false;
    popup = window.open(URL, "yfc-owner-editorial-bridge",
      "popup,width=660,height=760,resizable=yes,scrollbars=yes");
    if (!popup) { nonce = null; throw Error("yfc_popup_blocked"); }
    // YFC signals ready only after its own authenticated Root frontend loads.
  }
  function request(action, payload = {}, signal) {
    if (!granted || !nonce || !popup || popup.closed)
      return Promise.reject(Error("yfc_popup_unavailable"));
    if (!["list", "detail", "publish"].includes(action))
      return Promise.reject(Error("yfc_request_unavailable"));
    if (signal?.aborted) return Promise.reject(Error("yfc_request_unavailable"));
    return new Promise((resolve, reject) => {
      const id = randomHex(16);
      const finish = () => {
        const item = pending.get(id);
        if (!item) return;
        pending.delete(id);
        clearTimeout(item.timer);
        item.signal?.removeEventListener("abort", item.abort);
        reject(Error("yfc_request_unavailable"));
      };
      const timeout = action === "publish" ? 180000 : TIMEOUT;
      const timer = setTimeout(finish, timeout);
      pending.set(id, {resolve, reject, timer, signal, abort: finish});
      signal?.addEventListener("abort", finish, {once: true});
      try { send({kind: "request", request_id: id, action, payload}); }
      catch { finish(); }
    });
  }
  function disconnect(close = true) {
    if (destroyed) return;
    if (granted && popup && !popup.closed) {
      try { send({kind: "disconnect"}); } catch { /* popup is gone */ }
    }
    rejectAll();
    granted = false; nonce = null;
    if (close && popup && !popup.closed) popup.close();
    popup = null;
    onDisconnected?.();
  }
  function destroy() {
    disconnect(false);
    destroyed = true;
    window.removeEventListener("message", receive);
  }
  return {connect, request, disconnect, destroy, isConnected: () => granted};
}
