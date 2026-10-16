/** PWA can only cache a fixed anonymous offline document. */
export async function registerPwa(){
 if(!("serviceWorker" in navigator) || !window.isSecureContext) return false;
 try { await navigator.serviceWorker.register("/sw.js",{scope:"/",updateViaCache:"none"}); return true; }
 catch (_error){return false;}
}
