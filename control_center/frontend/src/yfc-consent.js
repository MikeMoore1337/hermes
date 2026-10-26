/** Transient owner pairing; the transferred access token is never stored. */
export function validYfcConsentMessage(event,origin,expectedWindow,expectedNonce){
 return event?.origin===origin&&event?.source===expectedWindow&&
  expectedWindow!=null&&typeof expectedNonce==="string"&&
  /^[0-9a-f]{64}$/.test(expectedNonce)&&
  event.data?.type==="yfc-root-editorial-consent-v1"&&
  event.data?.nonce===expectedNonce&&
  typeof event.data?.token==="string"&&
  /^[A-Za-z0-9._-]{20,4096}$/.test(event.data.token);
}
