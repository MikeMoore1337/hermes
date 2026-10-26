import test from "node:test";
import assert from "node:assert/strict";
import {validYfcConsentMessage} from "./yfc-consent.js";

const windowRef={postMessage(){}};
const origin="https://app.your-fitness-coach.ru";
const nonce="a".repeat(64);
const token="ephemeral_root_owner_access_token_1234567890";
const event={origin,source:windowRef,data:{type:"yfc-root-editorial-consent-v1",nonce,token}};

test("only intended YFC popup and exact one-use challenge can provide Root consent",()=>{
 assert.equal(validYfcConsentMessage(event,origin,windowRef,nonce),true);
 for(const fake of [
  {...event,origin:"https://attacker.example"},
  {...event,origin:"https://yfc.attacker.example"},
  {...event,source:{}},
  {...event,data:{...event.data,type:"other"}},
  {...event,data:{...event.data,nonce:"b".repeat(64)}},
  {...event,data:{...event.data,token:"short"}},
  {...event,data:{...event.data,token:"inject\nhello"}},
  {...event,data:{...event.data,token:null}},
 ]){
  assert.equal(validYfcConsentMessage(fake,origin,windowRef,nonce),false);
 }
 assert.equal(validYfcConsentMessage(event,origin,null,nonce),false);
 assert.equal(validYfcConsentMessage(event,origin,windowRef,null),false);
});
