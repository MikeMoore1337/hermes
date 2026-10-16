"""Synthetic-only cryptographic regression check. No tokens/keys printed or persisted."""
import json
import time
from importlib.metadata import version
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
private = key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo)
payload = {"sub": "synthetic", "exp": int(time.time()) + 60}
token = jwt.encode(payload, private, algorithm="RS256")
actual = jwt.decode(token, public, algorithms=["RS256"], options={"require": ["sub", "exp"]})
assert actual["sub"] == "synthetic"
parts = token.split(".")
bad_payload = jwt.utils.base64url_encode(
    json.dumps({"sub": "tampered", "exp": payload["exp"]}, separators=(",", ":")).encode()
).decode("ascii")
altered = parts[0] + "." + bad_payload + "." + parts[2]
denied = False
try:
    jwt.decode(altered, public, algorithms=["RS256"])
except jwt.InvalidSignatureError:
    denied = True
assert denied
print(json.dumps({"schema": "hermes-h18-pyjwt-crypto-smoke-v1", "version": version("PyJWT"),
                  "rs256_signed_token_accepted": True, "tampered_signature_denied": denied,
                  "resident_agent_allowed": False}, sort_keys=True))
