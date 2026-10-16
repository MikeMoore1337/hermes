import jwt

def insecure(token):
    # ruleid: hermes-jwt-verify-disabled
    return jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])

def secure(token, key):
    # ok: hermes-jwt-verify-disabled
    return jwt.decode(token, key, algorithms=["HS256"], options={"verify_signature": True})
