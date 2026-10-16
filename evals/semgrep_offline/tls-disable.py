import requests
import httpx

def insecure(endpoint):
    # ruleid: hermes-requests-verify-false
    requests.get(endpoint, verify=False, timeout=2)
    # ruleid: hermes-requests-verify-false
    requests.post(endpoint, data=b"", verify=False, timeout=2)
    # ruleid: hermes-requests-verify-false
    requests.request("GET", endpoint, verify=False, timeout=2)
    # ruleid: hermes-requests-verify-false
    httpx.Client(verify=False)

def secure(endpoint):
    # ok: hermes-requests-verify-false
    requests.get(endpoint, verify=True, timeout=2)
    # ok: hermes-requests-verify-false
    httpx.Client(verify=True)
