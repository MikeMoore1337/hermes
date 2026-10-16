import os

def unsafe(command):
    # ruleid: hermes-direct-os-system
    os.system(command)

def good():
    # ok: hermes-direct-os-system
    return os.path.basename("trusted")
