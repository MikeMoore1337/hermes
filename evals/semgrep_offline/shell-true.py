import subprocess

def dangerous(input_text):
    # ruleid: hermes-subprocess-shell-true
    subprocess.run(input_text, shell=True)
    # ruleid: hermes-subprocess-shell-true
    subprocess.Popen(input_text, shell=True, timeout=1)
    # ruleid: hermes-subprocess-shell-true
    subprocess.call(input_text, shell=True)

def safer(arguments):
    # ok: hermes-subprocess-shell-true
    subprocess.run(["echo", "hello"], check=True, shell=False)
    # ok: hermes-subprocess-shell-true
    subprocess.run(arguments, shell=False, timeout=2)
