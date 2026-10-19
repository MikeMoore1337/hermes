"""Synthetic Semgrep H-21 mutation corpus. Parse and scan ONLY; never execute.

Markers describe the *security meaning* of the next statement, not the
matcher expectation. Safe diagnostic uses and literal shell commands test FP.
Every command and credential name is synthetic.
"""
import logging
import os
import subprocess
import httpx
import jwt
import requests
from subprocess import run as aliased_run

logger = logging.getLogger(__name__)


def shell_examples(user_command):
    # h21-case: shell_run shell-true vuln
    subprocess.run(user_command, shell=True)
    # h21-case: shell_popen shell-true vuln
    subprocess.Popen(user_command, shell=True)
    # h21-case: shell_alias shell-true vuln
    aliased_run(user_command, shell=True)
    # h21-case: shell_literal_kwargs shell-true vuln
    subprocess.run(user_command, **{"shell": True})
    opts = {"shell": True}
    # h21-case: shell_dynamic_kwargs shell-true vuln
    subprocess.run(user_command, **opts)
    # h21-case: shell_safe_argv shell-true safe
    subprocess.run(["echo", "synthetic"], shell=False)
    # h21-case: shell_safe_default shell-true safe
    subprocess.run(["echo", "synthetic"])
    # h21-case: shell_static_literal shell-true safe
    subprocess.run("echo synthetic", shell=True)


def os_system_examples(user_command):
    # h21-case: os_dynamic shell-os-system vuln
    os.system(user_command)
    # h21-case: os_static shell-os-system safe
    os.system("echo synthetic")
    # h21-case: os_argv shell-os-system safe
    subprocess.run(["echo", "synthetic"], shell=False)


def tls_examples(endpoint):
    # h21-case: tls_requests tls-disable vuln
    requests.get(endpoint, verify=False, timeout=2)
    # h21-case: tls_httpx tls-disable vuln
    httpx.Client(verify=False)
    session = requests.Session()
    # h21-case: tls_session tls-disable vuln
    session.verify = False
    # h21-case: tls_async tls-disable vuln
    httpx.AsyncClient(verify=False)
    # h21-case: tls_secure_request tls-disable safe
    requests.get(endpoint, verify=True, timeout=2)
    # h21-case: tls_secure_client tls-disable safe
    httpx.Client(verify=True)


def jwt_examples(token, key, already_rejected):
    # h21-case: jwt_literal jwt-no-verify vuln
    jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])
    options = {"verify_signature": False}
    # h21-case: jwt_options_var jwt-no-verify vuln
    jwt.decode(token, options=options, algorithms=["HS256"])
    # h21-case: jwt_verified jwt-no-verify safe
    jwt.decode(token, key, algorithms=["HS256"], options={"verify_signature": True})
    if already_rejected:
        # h21-case: jwt_diagnostics jwt-no-verify safe
        print("Rejected token header", jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"]).get("iat"))


def token_examples():
    # h21-case: secret_print token-log vuln
    print(os.environ["FAKE_API_TOKEN"])
    # h21-case: secret_logging token-log vuln
    logging.info("synthetic %s", os.environ["FAKE_SECRET"])
    # h21-case: secret_logger token-log vuln
    logger.info("synthetic %s", os.environ["FAKE_PASSWORD"])
    # h21-case: secret_fstring token-log vuln
    logger.warning(f"synthetic {os.environ['FAKE_API_TOKEN']}")
    # h21-case: secret_getenv token-log vuln
    print(os.getenv("FAKE_API_TOKEN"))
    secret = os.environ["FAKE_API_TOKEN"]
    # h21-case: secret_indirect token-log vuln
    logger.info("synthetic %s", secret)
    # h21-case: secret_public token-log safe
    print(os.environ["PUBLIC_ENVIRONMENT"])
    # h21-case: secret_constant token-log safe
    logger.info("synthetic startup")
