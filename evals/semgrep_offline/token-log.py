import logging
import os

logger = logging.getLogger(__name__)

def insecure():
    # ruleid: hermes-environment-secret-logged
    print(os.environ["FAKE_API_TOKEN"])
    # ruleid: hermes-environment-secret-logged
    logging.info("synthetic %s", os.environ["FAKE_SECRET"])
    # ruleid: hermes-environment-secret-logged
    logger.info("synthetic %s", os.environ["FAKE_PASSWORD"])

def safe():
    # ok: hermes-environment-secret-logged
    print(os.environ["PUBLIC_ENVIRONMENT"])
    # ok: hermes-environment-secret-logged
    logger.info("startup ok")
