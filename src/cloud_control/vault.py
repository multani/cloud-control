import logging
import logging.handlers
import subprocess
import sys
import time
from urllib.parse import urljoin

import requests
import structlog
from requests.exceptions import HTTPError

from .config import Config
from .exceptions import VaultInitConflict
from .http import raise_http_error
from .utils import random_delay

logger = structlog.get_logger(module="vault")


class RaftNodeNotFound(Exception):
    pass


def is_vault_initialized(vault_addr: str, vault_token: str | None = None) -> bool:
    headers = {
        "x-vault-token": vault_token,
    }

    r = requests.get(f"{vault_addr}/v1/sys/init", headers=headers)
    raise_http_error(r)
    data = r.json()
    print(data)
    is_initialized = bool(data.get("initialized", False))
    return is_initialized


def find_raft_node(vault_addr: str, headers: dict[str, str], address: str) -> str:
    url = urljoin(vault_addr, "/v1/sys/storage/raft/configuration")
    r = requests.get(url, headers=headers)
    raise_http_error(r)
    data = r.json()

    for server in data["data"]["config"]["servers"]:
        if server["address"].split(":")[0] == address:
            node_id = str(server["node_id"])
            break
    else:
        logger.debug(f"Couldn't find Vault node name for {address}")
        raise RaftNodeNotFound(address)

    return node_id


def init(vault_addr: str) -> int:
    headers: dict[str, str] = {}

    config = Config.load()
    provider = config.get_provider()

    lock = provider.get_vault_initializer()

    for i in range(10):
        logger.info("Checking if Vault needs to be initialized...")
        is_initialized = is_vault_initialized(vault_addr)

        if is_initialized:
            break

        logger.debug("Trying to get a secret lock")
        try:
            lock.acquire()
        except VaultInitConflict:
            # This exception should raise on all but the very first client:
            # If a version with this value already exists and the version of the
            # SecretString and SecretBinary values are different from those in
            # the request, then the request fails because you can't modify a
            # secret version.
            # You can only create new versions to store new secret values.
            delay = random_delay()
            logger.info(f"Vault seems to be already initializing, waiting {delay}s...")
            time.sleep(delay)
        else:
            logger.info("Secret lock obtained")
            break
    else:
        logger.critical("Unable to initialize Vault, something is really wrong!")
        return 255

    if is_initialized:
        logger.info("Vault is already initialized, all good.")
        return 0

    args = {
        "stored_shares": 5,
        "recovery_shares": 5,
        "recovery_threshold": 5,
    }
    logger.info(f"Initializing Vault with: {args}")
    try:
        r = requests.put(f"{vault_addr}/v1/sys/init", headers=headers, json=args)
        raise_http_error(r)
    except HTTPError as exc:
        if is_vault_initialized(vault_addr):
            logger.info("Vault is already initialized, so we are all good.")
            return 0
        logger.critical(f"Failed to initialize: {exc}")
        raise exc

    data = r.json()

    root_token = data["root_token"]

    logger.info("Saving Vault root token")
    provider.save_root_token(root_token)

    logger.info("Vault initialized, the root token has been saved!")
    return 0


def stop(vault_addr: str) -> None:
    conf = Config.load()

    provider = conf.get_provider()
    vault_token = provider.get_root_token()

    headers = {
        "x-vault-token": vault_token,
    }

    local_address = conf.network.ip
    logging.debug(f"Local IP address={local_address}")

    logging.debug(f"Finding Raft node associated with {local_address}")
    try:
        node_id = find_raft_node(vault_addr, headers, local_address)
    except RaftNodeNotFound:
        logger.critical(f"Couldn't find Vault node name for {local_address}")
        sys.exit(1)

    logging.debug(f"Raft node for {local_address} is: {node_id}")

    r = requests.get(f"{vault_addr}/v1/sys/leader", headers=headers)
    raise_http_error(r)
    data = r.json()
    if data["is_self"]:
        logger.info("I'm the leader, proactively stepping down")
        r = requests.put(
            f"{vault_addr}/v1/sys/step-down",
            headers=headers,
        )
        raise_http_error(r)

    delay = random_delay(5)  # max 10s
    logger.info(f"Stopping Vault in {delay}s")
    time.sleep(delay)
    subprocess.run(["systemctl", "stop", "vault.service"], check=True)

    while True:
        logger.info("Waiting for Vault to stop")
        output = subprocess.run(
            ["systemctl", "is-active", "vault.service"], stdout=subprocess.PIPE
        ).stdout
        status = output.decode("utf-8").strip()
        if status == "inactive":
            time.sleep(2)  # Give time for the systemd log to show "stopped"
            break

        delay = random_delay(5)  # max 10s
        time.sleep(delay)

    logger.info("Vault stopped")
