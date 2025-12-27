#!/usr/bin/env -S python3 -u

import argparse
import json
import logging
import logging.handlers
import os
import random
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Self, Union
from urllib.parse import urljoin

import boto3
import requests
from botocore.config import Config as AWSConfig
from botocore.exceptions import ClientError
from requests.exceptions import HTTPError

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()


def get_aws_config() -> AWSConfig:
    aws_region = get_region()
    config = AWSConfig(region_name=aws_region)
    return config


@dataclass
class DiskConfig:
    data: str


@dataclass
class NetworkConfig:
    eni: str
    ip: str
    interface: str


@dataclass
class VaultConfig:
    root_token_secret_name: str


@dataclass
class Config:
    disk: DiskConfig
    network: NetworkConfig
    vault: VaultConfig

    @classmethod
    def load(cls, path: Path) -> Self:
        data = {}

        if path.is_file():
            data = json.loads(path.read_text())
        else:
            for p in path.iterdir():
                if p.suffix != ".json":
                    continue

                part = json.loads(path.read_text())
                data.update(part)

        disk = DiskConfig(**data["disk"])
        network = NetworkConfig(**data["network"])
        vault = VaultConfig(**data["vault"])
        return cls(disk=disk, network=network, vault=vault)


def get_config() -> None:
    pass


def main() -> int:
    instance_id = get_instance_id()

    syslog = logging.handlers.SysLogHandler("/dev/log")
    formatter = logging.Formatter(
        f"vault-control {instance_id} [%(levelname)s] %(message)s"
    )
    syslog.setFormatter(formatter)
    syslog.setLevel(logging.DEBUG)
    logger.addHandler(syslog)

    file_handler = logging.FileHandler("/var/log/vault-control.log")
    formatter = logging.Formatter(f"{instance_id} [%(levelname)s] %(message)s")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

    logging.getLogger("botocore").setLevel(logging.INFO)
    logging.getLogger("urllib3").setLevel(logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-a",
        "--vault-addr",
        default=os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200"),
    )
    parser.add_argument("-t", "--vault-token", default=os.environ.get("VAULT_TOKEN"))

    subparsers = parser.add_subparsers()

    init = subparsers.add_parser("init")
    init.set_defaults(func=cmd_init)

    stop = subparsers.add_parser("stop")
    stop.set_defaults(func=cmd_stop)

    wait_disk = subparsers.add_parser("wait-disk")
    wait_disk.set_defaults(func=cmd_wait_disk)

    wait_interface = subparsers.add_parser("wait-interface")
    wait_interface.set_defaults(func=cmd_wait_interface)

    args = parser.parse_args()
    if "func" not in args:
        parser.error("Must specify a subcommand")
    kwargs = dict(args.__dict__)
    del kwargs["func"]
    try:
        return args.func(**kwargs)
    except Exception:
        logger.exception("Error general totoz")
        return 255


def get_instance_id() -> str:
    headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
    with requests.put(
        "http://169.254.169.254/latest/api/token", headers=headers
    ) as response:
        raise_http_error(response)
        token = response.text

    headers = {"X-aws-ec2-metadata-token": token}
    with requests.get(
        "http://169.254.169.254/latest/meta-data/instance-id", headers=headers
    ) as response:
        raise_http_error(response)
        instance_id = str(response.text)
        return instance_id


def get_region() -> str:
    headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
    with requests.put(
        "http://169.254.169.254/latest/api/token", headers=headers
    ) as response:
        raise_http_error(response)
        token = response.text

    headers = {"X-aws-ec2-metadata-token": token}
    with requests.get(
        "http://169.254.169.254/latest/meta-data/placement/availability-zone",
        headers=headers,
    ) as response:
        raise_http_error(response)
        az = str(response.text)
        region = az[:-1]
        return region


def is_vault_initialized(vault_addr: str, vault_token: Union[str, None] = None) -> bool:
    headers = {
        "x-vault-token": vault_token,
    }

    r = requests.get(f"{vault_addr}/v1/sys/init", headers=headers)
    raise_http_error(r)
    data = r.json()
    print(data)
    is_initialized = bool(data.get("initialized", False))
    return is_initialized


def cmd_init(vault_addr: str, vault_token: str) -> int:
    headers = {
        "x-vault-token": vault_token,
    }

    config = Config.load(Path("/etc/conf.json"))
    secret_id = config.vault.root_token_secret_name

    init_secret_id = str(uuid.uuid4())
    init_request_token = "abb383ec-f2cd-473e-81d1-67d60a4b6715"

    sm = boto3.client("secretsmanager", config=get_aws_config())

    for i in range(10):
        logger.info("Checking if Vault needs to be initialized...")
        is_initialized = is_vault_initialized(vault_addr, vault_token)

        if is_initialized:
            break

        try:
            logger.debug("Trying to get a secret lock")
            sm.put_secret_value(
                SecretId=secret_id,
                ClientRequestToken=init_request_token,
                SecretString=init_secret_id,
            )
        except sm.exceptions.ResourceExistsException:
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
        if is_vault_initialized(vault_addr, vault_token):
            logger.info("Vault is already initialized, so we are all good.")
            return 0
        logger.critical(f"Failed to initialize: {exc}")
        raise exc

    data = r.json()

    root_token = data["root_token"]

    logger.info(f"Saving root token into Secrets Manager {secret_id!r}")
    sm.put_secret_value(
        SecretId=secret_id,
        SecretString=root_token,
    )

    logger.info(f"Vault initialized, the root token is in {secret_id!r}")
    return 0


def parted(*args: str) -> bytes:
    cmd: list[str] = ["parted", "--script"] + list(args)
    return subprocess.check_output(cmd)


def create_partition(partition: str) -> str:
    suffix = "p1"
    assert partition.endswith(suffix), f"{partition=} must end with {suffix=}"

    device = partition[0 : -len(suffix)]

    logger.info(f"Waiting for device {device} to show up")
    while True:
        try:
            os.stat(device)
            break
        except FileNotFoundError:
            logger.info(f"Device {device} not found")
            time.sleep(5)
        else:
            logger.info(f"Device {device} is present")

    logger.info(f"{device}: Creating partition table")
    parted(device, "mktable", "gpt")

    logger.info(f"{device}: Creating a single partition")
    parted(device, "mkpart", "gpt", "0%", "100%")
    time.sleep(1)

    max_tries = 5
    for i in range(max_tries):
        logger.info(
            f"Waiting for partition {partition} to show up ({i + 1}/{max_tries})"
        )
        try:
            os.stat(partition)
            break
        except FileNotFoundError:
            time.sleep(5)

    logger.info(f"{partition}: formatting disk with ext4")
    subprocess.check_output(["mkfs.ext4", partition])

    return partition


def try_mount(partition: str, mount_point: str, tries: int = 0) -> None:
    max_tries = 5
    logger.info(f"Mount {partition} to {mount_point} ({tries + 1}/{max_tries})")

    try:
        subprocess.check_output(["mount", partition, mount_point])
    except subprocess.CalledProcessError as exc:
        if exc.returncode == 32:
            if tries > max_tries:
                logger.info("Tried too many times, giving up")
                raise exc from None
            create_partition(partition)
            try_mount(partition, mount_point, tries + 1)
        else:
            raise

    logger.info(f"{partition} mounted to {mount_point}")


def wait_disk_attached(
    ec2,
    disk_id: str,
    instance_id: str,
    device: str,
) -> None:
    # aws ec2 attach-volume --instance-id "$INSTANCE_ID" --volume-id "$DISK_ID" --device "$DEVICE"
    max_tries = 60

    for i in range(max_tries):
        logger.info(
            f"Trying to attach volume {disk_id} to instance {instance_id} ({i + 1}/{max_tries})"
        )

        # First, verify that the disk is not already attached to another instance
        while True:
            logger.debug(f"Checking status of disk {disk_id}")
            response = ec2.describe_volumes(VolumeIds=[disk_id])
            volume = response["Volumes"][0]

            attachments = volume["Attachments"]
            # No attachments, so disk is free
            if len(attachments) == 0:
                try:
                    response = ec2.attach_volume(
                        Device=device,
                        InstanceId=instance_id,
                        VolumeId=disk_id,
                    )
                except ClientError as exc:
                    logger.warning(exc)
                    duration = 5
                    time.sleep(duration)
                    continue

                state = response["State"]
                logger.info(f"Disk attachment successful, {state=}")

                if state == "attached":
                    return
                elif state == "attaching":
                    logger.info("Disk is being attached, will try again soon")
                    duration = 2
                    time.sleep(duration)
                    continue

            for attachment in attachments:
                on_instance_id = attachment["InstanceId"]
                state = attachment["State"]

                logger.debug(
                    f"Disk {disk_id} is attached to {on_instance_id} with {state=}"
                )

                if state == "attached" and on_instance_id == instance_id:
                    logger.info("Disk is already attached to this instance, all good")
                    return

                elif state == "detaching":
                    duration = 2
                    logger.info(f"Disk is being detached from {on_instance_id}...")

                elif state == "attached" and on_instance_id != instance_id:
                    duration = 30
                    logger.warning(
                        f"Disk attached to {on_instance_id}, hope it will be detached soon..."
                    )

                else:
                    duration = 1
                    logger.warning("Unknown attachment state, will retry soon")

                logger.info(f"Waiting {duration}s")
                time.sleep(duration)


def cmd_wait_interface(vault_addr: str, vault_token: Union[str, None]) -> int:
    with open("/etc/conf.json") as fp:
        conf = json.load(fp)

    eni_id = conf["network"]["eni"]
    ip = conf["network"]["ip"]
    instance_id = get_instance_id()
    device_index = 1

    config = get_aws_config()
    ec2 = boto3.client("ec2", config=config)

    max_tries = 5

    for i in range(max_tries):
        logger.info(
            f"Trying to attach ENI {eni_id} to instance {instance_id} ({i + 1}/{max_tries})"
        )

        attached = False
        while True:
            response = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
            interface = response["NetworkInterfaces"][0]

            assert interface["NetworkInterfaceId"] == eni_id
            attachment = interface.get("Attachment")

            if attachment is None:
                break

            status = attachment["Status"]
            on_instance_id = attachment["InstanceId"]

            logger.debug(f"ENI {eni_id} is attached to {on_instance_id} with {status=}")

            if on_instance_id != instance_id:
                logger.warning(
                    f"ENI {eni_id} is still attached to another instance: {on_instance_id} != {instance_id}"
                )

            elif status == "attached":
                logger.info("ENI is already attached to this instance, all good")
                attached = True
                break

            logger.info(f"ENI is not completed attached: {status=}, waiting 2s")
            time.sleep(2)

        try:
            if not attached:
                response = ec2.attach_network_interface(
                    NetworkInterfaceId=eni_id,
                    InstanceId=instance_id,
                    DeviceIndex=device_index,
                )
                attached = True
        except ClientError as exc:
            msg = exc.args[0]

            if "already has an interface attached" in msg:
                logger.info(f"ENI should already be attached: {msg}")
                attached = True

        if attached:
            logger.info("ENI attached successfully")
            if wait_ip_address(ip):
                break

            response = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
            interface = response["NetworkInterfaces"][0]
            assert interface["NetworkInterfaceId"] == eni_id
            attachment_id = interface["Attachment"]["AttachmentId"]

            logger.info(
                "Coulnd't find IP address from the interface, detaching and retrying"
            )
            ec2.detach_network_interface(
                AttachmentId=attachment_id,
                Force=True,
            )

        time.sleep(2)

    else:
        logger.info("Unable to attach ENI and find IP address, giving up")
        return 255

    return 0


def wait_ip_address(ip: str) -> bool:
    max_tries = 30

    for i in range(max_tries):
        logger.info(
            f"Checking if IP address is present on any interface ({i + 1}/{max_tries})"
        )
        output = subprocess.check_output(["ip", "--json", "address", "show"])
        interfaces = json.loads(output)

        for interface in interfaces:
            ifname = interface["ifname"]

            if ifname == "ens6" and interface["operstate"] != "UP":
                output = subprocess.check_output(
                    ["ip", "link", "set", "dev", ifname, "up"]
                )

            for addr in interface["addr_info"]:
                if addr["local"] == ip:
                    logger.info(f"Found IP address {ip} on interface {ifname}")
                    return True

        logger.info(
            f"IP address {ip} not found, waiting 2s and trying again ({i + 1}/{max_tries})"
        )
        time.sleep(2)

    logger.info("Unable to find IP address, giving up")
    return False


def find_device_name(disk_id: str) -> str:
    lookup_id = disk_id.replace("-", "")

    block_devices = Path("/sys/block")

    while True:
        logger.info(f"Looking for device with id {disk_id}")

        for device in block_devices.iterdir():
            serial_path = device / "device" / "serial"
            logger.debug(f"Checking device {serial_path}")

            if not serial_path.is_file():
                continue

            serial = serial_path.read_text().strip()

            logger.debug(f"Device {device.name} has serial {serial}")

            if serial == lookup_id:
                dev_name = f"/dev/{device.name}"
                os.stat(dev_name)
                return dev_name

        logger.info(f"Device {disk_id} not found, waiting 2s and trying again")
        time.sleep(2)


def cmd_wait_disk(vault_addr: str, vault_token: Union[str, None]) -> int:
    # TODO: how to check this is the correct disk?
    with open("/etc/conf.json") as fp:
        conf = json.load(fp)

    disk_id = conf["disk"]["data"]
    instance_id = get_instance_id()
    device = "/dev/sdb"

    config = get_aws_config()
    ec2 = boto3.client("ec2", config=config)

    wait_disk_attached(ec2, disk_id, instance_id, device)

    device = find_device_name(disk_id)
    logger.info(f"Found device name: {device}")

    try_mount(f"{device}p1", "/srv")

    return 0


def cmd_stop(vault_addr: str, vault_token: str) -> None:
    headers = {
        "x-vault-token": vault_token,
    }

    with open("/etc/conf.json") as fp:
        conf = json.load(fp)

    LOCAL_ADDRESS = conf["network"]["ip"]

    # logging.debug("Finding local IP address...")
    # default_route = json.loads(
    #     subprocess.check_output(["ip", "--json", "route", "get", "8.8.8.8"])
    # )
    # iface = default_route[0]["dev"]

    # ipaddrs = json.loads(subprocess.check_output(["ip", "--json", "address"]))
    # for ipaddr in ipaddrs:
    #     if ipaddr["ifname"] == iface:
    #         for addr in ipaddr["addr_info"]:
    #             if addr["family"] == "inet":
    #                 LOCAL_ADDRESS = addr["local"]
    #                 break
    #         else:
    #             logger.critical(f"Couldn't find inet address of {iface}")
    #             sys.exit(1)
    #         break
    # else:
    #     logger.critical(f"Couldn't find local address of {iface}")
    #     sys.exit(1)

    logging.debug(f"Found local IP address={LOCAL_ADDRESS}")

    logging.debug(f"Finding Raft node associated with {LOCAL_ADDRESS}")
    try:
        node_id = find_raft_node(vault_addr, headers, LOCAL_ADDRESS)
    except NotFound:
        logger.critical(f"Couldn't find Vault node name for {LOCAL_ADDRESS}")
        sys.exit(1)

    logging.debug(f"Raft node for {LOCAL_ADDRESS} is: {node_id}")

    # while node_id is not None:
    #     logger.info(f"Removing node: {node_id}")
    #     r = requests.post(
    #         f"{vault_addr}/v1/sys/storage/raft/remove-peer",
    #         headers=headers,
    #         json={
    #             "server_id": node_id,
    #         },
    #     )
    #     raise_http_error(r)

    #     delay = random_delay(10)
    #     logger.info(f"Checking if node {node_id} is out in {delay}s")
    #     time.sleep(delay)

    #     try:
    #         node_id = find_raft_node(vault_addr, headers, LOCAL_ADDRESS)
    #     except NotFound:
    #         break
    #     else:
    #         continue

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

    # logger.info("Removing Vault data files")
    # shutil.rmtree("/srv/vault/data/raft")
    # os.remove("/srv/vault/data/vault.db")
    # os.remove("/srv/vault/data/node-id")

    # logger.info("Vault and its data have been terminated")


def random_delay(maximum: int = 30) -> float:
    return random.random() * maximum


def raise_http_error(response: requests.Response) -> None:
    if response.ok:
        return

    try:
        errors = response.json()["errors"]
    except:  # noqa:E722
        response.raise_for_status()

    msg = [
        f"{response.status_code} {response.reason} for url: {response.request.url}"
    ] + errors
    msg = "; ".join(msg)
    raise HTTPError(msg)


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
        raise NotFound(address)

    return node_id


class NotFound(Exception):
    pass


if __name__ == "__main__":
    sys.exit(main())
