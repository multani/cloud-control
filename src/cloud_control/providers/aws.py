import time

import boto3

from ._base import BaseProvider
from types_boto3_ec2.client import EC2Client
import requests
import structlog
from botocore.config import Config as AWSConfig
from botocore.exceptions import ClientError
from cloud_control.http import raise_http_error

from .. import network

logger = structlog.get_logger(module="aws")


def get_aws_config() -> AWSConfig:
    aws_region = get_region()
    config = AWSConfig(region_name=aws_region)
    return config


def get_metadata_token() -> str:
    headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
    token_url = "http://169.254.169.254/latest/api/token"
    with requests.put(token_url, headers=headers) as response:
        raise_http_error(response)
        return response.text


def get_instance_id() -> str:
    token = get_metadata_token()
    headers = {"X-aws-ec2-metadata-token": token}

    url = "http://169.254.169.254/latest/meta-data/instance-id"
    with requests.get(url, headers=headers) as response:
        raise_http_error(response)
        instance_id = str(response.text)
        return instance_id


def get_region() -> str:
    token = get_metadata_token()
    headers = {"X-aws-ec2-metadata-token": token}

    url = "http://169.254.169.254/latest/meta-data/placement/availability-zone"
    with requests.get(url, headers=headers) as response:
        raise_http_error(response)
        az = str(response.text)
        region = az[:-1]
        return region


class AWS(BaseProvider):
    def __init__(self) -> None:
        self.config = get_aws_config()
        self.ec2: EC2Client = boto3.client("ec2", config=self.config)
        self.logger = structlog.get_logger(module="aws.ec2")
        self.instance_id = get_instance_id()

    def wait_disk_attached(self, disk_id: str, device: str) -> None:
        # aws ec2 attach-volume --instance-id "$INSTANCE_ID" --volume-id "$DISK_ID" --device "$DEVICE"
        max_tries = 60

        for i in range(max_tries):
            logger = self.logger.bind(iteration=f"{i + 1}/{max_tries}")
            logger.info(
                f"Trying to attach volume {disk_id} to instance {self.instance_id}"
            )

            # First, verify that the disk is not already attached to another instance
            while True:
                logger.debug(f"Checking status of disk {disk_id}")
                response_describe_volumes = self.ec2.describe_volumes(
                    VolumeIds=[disk_id]
                )
                volume = response_describe_volumes["Volumes"][0]

                attachments = volume["Attachments"]
                # No attachments, so disk is free
                if len(attachments) == 0:
                    try:
                        response_attach_volume = self.ec2.attach_volume(
                            Device=device,
                            InstanceId=self.instance_id,
                            VolumeId=disk_id,
                        )
                    except ClientError as exc:
                        logger.warning(exc)
                        duration = 5
                        time.sleep(duration)
                        continue

                    state = response_attach_volume["State"]
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

                    if state == "attached" and on_instance_id == self.instance_id:
                        logger.info(
                            "Disk is already attached to this instance, all good"
                        )
                        return

                    elif state == "detaching":
                        duration = 2
                        logger.info(f"Disk is being detached from {on_instance_id}...")

                    elif state == "attached" and on_instance_id != self.instance_id:
                        duration = 30
                        logger.warning(
                            f"Disk attached to {on_instance_id}, hope it will be detached soon..."
                        )

                    else:
                        duration = 1
                        logger.warning("Unknown attachment state, will retry soon")

                    logger.info(f"Waiting {duration}s")
                    time.sleep(duration)

    def wait_eni(self, eni_id: str, ip: str) -> int:  # TODO: change return type
        device_index = 1

        max_tries = 5

        for i in range(max_tries):
            logger = self.logger.bind(iteration=f"{i + 1}/{max_tries}")
            msg = f"Trying to attach ENI {eni_id} to instance {self.instance_id}"
            logger.info(msg)

            attached = False
            while True:
                response = self.ec2.describe_network_interfaces(
                    NetworkInterfaceIds=[eni_id]
                )
                interface = response["NetworkInterfaces"][0]

                assert interface["NetworkInterfaceId"] == eni_id
                attachment = interface.get("Attachment")

                if attachment is None:
                    break

                status = attachment["Status"]
                on_instance_id = attachment["InstanceId"]

                logger.debug(
                    f"ENI {eni_id} is attached to {on_instance_id} with {status=}"
                )

                if on_instance_id != self.instance_id:
                    logger.warning(
                        f"ENI {eni_id} is still attached to another instance: {on_instance_id} != {self.instance_id}"
                    )

                elif status == "attached":
                    logger.info("ENI is already attached to this instance, all good")
                    attached = True
                    break

                logger.info(f"ENI is not completed attached: {status=}, waiting 2s")
                time.sleep(2)

            try:
                if not attached:
                    _ = self.ec2.attach_network_interface(
                        NetworkInterfaceId=eni_id,
                        InstanceId=self.instance_id,
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
                if network.wait_ip_address(ip):
                    break

                response = self.ec2.describe_network_interfaces(
                    NetworkInterfaceIds=[eni_id]
                )
                interface = response["NetworkInterfaces"][0]
                assert interface["NetworkInterfaceId"] == eni_id
                attachment_id = interface["Attachment"]["AttachmentId"]

                logger.info(
                    "Coulnd't find IP address from the interface, detaching and retrying"
                )
                self.ec2.detach_network_interface(
                    AttachmentId=attachment_id,
                    Force=True,
                )

            time.sleep(2)

        else:
            logger.info("Unable to attach ENI and find IP address, giving up")
            return 255

        return 0
