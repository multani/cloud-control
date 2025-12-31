import structlog
import os
import subprocess
import time
from pathlib import Path

logger = structlog.get_logger()


def parted(*args: str) -> bytes:
    cmd: list[str] = ["parted", "--script"] + list(args)
    return subprocess.check_output(cmd)


def find_device_name(disk_id: str) -> str:
    lookup_id = disk_id.replace("-", "")

    block_devices = Path("/sys/block")

    while True:  # TODO: max tries
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


def try_mount(partition: str, mount_point: str, tries: int = 0) -> None:
    max_tries = 5

    logger = structlog.get_logger(attempt=f"{tries + 1}/{max_tries}")
    logger.info(f"Mount {partition} to {mount_point}")

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
