import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

import structlog

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


def mount_data_disk(device: str) -> None:
    def mkdir(path: Path, mode: int = 0o700) -> Path:
        path.mkdir(exist_ok=True, mode=mode, parents=True)
        return path

    mnt_data = Path("/mnt/data")
    mkdir(mnt_data)

    # TODO: mkdir /mnt/data
    mnt_data_unit = Mount(f"{device}p1", mnt_data.as_posix()).mount()

    private_dir = mkdir(mnt_data / "private")
    Mount(
        private_dir.as_posix(),
        "/var/lib/private",
        options=["bind"],
        requires=[mnt_data_unit],
    ).mount()

    srv_dir = mkdir(mnt_data / "srv", mode=0o755)  # need more permissions
    Mount(
        srv_dir.as_posix(),
        "/srv",
        options=["bind"],
        requires=[mnt_data_unit],
    ).mount()


@dataclass
class Mount:
    what: str
    where: str
    options: list[str] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)

    @property
    def unit_name(self) -> str:
        name = self.where.lstrip("/").replace("/", "-")
        return f"{name}.mount"

    def save(self) -> str:
        content = [
            "[Unit]",
            "Before=local-fs.target",
        ]

        for require in self.requires:
            content.append(f"Requires={require}")

        content.append("[Mount]")
        content.append(f"What={self.what}")
        content.append(f"Where={self.where}")
        content.append(f"Options={','.join(self.options)}")

        target_path = Path("/etc/systemd/system") / self.unit_name
        target_path.write_text("\n".join(content))
        return self.unit_name

    def mount(self) -> str:
        logger.info(f"Mounting {self.what} to {self.where}")
        unit_name = self.save()
        subprocess.check_output(["systemctl", "daemon-reload"])
        subprocess.check_output(["systemctl", "start", unit_name])
        logger.info(f"{self.what} mounted to {self.where}")
        return unit_name
