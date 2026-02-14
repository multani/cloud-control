import logging
import logging.handlers
import sys
from dataclasses import dataclass
from typing import NoReturn

import click

from . import disks, vault
from .config import Config
from .providers import aws


@click.group()
def cli() -> None:
    pass


@cli.group(name="disk")
def disk_cmds() -> None:
    pass


@disk_cmds.command(name="wait")
def wait_disk() -> int:
    logger = logging.getLogger()

    conf = Config.load()
    disk_id = conf.disk.data
    device = "/dev/sdb"  # TODO: fetch from config

    ec2 = aws.AWS()
    ec2.wait_disk_attached(disk_id, device)
    device = disks.find_device_name(disk_id)
    logger.info(f"Found device name: {device}")

    disks.try_mount(f"{device}p1", "/srv")

    return 0


@cli.group(name="network")
def network_cmds() -> None:
    pass


@network_cmds.group(name="interface")
def network_interface_cmds() -> None:
    pass


@network_interface_cmds.command(name="wait")
def wait_interface() -> int:
    conf = Config.load()

    ec2 = aws.AWS()
    ec2.wait_eni(conf.network.eni, conf.network.ip)

    return 0


@dataclass
class VaultOptions:
    vault_addr: str
    vault_token: str


pass_vault_opts = click.make_pass_decorator(VaultOptions, ensure=True)


@cli.group(name="vault")
@click.option(
    "-a",
    "--vault-addr",
    required=True,
    help="Vault address",
    envvar="VAULT_ADDR",
    default="http://127.0.0.1:8200",
)
@click.option(
    "-t",
    "--vault-token",
    help="Vault token",
    envvar="VAULT_TOKEN",
    default="",
)
@click.pass_context
def vault_cmds(ctx: click.Context, vault_addr: str, vault_token: str) -> None:
    opts = VaultOptions(vault_addr=vault_addr, vault_token=vault_token)
    ctx.obj = opts


@vault_cmds.command(name="init")
@pass_vault_opts
def vault_init(opts: VaultOptions) -> int:
    vault.init(opts.vault_addr, opts.vault_token)
    return 0


@vault_cmds.command(name="stop")
@pass_vault_opts
def vault_stop(opts: VaultOptions) -> int:
    vault.stop(opts.vault_addr, opts.vault_token)
    return 0


def main() -> NoReturn:
    instance_id = "xxxx"  # TODO

    logging.basicConfig(level=logging.DEBUG)

    syslog = logging.handlers.SysLogHandler("/dev/log")
    formatter = logging.Formatter(
        f"vault-control {instance_id} [%(levelname)s] %(message)s"
    )
    syslog.setFormatter(formatter)
    syslog.setLevel(logging.DEBUG)
    logger = logging.getLogger()
    logger.addHandler(syslog)

    try:
        file_handler = logging.FileHandler("/var/log/vault-control.log")
    except PermissionError:
        pass
    else:
        formatter = logging.Formatter(f"{instance_id} [%(levelname)s] %(message)s")
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)

    logging.getLogger("botocore").setLevel(logging.INFO)
    logging.getLogger("urllib3").setLevel(logging.INFO)

    sys.exit(cli())
