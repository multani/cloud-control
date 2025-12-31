import sys
from typing import NoReturn
from dataclasses import dataclass
import logging
import click
import json
from . import disks
from . import vault


@click.group()
def cli() -> None:
    pass


@cli.command()
def wait_disk() -> int:
    logger = logging.getLogger()

    with open("/etc/conf.json") as fp:
        conf = json.load(fp)

    disk_id = conf["disk"]["data"]
    device = "/dev/sdb"

    from .providers import aws

    ec2 = aws.EC2()

    ec2.wait_disk_attached(disk_id, device)

    device = disks.find_device_name(disk_id)
    logger.info(f"Found device name: {device}")

    disks.try_mount(f"{device}p1", "/srv")

    return 0


@cli.command()
def wait_interface() -> int:
    with open("/etc/conf.json") as fp:
        conf = json.load(fp)

    from .providers import aws

    ec2 = aws.EC2()

    eni_id = conf["network"]["eni"]
    ip = conf["network"]["ip"]

    ec2.wait_eni(eni_id, ip)

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
