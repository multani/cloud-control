import click
import structlog

@click.group()
def cli() -> None:
    pass

@cli.command()
def wait_disk():
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


def main() -> int:
    cli()

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

