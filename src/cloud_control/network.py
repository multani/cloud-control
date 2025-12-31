import json
import structlog
import subprocess
import time


def wait_ip_address(ip: str) -> bool:
    max_tries = 30

    logger = structlog.get_logger()

    for i in range(max_tries):
        logger = logger.bind(attempt=f"{i + 1}/{max_tries}")
        logger.info("Checking if IP address is present on any interface")

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

        logger.info(f"IP address {ip} not found, waiting 2s and trying again")
        time.sleep(2)

    logger.info("Unable to find IP address, giving up")
    return False
