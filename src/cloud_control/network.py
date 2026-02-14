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


# def find_local_ip_address() -> str:
#     logging.debug("Finding local IP address...")
#     default_route = json.loads(
#         subprocess.check_output(["ip", "--json", "route", "get", "8.8.8.8"])
#     )
#     iface = default_route[0]["dev"]

#     ipaddrs = json.loads(subprocess.check_output(["ip", "--json", "address"]))
#     for ipaddr in ipaddrs:
#         if ipaddr["ifname"] == iface:
#             for addr in ipaddr["addr_info"]:
#                 if addr["family"] == "inet":
#                     LOCAL_ADDRESS = addr["local"]
#                     break
#             else:
#                 logger.critical(f"Couldn't find inet address of {iface}")
#                 sys.exit(1)
#             break
#     else:
#         logger.critical(f"Couldn't find local address of {iface}")
#         sys.exit(1)
