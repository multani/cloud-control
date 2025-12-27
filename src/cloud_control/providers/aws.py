

class EC2:
    def __init__(self) -> None:
        self.config = get_aws_config()
        self.client = boto3.client("ec2", config=config)

    def wait_disk_attached(self, disk_id: str, device: str) -> None:

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
