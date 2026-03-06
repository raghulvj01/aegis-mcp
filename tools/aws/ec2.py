from __future__ import annotations

from typing import Any


def list_ec2_instances(region: str) -> list[dict[str, Any]]:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    try:
        client = boto3.client("ec2", region_name=region)
        reservations = client.describe_instances().get("Reservations", [])
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"AWS EC2 error in region '{region}': {exc}") from exc

    output: list[dict[str, Any]] = []
    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            output.append(
                {
                    "instance_id": instance.get("InstanceId"),
                    "state": instance.get("State", {}).get("Name"),
                    "type": instance.get("InstanceType"),
                }
            )
    return output
