from __future__ import annotations

import json
import subprocess
from typing import Any


def list_pods(namespace: str = "default") -> list[dict[str, Any]]:
    result = subprocess.check_output(
        ["kubectl", "get", "pods", "-n", namespace, "-o", "json"],
        stderr=subprocess.STDOUT,
        text=True,
    )
    payload = json.loads(result)
    return [
        {
            "name": item["metadata"]["name"],
            "phase": item["status"].get("phase"),
        }
        for item in payload.get("items", [])
    ]
