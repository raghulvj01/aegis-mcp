from __future__ import annotations

import json
import subprocess


def run_trivy_scan(image: str) -> dict:
    output = subprocess.check_output(
        ["trivy", "image", "--format", "json", image],
        stderr=subprocess.STDOUT,
        text=True,
    )
    return json.loads(output)
