from __future__ import annotations

import json
import subprocess


def run_trivy_scan(image: str) -> dict:
    try:
        output = subprocess.check_output(
            ["trivy", "image", "--format", "json", image],
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("trivy is not installed or not on PATH") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Trivy scan failed for image '{image}': {exc.output}") from exc

    return json.loads(output)
