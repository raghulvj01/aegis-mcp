from __future__ import annotations

import requests


def pipeline_status(base_url: str, pipeline_id: str, token: str) -> dict:
    response = requests.get(
        f"{base_url.rstrip('/')}/pipelines/{pipeline_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )
    response.raise_for_status()
    return response.json()
