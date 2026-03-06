from __future__ import annotations

import requests


def pipeline_status(base_url: str, pipeline_id: str, api_token: str) -> dict:
    """Fetch the status of a CI/CD pipeline by its ID.

    Args:
        base_url: Base URL of the CI/CD service API.
        pipeline_id: Unique identifier of the pipeline.
        api_token: API token for authenticating with the CI/CD service.

    Returns:
        Pipeline status as a JSON-compatible dict.
    """
    try:
        response = requests.get(
            f"{base_url.rstrip('/')}/pipelines/{pipeline_id}",
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=15,
        )
        response.raise_for_status()
    except requests.ConnectionError as exc:
        raise RuntimeError(f"Cannot connect to CI/CD service at '{base_url}': {exc}") from exc
    except requests.HTTPError as exc:
        raise RuntimeError(
            f"CI/CD API error for pipeline '{pipeline_id}': {exc.response.status_code}"
        ) from exc
    except requests.Timeout as exc:
        raise RuntimeError(f"CI/CD API request timed out for pipeline '{pipeline_id}'") from exc

    return response.json()
