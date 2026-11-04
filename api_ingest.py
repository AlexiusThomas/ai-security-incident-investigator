
"""Day 17: REST API Security Event Ingestion."""

import os
import requests


class APIIngestionError(Exception):
    """Custom error for API ingestion failures."""


def fetch_security_events(url, api_key=None, timeout=10):
    """Fetch security events from a REST API."""

    headers = {"Accept": "application/json"}

    key = api_key or os.getenv("SECURITY_API_KEY")

    if key:
        headers["Authorization"] = f"Bearer {key}"

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=timeout
        )

        response.raise_for_status()
        payload = response.json()

    except requests.Timeout as exc:
        raise APIIngestionError(
            "API request timed out"
        ) from exc

    except requests.HTTPError as exc:
        raise APIIngestionError(
            f"API returned HTTP {exc.response.status_code}"
        ) from exc

    except requests.RequestException as exc:
        raise APIIngestionError(
            "API connection failed"
        ) from exc

    except ValueError as exc:
        raise APIIngestionError(
            "API returned invalid JSON"
        ) from exc

    if isinstance(payload, dict):
        events = payload.get("events")
    elif isinstance(payload, list):
        events = payload
    else:
        raise APIIngestionError(
            "Unexpected API response format"
        )

    if not isinstance(events, list):
        raise APIIngestionError(
            "Events must be a list"
        )

    if not all(isinstance(event, dict) for event in events):
        raise APIIngestionError(
            "Each event must be an object"
        )

    return events
