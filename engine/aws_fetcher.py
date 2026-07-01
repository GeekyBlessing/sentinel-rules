"""
Fetches real CloudTrail events from AWS CloudTrail Event History (the default
90-day event log available in every AWS account with no trail configuration
required) and normalizes them into the same event shape the detection engine
expects from static fixture files.
"""
import boto3
from datetime import datetime, timedelta, timezone


def fetch_cloudtrail_events(
    region: str = "eu-north-1",
    hours_back: int = 24,
    max_events: int = 500,
) -> list[dict]:
    """
    Pulls events from CloudTrail Event History for the given lookback window.
    Returns a list of event dicts normalized to match the fixture event shape
    (eventTime, eventSource, eventName, userIdentity, requestParameters).
    """
    client = boto3.client("cloudtrail", region_name=region)

    start_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)
    end_time = datetime.now(timezone.utc)

    events = []
    paginator = client.get_paginator("lookup_events")
    page_iterator = paginator.paginate(
        StartTime=start_time,
        EndTime=end_time,
        PaginationConfig={"MaxItems": max_events},
    )

    for page in page_iterator:
        for raw in page.get("Events", []):
            normalized = _normalize_event(raw)
            if normalized:
                events.append(normalized)

    return events


def _normalize_event(raw_event: dict) -> dict:
    """
    CloudTrail's lookup_events API returns a summary shape with the full event
    JSON nested inside 'CloudTrailEvent' as a string. We parse that out so the
    detection engine sees the same structure it expects from fixture files.
    """
    import json

    cloudtrail_event_str = raw_event.get("CloudTrailEvent")
    if not cloudtrail_event_str:
        return None

    try:
        full_event = json.loads(cloudtrail_event_str)
    except json.JSONDecodeError:
        return None

    return full_event
