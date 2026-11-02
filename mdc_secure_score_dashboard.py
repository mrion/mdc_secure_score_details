#!/usr/bin/env python3
"""Retrieve and report Microsoft Defender for Cloud secure scores."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import html
import json
import math
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Mapping, NoReturn, Sequence
import webbrowser


MAX_SCORE_VALUE = 1_000_000_000.0
MAX_WEIGHT_VALUE = 1_000_000_000_000.0
MAX_RESOURCE_COUNT = 100_000_000
AZURE_COMMAND_TIMEOUT_SECONDS = 120
RESOURCE_GRAPH_PAGE_SIZE = 1_000
MAX_RESOURCE_GRAPH_PAGES = 100
MAX_RESOURCE_GRAPH_ROWS = RESOURCE_GRAPH_PAGE_SIZE * MAX_RESOURCE_GRAPH_PAGES
MAX_AZURE_OUTPUT_BYTES = 32 * 1024 * 1024
RESOURCE_GRAPH_API_VERSION = "2022-10-01"
RESOURCE_GRAPH_URL = (
    "https://management.azure.com/providers/Microsoft.ResourceGraph/resources"
    f"?api-version={RESOURCE_GRAPH_API_VERSION}"
)

SUBSCRIPTION_QUERY = r"""
ResourceContainers
| where type =~ 'microsoft.resources/subscriptions'
    and properties.state =~ 'Enabled'
| project tenantId, subscriptionId, subscriptionName=name
| join kind=leftouter (
    SecurityResources
    | where type =~ 'microsoft.security/securescores' and name =~ 'ascScore'
    | extend currentScore=todouble(properties.score.current),
        maxScore=todouble(properties.score.max),
        reportedPercentage=todouble(properties.score.percentage),
        weight=todouble(properties.weight),
        hasSecureScore=true
    | project subscriptionId, currentScore, maxScore,
        reportedPercentage, weight, hasSecureScore
  ) on subscriptionId
| extend currentScore=coalesce(currentScore, 0.0),
    maxScore=coalesce(maxScore, 0.0),
    weight=coalesce(weight, 0.0),
    hasSecureScore=coalesce(hasSecureScore, false)
| project tenantId, subscriptionId, subscriptionName, currentScore, maxScore,
    reportedPercentage, weight, hasSecureScore
| order by subscriptionName asc, subscriptionId asc
""".strip()

ASSESSED_RESOURCE_QUERY = r"""
SecurityResources
| where type =~ 'microsoft.security/assessments'
| extend assessmentStatus=tostring(properties.status.code),
    assessedResourceId=tostring(properties.resourceDetails.Id)
| where assessmentStatus in~ ('Healthy', 'Unhealthy', 'NotApplicable')
    and isnotempty(assessedResourceId)
| summarize hasUnhealthy=countif(assessmentStatus =~ 'Unhealthy') > 0,
    hasHealthy=countif(assessmentStatus =~ 'Healthy') > 0
    by subscriptionId, assessedResourceId
| extend resourceStatus=case(
    hasUnhealthy, 'Unhealthy',
    hasHealthy, 'Healthy',
    'NotApplicable')
| summarize healthyResourceCount=countif(resourceStatus == 'Healthy'),
    unhealthyResourceCount=countif(resourceStatus == 'Unhealthy'),
    notApplicableResourceCount=countif(resourceStatus == 'NotApplicable')
    by subscriptionId
| extend assessedResourceCount=healthyResourceCount + unhealthyResourceCount
| order by subscriptionId asc
""".strip()

CONTROL_QUERY = r"""
SecurityResources
| where type =~ 'microsoft.security/securescores/securescorecontrols'
    and id contains '/secureScores/ascScore/'
| extend controlName=tostring(properties.displayName),
    controlId=tostring(properties.definition.name),
    healthyResourceCount=tolong(properties.healthyResourceCount),
    unhealthyResourceCount=tolong(properties.unhealthyResourceCount),
    notApplicableResourceCount=tolong(properties.notApplicableResourceCount),
    currentScore=todouble(properties.score.current),
    maxScore=todouble(properties.definition.properties.maxScore),
    weight=todouble(properties.weight)
| join kind=inner (
    ResourceContainers
    | where type =~ 'microsoft.resources/subscriptions'
        and properties.state =~ 'Enabled'
    | project subscriptionId, subscriptionName=name
  ) on subscriptionId
| project tenantId, subscriptionId, subscriptionName, controlId, controlName,
    currentScore, maxScore, weight, healthyResourceCount,
    unhealthyResourceCount, notApplicableResourceCount
| order by subscriptionName asc, controlName asc, subscriptionId asc, controlId asc
""".strip()


class DataValidationError(ValueError):
    """Raised when Azure Resource Graph returns invalid score data."""


def _bounded_number(
    value: Any, *, field: str, maximum: float, allow_zero: bool = True
) -> float:
    if isinstance(value, bool):
        raise DataValidationError(f"{field} must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise DataValidationError(f"{field} must be numeric") from error
    minimum = 0.0 if allow_zero else math.nextafter(0.0, 1.0)
    if not math.isfinite(number) or number < minimum or number > maximum:
        raise DataValidationError(
            f"{field} must be between {minimum} and {maximum}"
        )
    return number


def _required_text(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DataValidationError(f"{field} must be a non-empty string")
    return value.strip()


@dataclass(frozen=True, slots=True)
class SubscriptionScore:
    tenant_id: str
    subscription_id: str
    subscription_name: str
    current: float
    maximum: float
    percentage: float
    weight: float
    assessed_resources: int
    healthy_resources: int
    unhealthy_resources: int
    not_applicable_resources: int
    available: bool

    @classmethod
    def from_mapping(cls, row: Mapping[str, Any]) -> "SubscriptionScore":
        current = _bounded_number(
            row.get("currentScore"), field="currentScore", maximum=MAX_SCORE_VALUE
        )
        maximum = _bounded_number(
            row.get("maxScore"), field="maxScore", maximum=MAX_SCORE_VALUE
        )
        if current > maximum:
            raise DataValidationError("currentScore cannot exceed maxScore")
        percentage = 0.0 if maximum == 0.0 else current / maximum
        raw_available = row.get("hasSecureScore", True)
        if isinstance(raw_available, str) and raw_available.casefold() in {"true", "false"}:
            raw_available = raw_available.casefold() == "true"
        if type(raw_available) in {int, float} and raw_available in {0, 1}:
            raw_available = bool(raw_available)
        if not isinstance(raw_available, bool):
            raise DataValidationError("hasSecureScore must be a boolean")
        assessed_resources = _bounded_integer(
            row.get("assessedResourceCount"),
            field="assessedResourceCount",
            maximum=MAX_RESOURCE_COUNT,
        )
        healthy_resources = _bounded_integer(
            row.get("healthyResourceCount"), field="healthyResourceCount"
        )
        unhealthy_resources = _bounded_integer(
            row.get("unhealthyResourceCount"), field="unhealthyResourceCount"
        )
        not_applicable_resources = _bounded_integer(
            row.get("notApplicableResourceCount"),
            field="notApplicableResourceCount",
        )
        if assessed_resources != healthy_resources + unhealthy_resources:
            raise DataValidationError(
                "assessedResourceCount must equal healthy plus unhealthy resources"
            )
        return cls(
            tenant_id=_required_text(row.get("tenantId"), field="tenantId"),
            subscription_id=_required_text(
                row.get("subscriptionId"), field="subscriptionId"
            ),
            subscription_name=_required_text(
                row.get("subscriptionName") or row.get("subscriptionId"),
                field="subscriptionName",
            ),
            current=current,
            maximum=maximum,
            percentage=percentage,
            weight=_bounded_number(
                row.get("weight"), field="weight", maximum=MAX_WEIGHT_VALUE
            ),
            assessed_resources=assessed_resources,
            healthy_resources=healthy_resources,
            unhealthy_resources=unhealthy_resources,
            not_applicable_resources=not_applicable_resources,
            available=raw_available,
        )


@dataclass(frozen=True, slots=True)
class AggregateScore:
    percentage: float
    weighted_points: float
    total_weight: float
    included_subscriptions: int
    excluded_subscriptions: int


def calculate_aggregate(scores: Sequence[SubscriptionScore]) -> AggregateScore:
    weighted_points = math.fsum(
        score.weight * score.percentage
        for score in scores
        if score.available and score.weight > 0.0 and score.maximum > 0.0
    )
    included = [
        score
        for score in scores
        if score.available and score.weight > 0.0 and score.maximum > 0.0
    ]
    total_weight = math.fsum(score.weight for score in included)
    percentage = weighted_points / total_weight if total_weight > 0.0 else 0.0
    return AggregateScore(
        percentage=percentage,
        weighted_points=weighted_points,
        total_weight=total_weight,
        included_subscriptions=len(included),
        excluded_subscriptions=len(scores) - len(included),
    )


@dataclass(frozen=True, slots=True)
class ControlScore:
    tenant_id: str
    subscription_id: str
    subscription_name: str
    control_id: str
    control_name: str
    current: float
    maximum: float
    weight: float
    healthy_resources: int
    unhealthy_resources: int
    not_applicable_resources: int

    @classmethod
    def from_mapping(cls, row: Mapping[str, Any]) -> "ControlScore":
        current = _bounded_number(
            row.get("currentScore"), field="currentScore", maximum=MAX_SCORE_VALUE
        )
        maximum = _bounded_number(
            row.get("maxScore"), field="maxScore", maximum=MAX_SCORE_VALUE
        )
        if current > maximum:
            raise DataValidationError("control currentScore cannot exceed maxScore")
        return cls(
            tenant_id=_required_text(row.get("tenantId"), field="tenantId"),
            subscription_id=_required_text(
                row.get("subscriptionId"), field="subscriptionId"
            ),
            subscription_name=_required_text(
                row.get("subscriptionName") or row.get("subscriptionId"),
                field="subscriptionName",
            ),
            control_id=_required_text(row.get("controlId"), field="controlId"),
            control_name=_required_text(row.get("controlName"), field="controlName"),
            current=current,
            maximum=maximum,
            weight=_bounded_number(
                row.get("weight"), field="weight", maximum=MAX_WEIGHT_VALUE
            ),
            healthy_resources=_bounded_integer(
                row.get("healthyResourceCount"), field="healthyResourceCount"
            ),
            unhealthy_resources=_bounded_integer(
                row.get("unhealthyResourceCount"), field="unhealthyResourceCount"
            ),
            not_applicable_resources=_bounded_integer(
                row.get("notApplicableResourceCount"),
                field="notApplicableResourceCount",
            ),
        )


@dataclass(frozen=True, slots=True)
class ControlCounts:
    total: int
    healthy: int
    unhealthy: int
    not_applicable: int


def summarize_controls_by_subscription(
    controls: Sequence[ControlScore],
) -> dict[str, ControlCounts]:
    classified: dict[str, list[int]] = {}
    seen: set[tuple[str, str]] = set()
    for control in controls:
        key = (control.subscription_id, control.control_id)
        if key in seen:
            raise DataValidationError(
                f"duplicate control {control.control_id} for subscription "
                f"{control.subscription_id}"
            )
        seen.add(key)
        counts = classified.setdefault(control.subscription_id, [0, 0, 0])
        if control.unhealthy_resources > 0:
            counts[1] += 1
        elif control.healthy_resources > 0:
            counts[0] += 1
        else:
            counts[2] += 1
    return {
        subscription_id: ControlCounts(
            total=sum(counts),
            healthy=counts[0],
            unhealthy=counts[1],
            not_applicable=counts[2],
        )
        for subscription_id, counts in classified.items()
    }


def _bounded_integer(
    value: Any, *, field: str, maximum: int = MAX_RESOURCE_COUNT
) -> int:
    number = _bounded_number(value, field=field, maximum=float(maximum))
    if not number.is_integer():
        raise DataValidationError(f"{field} must be an integer")
    return int(number)


def attach_assessed_resource_counts(
    subscription_rows: Sequence[Mapping[str, Any]],
    count_rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    count_fields = (
        "assessedResourceCount",
        "healthyResourceCount",
        "unhealthyResourceCount",
        "notApplicableResourceCount",
    )
    counts: dict[str, dict[str, int]] = {}
    for row in count_rows:
        subscription_id = _required_text(
            row.get("subscriptionId"), field="subscriptionId"
        )
        if subscription_id in counts:
            raise DataValidationError(
                f"duplicate assessed resource count for subscription {subscription_id}"
            )
        validated_counts = {
            field: _bounded_integer(row.get(field), field=field)
            for field in count_fields
        }
        if validated_counts["assessedResourceCount"] != (
            validated_counts["healthyResourceCount"]
            + validated_counts["unhealthyResourceCount"]
        ):
            raise DataValidationError(
                "assessedResourceCount must equal healthy plus unhealthy resources"
            )
        counts[subscription_id] = validated_counts
    enriched_rows: list[dict[str, Any]] = []
    for row in subscription_rows:
        enriched = dict(row)
        subscription_id = _required_text(
            enriched.get("subscriptionId"), field="subscriptionId"
        )
        resource_counts = counts.get(subscription_id)
        for field in count_fields:
            enriched[field] = resource_counts[field] if resource_counts else 0
        enriched_rows.append(enriched)
    return enriched_rows


class ResourceGraphClient:
    """Shared pagination for CLI and managed-identity transports."""

    def _request(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        raise NotImplementedError

    def query(
        self, query: str, *, subscription_ids: Sequence[str] | None = None
    ) -> list[Mapping[str, Any]]:
        rows: list[Mapping[str, Any]] = []
        skip_token: str | None = None
        seen_tokens: set[str] = set()
        for _ in range(MAX_RESOURCE_GRAPH_PAGES):
            options: dict[str, Any] = {
                "$top": RESOURCE_GRAPH_PAGE_SIZE,
                "resultFormat": "objectArray",
                "allowPartialScopes": False,
            }
            if skip_token is not None:
                options["$skipToken"] = skip_token
            body: dict[str, Any] = {"query": query, "options": options}
            if subscription_ids is not None:
                if not subscription_ids:
                    raise ValueError("subscription_ids must not be empty")
                body["subscriptions"] = list(subscription_ids)
            response = self._request(body)
            if not isinstance(response, Mapping):
                raise RuntimeError("Azure Resource Graph response is not an object")
            page_rows = response.get("data")
            if not isinstance(page_rows, list):
                raise RuntimeError("Azure Resource Graph response has no data array")
            for row in page_rows:
                if not isinstance(row, Mapping):
                    raise RuntimeError("Azure Resource Graph returned a non-object row")
                rows.append(row)
            if len(rows) > MAX_RESOURCE_GRAPH_ROWS:
                raise RuntimeError("Azure Resource Graph result exceeded the row limit")
            raw_skip_token = response.get("$skipToken")
            if raw_skip_token is None:
                if str(response.get("resultTruncated", False)).casefold() == "true":
                    raise RuntimeError(
                        "Azure Resource Graph truncated the result without a continuation token"
                    )
                total_records = response.get("totalRecords")
                if total_records is not None and (
                    not isinstance(total_records, int)
                    or isinstance(total_records, bool)
                    or total_records != len(rows)
                ):
                    raise RuntimeError(
                        "Azure Resource Graph result does not match its total record count"
                    )
                return rows
            if not isinstance(raw_skip_token, str) or not raw_skip_token:
                raise RuntimeError("Azure Resource Graph returned an invalid skip token")
            if raw_skip_token in seen_tokens:
                raise RuntimeError("Azure Resource Graph repeated a continuation token")
            seen_tokens.add(raw_skip_token)
            skip_token = raw_skip_token
        raise RuntimeError(
            f"Azure Resource Graph query exceeded {MAX_RESOURCE_GRAPH_PAGES} pages"
        )


class AzureResourceGraphClient(ResourceGraphClient):
    def __init__(self, executable: str = "az") -> None:
        resolved = shutil.which(executable)
        if resolved is None:
            raise RuntimeError(
                "Azure CLI was not found. Install it and run 'az login' first."
            )
        self._executable = resolved

    def _request(self, body: Mapping[str, Any]) -> Mapping[str, Any]:
        command = [
            self._executable,
            "rest",
            "--method",
            "post",
            "--url",
            RESOURCE_GRAPH_URL,
            "--headers",
            "Content-Type=application/json",
            "--body",
            json.dumps(body),
            "--output",
            "json",
            "--only-show-errors",
        ]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                timeout=AZURE_COMMAND_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                f"Azure Resource Graph request timed out after "
                f"{AZURE_COMMAND_TIMEOUT_SECONDS} seconds"
            ) from error
        if len(completed.stdout) > MAX_AZURE_OUTPUT_BYTES:
            raise RuntimeError("Azure CLI response exceeded the configured size limit")
        if completed.returncode != 0:
            message = completed.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"Azure Resource Graph request failed: {message}")
        try:
            response = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("Azure CLI returned malformed JSON") from error
        if not isinstance(response, Mapping):
            raise RuntimeError("Azure CLI response is not an object")
        return response


def _score_dict(score: SubscriptionScore, control_counts: ControlCounts) -> dict[str, Any]:
    return {
        "tenantId": score.tenant_id,
        "subscriptionId": score.subscription_id,
        "subscriptionName": score.subscription_name,
        "current": score.current,
        "maximum": score.maximum,
        "percentage": score.percentage,
        "weight": score.weight,
        "assessedResources": score.assessed_resources,
        "healthyResources": score.healthy_resources,
        "unhealthyResources": score.unhealthy_resources,
        "notApplicableResources": score.not_applicable_resources,
        "totalControls": control_counts.total,
        "healthyControls": control_counts.healthy,
        "unhealthyControls": control_counts.unhealthy,
        "notApplicableControls": control_counts.not_applicable,
        "weightedContribution": score.weight * score.percentage,
        "available": score.available,
    }


def _control_dict(control: ControlScore) -> dict[str, Any]:
    percentage = control.current / control.maximum if control.maximum > 0.0 else 0.0
    return {
        "tenantId": control.tenant_id,
        "subscriptionId": control.subscription_id,
        "subscriptionName": control.subscription_name,
        "controlId": control.control_id,
        "controlName": control.control_name,
        "current": control.current,
        "maximum": control.maximum,
        "percentage": percentage,
        "weight": control.weight,
        "healthyResources": control.healthy_resources,
        "unhealthyResources": control.unhealthy_resources,
        "notApplicableResources": control.not_applicable_resources,
    }


def build_report(
    scores: Sequence[SubscriptionScore], controls: Sequence[ControlScore]
) -> dict[str, Any]:
    aggregate = calculate_aggregate(scores)
    controls_by_subscription = summarize_controls_by_subscription(controls)
    no_controls = ControlCounts(total=0, healthy=0, unhealthy=0, not_applicable=0)
    return {
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "aggregate": {
            "percentage": aggregate.percentage,
            "weightedPoints": aggregate.weighted_points,
            "totalWeight": aggregate.total_weight,
            "includedSubscriptions": aggregate.included_subscriptions,
            "excludedSubscriptions": aggregate.excluded_subscriptions,
        },
        "subscriptions": [
            _score_dict(
                score,
                controls_by_subscription.get(score.subscription_id, no_controls),
            )
            for score in scores
        ],
        "controls": [_control_dict(control) for control in controls],
    }


def _json_for_script(report: Mapping[str, Any]) -> str:
    return (
        json.dumps(report, ensure_ascii=False, separators=(",", ":"))
        .replace("<", "\\u003c")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def render_dashboard(report: Mapping[str, Any]) -> str:
    generated_timestamp = datetime.fromisoformat(str(report["generatedAt"]))
    generated_at = html.escape(
        generated_timestamp.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        quote=True,
    )
    data = _json_for_script(report)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<title>MDC Secure Score Overview</title>
<style>
:root {{ --ink:#15211d; --muted:#65736d; --paper:#f4f1e8; --panel:#fffdf7; --line:#d5d8cc; --green:#16715a; --amber:#c88412; --red:#b44734; --blue:#276a8c; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; color:var(--ink); background:var(--paper); font-family:"Aptos","Trebuchet MS",sans-serif; letter-spacing:0; }}
header {{ background:var(--ink); color:#fff; padding:28px clamp(20px,5vw,72px) 24px; border-bottom:5px solid var(--green); }}
.eyebrow {{ color:#9fc8b9; font-size:12px; font-weight:700; text-transform:uppercase; letter-spacing:1.5px; }}
h1 {{ margin:7px 0 4px; font-family:Georgia,serif; font-size:clamp(30px,5vw,54px); font-weight:500; }}
.stamp {{ color:#bac5c0; font-size:13px; }}
main {{ max-width:1500px; margin:auto; padding:24px clamp(16px,4vw,56px) 48px; }}
.metrics {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); border:1px solid var(--line); background:var(--panel); }}
.metric {{ min-width:0; padding:20px; border-right:1px solid var(--line); }} .metric:last-child {{ border:0; }}
.metric-label {{ color:var(--muted); font-size:12px; font-weight:700; text-transform:uppercase; }}
.metric-value {{ margin-top:5px; font-family:Georgia,serif; font-size:clamp(25px,4vw,42px); }}
.toolbar {{ display:flex; gap:12px; align-items:center; margin:24px 0 12px; flex-wrap:wrap; }}
input,select,button {{ height:40px; border:1px solid #aeb8b2; background:var(--panel); color:var(--ink); padding:0 12px; font:inherit; border-radius:4px; }}
input {{ flex:1; min-width:220px; }} select {{ min-width:190px; }}
button {{ cursor:pointer; font-weight:700; white-space:nowrap; }} button:hover {{ border-color:var(--green); color:var(--green); }} button:focus-visible {{ outline:3px solid #8bb9a8; outline-offset:2px; }}
.table-wrap {{ overflow:auto; border:1px solid var(--line); background:var(--panel); }}
table {{ width:100%; border-collapse:collapse; font-size:14px; }}
th {{ position:sticky; top:0; background:#e5e7dd; text-align:left; color:#3d4b45; font-size:11px; text-transform:uppercase; padding:11px 12px; white-space:nowrap; }}
.group-row th {{ background:#d4d9ce; border-bottom:1px solid #b8c0b7; font-size:12px; }}
.group-row .group {{ text-align:center; }}
.group-row .resources-group {{ background:#c8ddd3; color:#155b49; border-left:2px solid #7ea5b8; }}
.group-row .controls-group {{ background:#eadcbf; color:#775414; border-left:2px solid #7ea5b8; }}
.group-row .score-group {{ background:#cedde5; color:#245f7b; border-left:2px solid #7ea5b8; border-right:2px solid #7ea5b8; }}
.subscription-table .group-row th:first-child {{ border-left:2px solid #7ea5b8; }}
.column-row th {{ top:37px; }}
.column-row .resource-column {{ background:#e3eee8; }}
.column-row .control-column {{ background:#f2ead8; }}
.column-row .score-column {{ background:#e5eef2; }}
.column-row .resource-column:first-child {{ border-left:2px solid #9aaea5; }}
.column-row .control-column:nth-child(5) {{ border-left:2px solid #9aaea5; }}
.column-row .score-column:nth-child(9) {{ border-left:2px solid #9aaea5; }}
.column-row .score-column:last-child {{ border-right:2px solid #9aaea5; }}
.subscription-table tbody td:first-child {{ border-left:2px solid #9aaea5; }}
.subscription-table tbody td:nth-child(3) {{ border-left:2px solid #9aaea5; }}
.subscription-table tbody td:nth-child(7) {{ border-left:2px solid #9aaea5; }}
.subscription-table tbody td:nth-child(11) {{ border-left:2px solid #9aaea5; }}
.subscription-table tbody td:last-child {{ border-right:2px solid #9aaea5; }}
.subscription-table tbody td:nth-child(n+3):nth-child(-n+6) {{ background:#f3f8f5; }}
.subscription-table tbody td:nth-child(n+7):nth-child(-n+10) {{ background:#fbf7ed; }}
.subscription-table tbody td:nth-child(n+11):nth-child(-n+14) {{ background:#f2f7f9; }}
.subscription-table tbody tr:hover td:nth-child(n+3):nth-child(-n+6) {{ background:#e6f2eb; }}
.subscription-table tbody tr:hover td:nth-child(n+7):nth-child(-n+10) {{ background:#f3ead5; }}
.subscription-table tbody tr:hover td:nth-child(n+11):nth-child(-n+14) {{ background:#e4eff4; }}
td {{ padding:12px; border-top:1px solid var(--line); vertical-align:middle; }}
tbody tr:hover {{ background:#f1f5ef; }} .num {{ text-align:right; font-variant-numeric:tabular-nums; }}
.score {{ display:grid; grid-template-columns:58px minmax(90px,1fr); align-items:center; gap:8px; }}
.track {{ height:8px; background:#dfe2da; overflow:hidden; }} .fill {{ height:100%; background:var(--green); }}
.low .fill {{ background:var(--red); }} .medium .fill {{ background:var(--amber); }}
.section-head {{ margin:32px 0 12px; display:flex; justify-content:space-between; align-items:end; gap:12px; }}
h2 {{ margin:0; font-family:Georgia,serif; font-size:25px; font-weight:500; }} .count {{ color:var(--muted); font-size:13px; }}
.empty {{ padding:30px; text-align:center; color:var(--muted); }}
@media(max-width:800px) {{ .metrics {{ grid-template-columns:1fr 1fr; }} .metric:nth-child(2) {{ border-right:0; }} .metric:nth-child(-n+2) {{ border-bottom:1px solid var(--line); }} }}
@media(max-width:480px) {{ .metrics {{ grid-template-columns:1fr; }} .metric {{ border-right:0; border-bottom:1px solid var(--line); }} .metric:nth-child(3) {{ border-bottom:1px solid var(--line); }} }}
</style>
</head>
<body>
<header><div class="eyebrow">Microsoft Defender for Cloud</div><h1>Secure Score Overview</h1><div class="stamp">Generated {generated_at}</div></header>
<main>
<section class="metrics" id="metrics"></section>
<div class="section-head"><h2>Subscriptions</h2><span class="count" id="subscription-count"></span></div>
<div class="toolbar"><input id="subscription-search" type="search" maxlength="200" aria-label="Search subscriptions" placeholder="Filter subscriptions"><select id="subscription-filter" aria-label="Select subscription"><option value="">All subscriptions</option></select><button id="export-subscriptions" type="button">Export to Excel</button></div>
<div class="table-wrap"><table class="subscription-table"><thead><tr class="group-row"><th scope="col" rowspan="2">Subscription</th><th scope="col" rowspan="2">Secure score</th><th class="group resources-group" scope="colgroup" colspan="4">Resources</th><th class="group controls-group" scope="colgroup" colspan="4">Controls</th><th class="group score-group" scope="colgroup" colspan="4">Score</th></tr><tr class="column-row"><th class="num resource-column" scope="col">Assessed</th><th class="num resource-column" scope="col">Healthy</th><th class="num resource-column" scope="col">Unhealthy</th><th class="num resource-column" scope="col">N/A</th><th class="num control-column" scope="col">Total</th><th class="num control-column" scope="col">Healthy</th><th class="num control-column" scope="col">Unhealthy</th><th class="num control-column" scope="col">N/A</th><th class="num score-column" scope="col">Current</th><th class="num score-column" scope="col">Maximum</th><th class="num score-column" scope="col">Assigned weight</th><th class="num score-column" scope="col">Weighted contribution</th></tr></thead><tbody id="subscriptions"></tbody></table></div>
<div class="section-head"><h2>Security controls</h2><span class="count" id="control-count"></span></div>
<div class="toolbar"><input id="controls-search" type="search" maxlength="200" aria-label="Search security controls" placeholder="Filter security controls"><button id="export-controls" type="button">Export to Excel</button></div>
<div class="table-wrap"><table><thead><tr><th>Control</th><th>Subscription</th><th>Score</th><th class="num">Current</th><th class="num">Maximum</th><th class="num">Weight</th><th class="num">Healthy</th><th class="num">Unhealthy</th><th class="num">N/A</th></tr></thead><tbody id="controls"></tbody></table></div>
</main>
<script id="report-data" type="application/json">{data}</script>
<script>
'use strict';
const report=JSON.parse(document.getElementById('report-data').textContent);
const pct=value=>new Intl.NumberFormat(undefined,{{style:'percent',minimumFractionDigits:1,maximumFractionDigits:1}}).format(value);
const num=value=>new Intl.NumberFormat(undefined,{{maximumFractionDigits:2}}).format(value);
const text=value=>{{const span=document.createElement('span');span.textContent=String(value);return span.innerHTML;}};
const band=value=>value<0.4?'low':value<0.7?'medium':'high';
const scoreCell=(value,available=true)=>available?`<div class="score ${{band(value)}}"><span>${{pct(value)}}</span><div class="track"><div class="fill" style="width:${{Math.max(0,Math.min(100,value*100))}}%"></div></div></div>`:'<span>Unavailable</span>';
const DOWNLOAD_URL_REVOKE_DELAY_MS=1000;
const csvCell=value=>{{let cell=String(value??'');if(/^[\\t\\r\\n ]*[=+\\-@]/.test(cell))cell=`'${{cell}}`;return `"${{cell.replaceAll('"','""')}}"`;}};
function downloadCsv(filename,headers,rows){{const csv='\ufeff'+[headers,...rows].map(row=>row.map(csvCell).join(',')).join('\\r\\n');const url=URL.createObjectURL(new Blob([csv],{{type:'text/csv;charset=utf-8'}}));const link=document.createElement('a');link.href=url;link.download=filename;link.hidden=true;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),DOWNLOAD_URL_REVOKE_DELAY_MS);}}
const aggregate=report.aggregate;
document.getElementById('metrics').innerHTML=[['Overall score',pct(aggregate.percentage)],['Total weight',num(aggregate.totalWeight)],['Subscriptions',num(report.subscriptions.length)],['Security controls',num(report.controls.length)]].map(([label,value])=>`<div class="metric"><div class="metric-label">${{label}}</div><div class="metric-value">${{value}}</div></div>`).join('');
const subscriptionSelect=document.getElementById('subscription-filter');
for(const subscription of report.subscriptions){{const option=document.createElement('option');option.value=subscription.subscriptionId;option.textContent=subscription.subscriptionName;subscriptionSelect.append(option);}}
function filteredSubscriptions(){{
 const query=document.getElementById('subscription-search').value.trim().toLocaleLowerCase(); const selected=subscriptionSelect.value;
 return report.subscriptions.filter(item=>(!selected||item.subscriptionId===selected)&&(!query||`${{item.subscriptionName}} ${{item.subscriptionId}}`.toLocaleLowerCase().includes(query)));
}}
function renderSubscriptions(){{
 const subscriptions=filteredSubscriptions();
 document.getElementById('subscriptions').innerHTML=subscriptions.length?subscriptions.map(item=>`<tr><td><strong>${{text(item.subscriptionName)}}</strong><br><small>${{text(item.subscriptionId)}}</small></td><td>${{scoreCell(item.percentage,item.available)}}</td><td class="num">${{num(item.assessedResources)}}</td><td class="num">${{num(item.healthyResources)}}</td><td class="num">${{num(item.unhealthyResources)}}</td><td class="num">${{num(item.notApplicableResources)}}</td><td class="num">${{num(item.totalControls)}}</td><td class="num">${{num(item.healthyControls)}}</td><td class="num">${{num(item.unhealthyControls)}}</td><td class="num">${{num(item.notApplicableControls)}}</td><td class="num">${{item.available?num(item.current):'N/A'}}</td><td class="num">${{item.available?num(item.maximum):'N/A'}}</td><td class="num">${{item.available?num(item.weight):'N/A'}}</td><td class="num">${{item.available?num(item.weightedContribution):'N/A'}}</td></tr>`).join(''):'<tr><td colspan="14" class="empty">No matching subscriptions</td></tr>';
 document.getElementById('subscription-count').textContent=`${{subscriptions.length}} of ${{report.subscriptions.length}}`;
}}
function filteredControls(){{
 const query=document.getElementById('controls-search').value.trim().toLocaleLowerCase(); const selected=subscriptionSelect.value;
 return report.controls.filter(item=>(!selected||item.subscriptionId===selected)&&(!query||`${{item.controlName}} ${{item.subscriptionName}} ${{item.controlId}}`.toLocaleLowerCase().includes(query)));
}}
function renderControls(){{
 const controls=filteredControls();
 document.getElementById('controls').innerHTML=controls.length?controls.map(item=>`<tr><td><strong>${{text(item.controlName)}}</strong></td><td>${{text(item.subscriptionName)}}</td><td>${{scoreCell(item.percentage)}}</td><td class="num">${{num(item.current)}}</td><td class="num">${{num(item.maximum)}}</td><td class="num">${{num(item.weight)}}</td><td class="num">${{num(item.healthyResources)}}</td><td class="num">${{num(item.unhealthyResources)}}</td><td class="num">${{num(item.notApplicableResources)}}</td></tr>`).join(''):'<tr><td colspan="9" class="empty">No matching controls</td></tr>';
 document.getElementById('control-count').textContent=`${{controls.length}} of ${{report.controls.length}}`;
}}
document.getElementById('subscription-search').addEventListener('input',renderSubscriptions);subscriptionSelect.addEventListener('change',()=>{{renderSubscriptions();renderControls();}});
document.getElementById('controls-search').addEventListener('input',renderControls);
document.getElementById('export-subscriptions').addEventListener('click',()=>downloadCsv('mdc-subscriptions.csv',['Subscription','Subscription ID','Secure score','Assessed resources','Healthy resources','Unhealthy resources','Not applicable resources','Total controls','Healthy controls','Unhealthy controls','Not applicable controls','Current score','Maximum score','Assigned weight','Weighted contribution'],filteredSubscriptions().map(item=>[item.subscriptionName,item.subscriptionId,item.available?item.percentage:'N/A',item.assessedResources,item.healthyResources,item.unhealthyResources,item.notApplicableResources,item.totalControls,item.healthyControls,item.unhealthyControls,item.notApplicableControls,item.available?item.current:'N/A',item.available?item.maximum:'N/A',item.available?item.weight:'N/A',item.available?item.weightedContribution:'N/A'])));
document.getElementById('export-controls').addEventListener('click',()=>downloadCsv('mdc-security-controls.csv',['Control','Subscription','Secure score','Current score','Maximum score','Weight','Healthy resources','Unhealthy resources','Not applicable resources'],filteredControls().map(item=>[item.controlName,item.subscriptionName,item.percentage,item.current,item.maximum,item.weight,item.healthyResources,item.unhealthyResources,item.notApplicableResources])));
renderSubscriptions();renderControls();
</script>
</body>
</html>"""


def print_terminal_summary(report: Mapping[str, Any]) -> None:
    aggregate = report["aggregate"]
    subscriptions = report["subscriptions"]
    print("Microsoft Defender for Cloud Secure Score")
    print(
        f"Overall: {aggregate['percentage'] * 100:.2f}%  |  "
        f"Total weight: {aggregate['totalWeight']:.2f}  |  "
        f"Subscriptions: {aggregate['includedSubscriptions']}"
    )
    if aggregate["excludedSubscriptions"]:
        print(
            f"Excluded from aggregate (unavailable, zero weight, or zero max score): "
            f"{aggregate['excludedSubscriptions']}"
        )
    print()
    name_width = min(
        44,
        max(12, *(len(str(item["subscriptionName"])) for item in subscriptions)),
    )
    print(
        f"{'SUBSCRIPTION':<{name_width}}  {'SCORE':>8}  {'ASSESSED':>10}  "
        f"{'HEALTHY':>9}  {'UNHEALTHY':>10}  {'N/A':>7}  {'CURRENT':>9}  "
        f"{'MAX':>9}  {'WEIGHT':>10}"
    )
    print("-" * (name_width + 85))
    for item in sorted(subscriptions, key=lambda value: value["percentage"]):
        name = str(item["subscriptionName"])
        if len(name) > name_width:
            name = name[: name_width - 1] + "~"
        if item["available"]:
            print(
                f"{name:<{name_width}}  {item['percentage'] * 100:>7.2f}%  "
                f"{item['assessedResources']:>10}  "
                f"{item['healthyResources']:>9}  "
                f"{item['unhealthyResources']:>10}  "
                f"{item['notApplicableResources']:>7}  "
                f"{item['current']:>9.2f}  {item['maximum']:>9.2f}  "
                f"{item['weight']:>10.2f}"
            )
        else:
            print(
                f"{name:<{name_width}}  {'N/A':>8}  "
                f"{item['assessedResources']:>10}  "
                f"{item['healthyResources']:>9}  "
                f"{item['unhealthyResources']:>10}  "
                f"{item['notApplicableResources']:>7}  "
                f"{'N/A':>9}  {'N/A':>9}  "
                f"{'N/A':>10}"
            )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Retrieve all accessible Microsoft Defender for Cloud secure scores "
            "and generate a local dashboard."
        )
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("mdc-secure-score-dashboard.html"),
        help="HTML dashboard path (default: %(default)s)",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        default=Path("mdc-secure-score-data.json"),
        help="JSON export path (default: %(default)s)",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Open the generated dashboard in the default browser",
    )
    return parser.parse_args(argv)


def _fail(message: str) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        client = AzureResourceGraphClient()
        subscription_rows = client.query(SUBSCRIPTION_QUERY)
        assessed_resource_rows = client.query(ASSESSED_RESOURCE_QUERY)
        subscription_rows = attach_assessed_resource_counts(
            subscription_rows, assessed_resource_rows
        )
        control_rows = client.query(CONTROL_QUERY)
        scores = [SubscriptionScore.from_mapping(row) for row in subscription_rows]
        controls = [ControlScore.from_mapping(row) for row in control_rows]
        if not scores:
            raise RuntimeError(
                "No enabled subscriptions with MDC secure scores were returned. "
                "Verify Azure RBAC access and Defender for Cloud configuration."
            )
        score_ids = {score.subscription_id for score in scores}
        controls = [
            control for control in controls if control.subscription_id in score_ids
        ]
        report = build_report(scores, controls)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(render_dashboard(report), encoding="utf-8")
        args.json_output.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    except (DataValidationError, OSError, RuntimeError) as error:
        _fail(str(error))
    print_terminal_summary(report)
    print(f"\nDashboard: {args.output.resolve()}")
    print(f"JSON data: {args.json_output.resolve()}")
    if args.open:
        webbrowser.open(args.output.resolve().as_uri())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())