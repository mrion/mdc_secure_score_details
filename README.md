# MDC Secure Score Dashboard

This tool retrieves Microsoft Defender for Cloud secure scores and security
controls for every enabled Azure subscription visible to the current Azure CLI
session. It prints a terminal overview and creates a self-contained HTML
dashboard plus a JSON export. The subscription overview includes the distinct
number of resources with `Healthy` or `Unhealthy` Defender for Cloud
assessments, with separate healthy, unhealthy, and not-applicable counts. Each
resource is classified once: unhealthy takes precedence over healthy, followed
by not applicable. The assessed total excludes not-applicable resources.
Controls are summarized per subscription using the same precedence: a control
with any unhealthy resources is unhealthy; otherwise it is healthy when it has
healthy resources, and not applicable when it has neither.

The overall percentage uses Microsoft's subscription weighting formula:

```text
sum(subscription weight * subscription score percentage) / sum(subscription weight)
```

## Requirements

- Python 3.10 or newer
- Azure CLI
- An authenticated session created with `az login`
- Azure RBAC access to read Defender for Cloud data and subscriptions

The tool performs read-only Azure Resource Graph queries. It does not retrieve,
store, or embed Azure access tokens.

## Run

```bash
python3 mdc_secure_score_dashboard.py --open
```

Without `--open`, open `mdc-secure-score-dashboard.html` after the command
finishes. Use `--output` and `--json-output` to change the generated paths.

## Verify

```bash
python3 -m unittest discover -s tests -v
```

Microsoft references:

- [Secure score calculation](https://learn.microsoft.com/azure/defender-for-cloud/secure-score-security-controls#score-calculation-equations)
- [Azure Resource Graph samples](https://learn.microsoft.com/azure/defender-for-cloud/resource-graph-samples)
