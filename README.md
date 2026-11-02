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

## Security Copilot scheduled agent

The `security_copilot` directory contains an agent implementation, a Python
Azure Function backend, a Logic Apps workflow and Bicep infrastructure. These
are source/deployment artifacts: creating them does **not** deploy Azure
resources, install an agent, or enable a schedule.

```text
Security Copilot native recurring trigger (owner-selected interval)
  -> FetchSkill: GenerateMdcSecureScoreReport (LogicApp)
  -> Function: fixed Resource Graph queries and SLAM calculations
  -> Private Blob: one immutable archive containing HTML, JSON and summary
  -> FetchSkill returns [summary] for exactly one report
  -> ProcessSkill: summary plus protected dashboard and JSON links
```

Each successful retrieval includes:

| Level | Fields |
| --- | --- |
| Overall | Subscription-weighted percentage, total eligible weight, included/excluded subscription counts |
| Subscription | Name/ID, current/maximum score, percentage, assigned weight, weighted contribution, resource and control health counts |
| Control within subscription | Name/ID, current/maximum score, percentage, weight, healthy/unhealthy/not-applicable resources |

The agent dashboard reuses the original renderer's tables, subscription
selector, text filters and Excel-compatible CSV exports. Only its presentation
changes to the light/dark Clawpilot theme, with explicit coverage and score-model
notes. The original CLI dashboard and saved September snapshot are not replaced.

### Important scope and product distinctions

- This reports **classic MDC `ascScore`**, not Microsoft Secure Score or the
  risk-based Cloud Secure Score in the Defender portal. Classic control scores
  are recalculated approximately every eight hours; faster retrieval does not
  force Azure to recalculate them.
- "Overall" means the **explicitly configured reporting scope**, not every
  subscription in the tenant. `*` selects all subscriptions in the backend
  allowlist. End users can select a subset, but cannot expand that allowlist.
- Missing, disabled or inaccessible requested subscriptions fail the run rather
  than silently producing an incomplete overall score. An enabled subscription
  with no secure-score record is shown as unavailable and excluded.
- Zero-weight and zero-maximum subscriptions are excluded from the denominator.
  If no eligible subscriptions remain, the agent/dashboard says **Unavailable**.
  The JSON retains the original numeric aggregate for compatibility.
- `weightedContribution` is `weight * current / maximum`: unnormalized weighted
  points, not percentage points. Do not sum control weights to invent a
  subscription weight. The assigned subscription and control weights come from
  Azure independently.
- Queries are eventually consistent, not a transactionally consistent snapshot.
  The timestamp identifies retrieval time. Paging, duplicate detection and scope
  validation reject incomplete or inconsistent results.

### Prerequisites and authorization

Use an Azure public-cloud tenant with Security Copilot agent authoring enabled,
capacity available, and permission to upload/configure custom agents. This
implementation does not target sovereign clouds.

For deployment, install Azure CLI with Bicep support and sign in. You need
resource deployment permissions in the destination resource group and permission
to assign Reader to the Function's managed identity on **each** requested
subscription. The template also assigns Storage Blob Data Contributor on the
private report container. Reader is deliberately a broad, read-only baseline;
an administrator can design a narrower custom role for these ARG queries.

Create a **single-tenant Entra web/API app registration**:

1. Record its application/client ID and configure its identifier URI as
   `api://<client-id>`. Use v2 access tokens.
2. Create a client secret for Easy Auth browser sign-in. Supply it securely at
   deployment, not in source, a parameter file, the dashboard, or a URL.
3. After deployment, add the `webRedirectUri` output as a **Web** redirect URI:
   `https://<actual-function-host>/.auth/login/aad/callback`. Use the actual
   deployment output; do not infer a hostname.
4. The Logic App's managed identity requests an app-only token for this API.
   The backend authorizes its exact object ID. If your enterprise application
   requires assignment, define an application role and assign it to that
   managed identity before running the workflow. Likewise assign allowed
   human readers if enterprise-app assignment is required by tenant policy.

Four identities are separate: the Security Copilot run identity invokes the
Logic App; the Logic App identity invokes the Function; the Function identity
reads ARG and writes Blob; explicitly allowed human identities view reports.
Grant the configured Copilot run identity access to read/invoke the Logic App,
including its HTTP trigger/callback operation, according to tenant policy.

**Every allowed reader can read every report in this deployment.** The backend
does not impersonate readers for Azure RBAC and does not expand reader groups.
Use separate deployments for different audiences/authorization boundaries.
Supply Entra **object IDs**, not email addresses, for readers.

Functions have `ANONYMOUS` trigger authorization only because App Service
**Easy Auth is mandatory in front of every route**. Bicep enables tenant-specific
token validation and HTTPS; the application additionally checks the trusted
Easy Auth principal against generator/reader allowlists. Never expose this
Function behind a proxy that lets callers forge Easy Auth headers, or disable
Easy Auth while leaving the deployment flag enabled. A bare local Functions
host is not a secure production endpoint.

### Build, deploy and install

From the SLAM project directory, build a package with actual deployment
coordinates and an interval selected by the owner. This command is the
recurrence configuration, not an LLM prompt setting:

```powershell
python -m security_copilot.package --subscription-id "<deployment-subscription-guid>" --resource-group "<resource-group>" --workflow-name "<namePrefix>-collect" --interval-seconds 28800
```

On this project's Fedora WSL installation, the equivalent command from the
project directory in PowerShell is:

```powershell
wsl.exe --distribution fedora --exec python3 -m security_copilot.package --subscription-id "<deployment-subscription-guid>" --resource-group "<resource-group>" --workflow-name "<namePrefix>-collect" --interval-seconds 28800
```

`28800` is an example eight-hour interval, **not an activated schedule**.
The builder requires an explicit positive integer and writes it as numeric
`DefaultPeriodSeconds`. Microsoft does not document string interpolation of a
user setting into that field. Use the builder's Frequency configuration or
regenerate/reimport the manifest to change recurrence; confirm the installed
trigger's frequency before enabling it. Do not enable an additional Logic Apps
Recurrence trigger: that would create two schedules.

The output `security_copilot\dist` contains `agent.yaml`, `function-app.zip`,
the Bicep templates, `SETUP.txt`, and a **synthetic** `sample-dashboard.html`.
The Function ZIP uses a strict source-file whitelist: existing tenant JSON,
saved dashboards, credentials, caches and local environments are excluded.
The builder refuses to overwrite an existing output directory; use `--output`
with another directory when rebuilding.

Prepare `parameters.json` using `security_copilot\infra\parameters.example.json`,
replacing every example value. Deploy only after reviewing the resource,
permission and cost implications:

```powershell
az deployment group create --resource-group "<resource-group>" --template-file ".\security_copilot\dist\infra\main.bicep" --parameters "@parameters.json"
```

The required secure `apiClientSecret` parameter is intentionally omitted from
the example file; supply it through the CLI's secure interactive prompt or your
approved secret-management pipeline. Do not place it in shell history. Record
the deployment outputs and configure the app registration's redirect URI.

Deploy the Function package with remote Python dependency installation:

```powershell
az functionapp deployment source config-zip --resource-group "<resource-group>" --name "<functionAppName-output>" --src ".\security_copilot\dist\function-app.zip" --build-remote true
```

The workflow name in `agent.yaml` must equal the deployment's `workflowName`.
Allow Azure RBAC propagation before the first run. No resource creation,
deployment, identity grants or consent have been performed by building the
local files.

In Security Copilot:

1. Upload the generated `agent.yaml` through the custom agent/plugin workflow.
2. Configure its run identity and grant that identity Logic App invocation
   permissions. Make the skillset available to that identity.
3. Set **Reporting subscriptions** (`SubscriptionIds`) to `*` or a comma-separated
   approved subset. This setting is passed to the FetchSkill, not the process
   skill. Check the selected native trigger frequency.
4. Evaluate the fetch tool manually, then run the complete agent before enabling
   its schedule. Confirm the tool's evaluated result is an **array containing
   exactly one object**, not a response envelope or JSON string. Check the
   report timestamp, scope, and protected links with an allowed reader account.
5. Enable the recurring trigger only when those checks succeed.

### Platform boundaries requiring tenant validation

Microsoft documents the native trigger, LogicApp tools, and fetch-array
contract separately. Its public examples do not establish that every tenant's
LogicApp tool returns its HTTP response body unchanged when used as a FetchSkill.
The workflow deliberately returns HTTP 200 with `[summary]`; evaluate that
boundary in your tenant before treating this package as production-ready.

The process skill is a presentation-only `AGENT` with no child tools. The agent
build guide calls child skills optional, while the manifest reference is
inconsistent. Validate this presentation-only entrypoint during import. A GPT
skill is documented, but the exact GPT-as-scheduled-ProcessSkill combination is
not established by the public examples; it is not an assumed fallback.

There is no documented native custom-agent HTML-file attachment/rendering
contract, so this agent returns **authenticated links**, not attached files or
embedded executable HTML. Outbound Logic Apps is used for report persistence
instead of an API-plugin write, which current API-plugin docs do not support.
No OpenAPI endpoint or public schema hosting is needed by this integration.

The exact Security Copilot LogicApp-tool wait limit is not publicly specified.
Collection uses bounded HTTP requests and a total budget; measure real run
duration for the intended scope. Slow/large environments may need a Durable
Functions asynchronous workflow or a Logic Apps-owned schedule. A 202 response
alone is not a documented way to make a Security Copilot API tool poll.

### Operations and local development

Each Logic App workflow run passes its stable run identifier. A retry with that
identifier and the same canonical subscription scope reuses the stored report.
Different scheduled/manual runs get different report IDs. A single immutable
ZIP Blob holds `dashboard.html`, `report.json`, and `result.json`, preventing
partially published HTML/JSON pairs and eliminating shared "latest" file races.
No public Blob access, SAS URL or Function key is returned.

Artifacts contain tenant security posture data. Keep reader access narrow,
review retention policy, and do not enable public static-website hosting.
Nothing emails, messages or shares reports with additional recipients.
Storage retention is not automatically limited by this template.

The backend uses managed identity only; no `az login` session is needed in
Azure. For local tests, create an isolated Python environment, install
`security_copilot\requirements.txt`, then use the existing unittest runner:

```powershell
python -m unittest discover -s tests -v
```

The original CLI requires only Python/Azure CLI. Its original tests can still
run without Azure SDK dependencies using `python -m unittest tests.test_scores`.
Backend tests use mocked Azure services; no tenant credentials are required.

### Agent reference documentation

- [Agent manifest and trigger schema](https://learn.microsoft.com/copilot/security/developer/agent-manifest)
- [FetchSkill, ProcessSkill and settings semantics](https://learn.microsoft.com/copilot/security/developer/agent-components)
- [Build agent manifests](https://learn.microsoft.com/copilot/security/developer/build-agent-manifest)
- [Outbound Logic Apps tools](https://learn.microsoft.com/copilot/security/developer/plugin-logic-apps)
- [API plugin limitations](https://learn.microsoft.com/copilot/security/plugin-api#limitations)
- [App Service authentication](https://learn.microsoft.com/azure/app-service/overview-authentication-authorization)
- [Resource Graph paging and truncation](https://learn.microsoft.com/azure/governance/resource-graph/concepts/work-with-data)