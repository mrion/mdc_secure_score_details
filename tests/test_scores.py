from __future__ import annotations

import math
import unittest

from mdc_secure_score_dashboard import (
    ControlScore,
    DataValidationError,
    SubscriptionScore,
    attach_assessed_resource_counts,
    build_report,
    calculate_aggregate,
    render_dashboard,
    summarize_controls_by_subscription,
)


def score(*, current: float, maximum: float, weight: float) -> SubscriptionScore:
    return SubscriptionScore.from_mapping(
        {
            "tenantId": "tenant-1",
            "subscriptionId": f"subscription-{current}-{weight}",
            "subscriptionName": "Test subscription",
            "currentScore": current,
            "maxScore": maximum,
            "weight": weight,
            "assessedResourceCount": 4,
            "healthyResourceCount": 3,
            "unhealthyResourceCount": 1,
            "notApplicableResourceCount": 2,
        }
    )


class AggregateScoreTests(unittest.TestCase):
    def test_summarizes_each_control_into_one_health_state(self) -> None:
        controls = [
            ControlScore.from_mapping(
                {
                    "tenantId": "tenant-1",
                    "subscriptionId": "subscription-1",
                    "subscriptionName": "Subscription",
                    "controlId": control_id,
                    "controlName": control_id,
                    "currentScore": current,
                    "maxScore": 2,
                    "weight": 1,
                    "healthyResourceCount": healthy,
                    "unhealthyResourceCount": unhealthy,
                    "notApplicableResourceCount": not_applicable,
                }
            )
            for control_id, current, healthy, unhealthy, not_applicable in (
                ("healthy", 2, 3, 0, 0),
                ("unhealthy", 1, 2, 1, 0),
                ("not-applicable", 0, 0, 0, 4),
            )
        ]

        summary = summarize_controls_by_subscription(controls)["subscription-1"]

        self.assertEqual(summary.total, 3)
        self.assertEqual(summary.healthy, 1)
        self.assertEqual(summary.unhealthy, 1)
        self.assertEqual(summary.not_applicable, 1)

    def test_attaches_assessed_resource_counts_and_defaults_missing_to_zero(self) -> None:
        subscriptions = [
            {"subscriptionId": "subscription-1"},
            {"subscriptionId": "subscription-2"},
        ]

        result = attach_assessed_resource_counts(
            subscriptions,
            [
                {
                    "subscriptionId": "subscription-1",
                    "assessedResourceCount": 7,
                    "healthyResourceCount": 5,
                    "unhealthyResourceCount": 2,
                    "notApplicableResourceCount": 3,
                }
            ],
        )

        self.assertEqual(result[0]["assessedResourceCount"], 7)
        self.assertEqual(result[0]["healthyResourceCount"], 5)
        self.assertEqual(result[0]["unhealthyResourceCount"], 2)
        self.assertEqual(result[0]["notApplicableResourceCount"], 3)
        self.assertEqual(result[1]["assessedResourceCount"], 0)

    def test_rejects_duplicate_assessed_resource_counts(self) -> None:
        with self.assertRaises(DataValidationError):
            attach_assessed_resource_counts(
                [{"subscriptionId": "subscription-1"}],
                [
                    {
                        "subscriptionId": "subscription-1",
                        "assessedResourceCount": 1,
                        "healthyResourceCount": 1,
                        "unhealthyResourceCount": 0,
                        "notApplicableResourceCount": 0,
                    },
                    {
                        "subscriptionId": "subscription-1",
                        "assessedResourceCount": 2,
                        "healthyResourceCount": 1,
                        "unhealthyResourceCount": 1,
                        "notApplicableResourceCount": 0,
                    },
                ],
            )

    def test_uses_subscription_weight_not_arithmetic_average(self) -> None:
        result = calculate_aggregate(
            [
                score(current=8.0, maximum=10.0, weight=3.0),
                score(current=2.0, maximum=10.0, weight=1.0),
            ]
        )

        self.assertTrue(math.isclose(result.percentage, 0.65))
        self.assertEqual(result.total_weight, 4.0)
        self.assertEqual(result.included_subscriptions, 2)

    def test_excludes_zero_weight_and_zero_maximum(self) -> None:
        result = calculate_aggregate(
            [
                score(current=5.0, maximum=10.0, weight=2.0),
                score(current=10.0, maximum=10.0, weight=0.0),
                score(current=0.0, maximum=0.0, weight=4.0),
            ]
        )

        self.assertEqual(result.percentage, 0.5)
        self.assertEqual(result.included_subscriptions, 1)
        self.assertEqual(result.excluded_subscriptions, 2)

    def test_empty_input_returns_zero_aggregate(self) -> None:
        result = calculate_aggregate([])

        self.assertEqual(result.percentage, 0.0)
        self.assertEqual(result.total_weight, 0.0)

    def test_unavailable_subscription_is_reported_but_excluded(self) -> None:
        unavailable = SubscriptionScore.from_mapping(
            {
                "tenantId": "tenant-1",
                "subscriptionId": "subscription-without-score",
                "subscriptionName": "No MDC score",
                "currentScore": 0.0,
                "maxScore": 0.0,
                "weight": 0.0,
                "assessedResourceCount": 0,
                "healthyResourceCount": 0,
                "unhealthyResourceCount": 0,
                "notApplicableResourceCount": 0,
                "hasSecureScore": False,
            }
        )

        result = calculate_aggregate([unavailable])

        self.assertFalse(unavailable.available)
        self.assertEqual(result.included_subscriptions, 0)
        self.assertEqual(result.excluded_subscriptions, 1)

    def test_accepts_resource_graph_string_boolean(self) -> None:
        unavailable = SubscriptionScore.from_mapping(
            {
                "tenantId": "tenant-1",
                "subscriptionId": "subscription-without-score",
                "subscriptionName": "No MDC score",
                "currentScore": 0.0,
                "maxScore": 0.0,
                "weight": 0.0,
                "assessedResourceCount": 0,
                "healthyResourceCount": 0,
                "unhealthyResourceCount": 0,
                "notApplicableResourceCount": 0,
                "hasSecureScore": "false",
            }
        )

        self.assertFalse(unavailable.available)

    def test_accepts_resource_graph_numeric_boolean(self) -> None:
        available = SubscriptionScore.from_mapping(
            {
                "tenantId": "tenant-1",
                "subscriptionId": "subscription-with-score",
                "subscriptionName": "MDC score",
                "currentScore": 1.0,
                "maxScore": 2.0,
                "weight": 1.0,
                "assessedResourceCount": 2,
                "healthyResourceCount": 1,
                "unhealthyResourceCount": 1,
                "notApplicableResourceCount": 0,
                "hasSecureScore": 1,
            }
        )

        self.assertTrue(available.available)

    def test_rejects_non_finite_and_inconsistent_scores(self) -> None:
        with self.assertRaises(DataValidationError):
            score(current=float("nan"), maximum=10.0, weight=1.0)
        with self.assertRaises(DataValidationError):
            score(current=11.0, maximum=10.0, weight=1.0)

    def test_dashboard_escapes_untrusted_azure_text(self) -> None:
        subscription = SubscriptionScore.from_mapping(
            {
                "tenantId": "tenant-1",
                "subscriptionId": "subscription-1",
                "subscriptionName": "</script><script>alert(1)</script>",
                "currentScore": 5.0,
                "maxScore": 10.0,
                "weight": 2.0,
                "assessedResourceCount": 2,
                "healthyResourceCount": 1,
                "unhealthyResourceCount": 1,
                "notApplicableResourceCount": 0,
            }
        )
        control = ControlScore.from_mapping(
            {
                "tenantId": "tenant-1",
                "subscriptionId": "subscription-1",
                "subscriptionName": subscription.subscription_name,
                "controlId": "control-1",
                "controlName": "Unsafe <control>",
                "currentScore": 1.0,
                "maxScore": 2.0,
                "weight": 1.0,
                "healthyResourceCount": 1,
                "unhealthyResourceCount": 1,
                "notApplicableResourceCount": 0,
            }
        )

        dashboard = render_dashboard(build_report([subscription], [control]))

        self.assertNotIn("</script><script>alert(1)</script>", dashboard)
        self.assertIn("\\u003c/script>\\u003cscript>alert(1)\\u003c/script>", dashboard)

    def test_dashboard_groups_subscription_resource_and_score_columns(self) -> None:
        dashboard = render_dashboard(build_report([], []))

        self.assertIn(
            '<th class="group resources-group" scope="colgroup" colspan="4">Resources</th>',
            dashboard,
        )
        self.assertIn(
            '<th class="group score-group" scope="colgroup" colspan="4">Score</th>',
            dashboard,
        )
        self.assertIn(
            '<th class="group controls-group" scope="colgroup" colspan="4">Controls</th>',
            dashboard,
        )
        self.assertEqual(dashboard.count('class="num resource-column"'), 4)
        self.assertEqual(dashboard.count('class="num control-column"'), 4)
        self.assertEqual(dashboard.count('class="num score-column"'), 4)
        self.assertIn(
            ".subscription-table tbody td:nth-child(11)", dashboard
        )
        self.assertIn(
            ".column-row .score-column:nth-child(9)", dashboard
        )
        self.assertIn(
            ".column-row .resource-column:first-child", dashboard
        )
        self.assertIn(
            ".column-row .score-column:last-child", dashboard
        )
        self.assertIn(
            ".subscription-table .group-row th:first-child", dashboard
        )
        self.assertIn(
            ".subscription-table tbody td:first-child", dashboard
        )
        self.assertIn(
            ".subscription-table tbody td:nth-child(3)", dashboard
        )
        self.assertIn(
            ".subscription-table tbody td:last-child", dashboard
        )
        self.assertNotIn(
            ".subscription-table :is(th,td):nth-child", dashboard
        )
        self.assertIn('<th scope="col" rowspan="2">Subscription</th>', dashboard)
        self.assertIn('<th scope="col" rowspan="2">Secure score</th>', dashboard)

    def test_dashboard_uses_shared_subscription_and_independent_text_filters(self) -> None:
        dashboard = render_dashboard(build_report([], []))

        self.assertIn('id="subscription-search"', dashboard)
        self.assertIn('id="controls-search"', dashboard)
        self.assertIn('id="subscription-filter"', dashboard)
        self.assertNotIn('id="controls-subscription-filter"', dashboard)
        self.assertIn("const selected=subscriptionSelect.value;", dashboard)
        self.assertIn(
            "subscriptionSelect.addEventListener('change',()=>{renderSubscriptions();renderControls();})",
            dashboard,
        )
        self.assertIn("function renderSubscriptions()", dashboard)
        self.assertIn("function renderControls()", dashboard)
        self.assertNotIn('id="search"', dashboard)

    def test_dashboard_displays_control_current_and_maximum_scores(self) -> None:
        dashboard = render_dashboard(build_report([], []))

        self.assertIn('<th class="num">Current</th>', dashboard)
        self.assertIn('<th class="num">Maximum</th>', dashboard)
        self.assertIn('${num(item.current)}', dashboard)
        self.assertIn('${num(item.maximum)}', dashboard)
        self.assertIn('<td colspan="9" class="empty">No matching controls</td>', dashboard)

    def test_dashboard_exports_filtered_tables_as_safe_csv(self) -> None:
        dashboard = render_dashboard(build_report([], []))

        self.assertIn('id="export-subscriptions"', dashboard)
        self.assertIn('id="export-controls"', dashboard)
        self.assertIn("downloadCsv('mdc-subscriptions.csv'", dashboard)
        self.assertIn("downloadCsv('mdc-security-controls.csv'", dashboard)
        self.assertIn("filteredSubscriptions().map", dashboard)
        self.assertIn("filteredControls().map", dashboard)
        self.assertIn("if(/^[\\t\\r\\n ]*[=+\\-@]/.test(cell))", dashboard)
        self.assertIn("cell.replaceAll('\"','\"\"')", dashboard)
        self.assertIn(".join('\\r\\n')", dashboard)
        self.assertNotIn("]))))", dashboard)
        self.assertIn("const DOWNLOAD_URL_REVOKE_DELAY_MS=1000;", dashboard)
        self.assertIn(
            "setTimeout(()=>URL.revokeObjectURL(url),DOWNLOAD_URL_REVOKE_DELAY_MS)",
            dashboard,
        )
        self.assertIn("document.body.append(link);link.click();link.remove()", dashboard)

    def test_rejects_fractional_assessed_resource_count(self) -> None:
        with self.assertRaises(DataValidationError):
            SubscriptionScore.from_mapping(
                {
                    "tenantId": "tenant-1",
                    "subscriptionId": "subscription-1",
                    "subscriptionName": "Invalid count",
                    "currentScore": 1.0,
                    "maxScore": 2.0,
                    "weight": 1.0,
                    "assessedResourceCount": 1.5,
                    "healthyResourceCount": 1,
                    "unhealthyResourceCount": 0,
                    "notApplicableResourceCount": 0,
                }
            )

    def test_rejects_inconsistent_resource_status_totals(self) -> None:
        with self.assertRaises(DataValidationError):
            SubscriptionScore.from_mapping(
                {
                    "tenantId": "tenant-1",
                    "subscriptionId": "subscription-1",
                    "subscriptionName": "Invalid total",
                    "currentScore": 1.0,
                    "maxScore": 2.0,
                    "weight": 1.0,
                    "assessedResourceCount": 3,
                    "healthyResourceCount": 1,
                    "unhealthyResourceCount": 1,
                    "notApplicableResourceCount": 0,
                }
            )


if __name__ == "__main__":
    unittest.main()