"""
blast_radius.py — Financial Blast Radius Copilot (Tier 2)
=========================================================
Ported from the hackathon agent and adapted to the kiro pipeline's data model
(alert payload + triage dict + findings dict, instead of an AlertScenario).

Produces a unified narrative answering:
  1. WHAT BROKE   — technical root cause (suspected → confirmed)
  2. WHAT IT COSTS — customer impact + financial bleed rate + runbook savings

Business numbers are SIMULATED from alert metrics (formula-based) unless live
Datadog data is available. The technical cause is confirmed by the Bedrock
investigation loop. Always surfaces `data_source` so judges/engineers know
whether a figure is measured or estimated.
"""

import logging
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Runbook catalog keyed by service
# ---------------------------------------------------------------------------

RUNBOOKS: dict[str, dict[str, Any]] = {
    "auth-service": {
        "title": "Roll back auth deploy and flush token cache",
        "action": "Revert the latest auth-service release and clear the session/token cache",
        "estimated_savings_usd": 1800,
    },
    "checkout-service": {
        "title": "Route traffic to backup database",
        "action": "Failover checkout DB read replica and drain connection pool",
        "estimated_savings_usd": 2000,
    },
    "orders-service": {
        "title": "Scale order workers and enable request batching",
        "action": "Increase worker pool and switch to batched line-item API",
        "estimated_savings_usd": 1500,
    },
    "default": {
        "title": "Execute standard incident runbook",
        "action": "Follow on-call runbook for service failover and traffic shedding",
        "estimated_savings_usd": 1000,
    },
}

# Heuristic "customers stuck" fallback by severity when no metric is available.
_SEV_STUCK_FALLBACK = {"critical": 200, "high": 80, "medium": 30, "low": 10}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class TechnicalImpact:
    """What broke — technical root cause and affected components."""

    service: str
    endpoint: str
    error_codes: list[str]
    suspected_root_cause: str
    confirmed_root_cause: str = ""
    affected_file: str = ""
    symptoms: list[str] = field(default_factory=list)
    fix_pr_url: str = ""
    status: str = "suspected"  # "suspected" | "confirmed"


@dataclass
class BusinessImpact:
    """What it costs — customer and financial impact."""

    affected_customers: int
    affected_services: list[str]
    financial_bleed_rate_usd_per_min: float
    estimated_loss_next_30_min_usd: float
    recommended_runbook_title: str
    recommended_runbook_action: str
    recommended_runbook_url: str
    runbook_estimated_savings_usd: float
    data_source: str = "simulated"


@dataclass
class BlastRadiusReport:
    """Unified blast-radius output combining technical + business impact."""

    alert_title: str
    severity: str
    technical: TechnicalImpact
    business: BusinessImpact

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_title": self.alert_title,
            "severity": self.severity,
            "technical": asdict(self.technical),
            "business": asdict(self.business),
        }


# ---------------------------------------------------------------------------
# Calculator
# ---------------------------------------------------------------------------


class BlastRadiusCalculator:
    """Compute preliminary and final blast-radius reports from alert + triage data."""

    @classmethod
    def compute_preliminary(cls, payload: dict, triage: dict) -> BlastRadiusReport:
        service = str(triage.get("affected_service") or "unknown-service")
        technical = cls._build_technical(payload, triage, service)
        business = cls._build_business(payload, triage, service)
        severity = cls._map_severity(triage.get("severity", "high"))
        return BlastRadiusReport(
            alert_title=payload.get("title", "Unknown Alert"),
            severity=severity,
            technical=technical,
            business=business,
        )

    @classmethod
    def merge_final(
        cls,
        preliminary: BlastRadiusReport,
        findings: dict,
        summary: str,
        pr_url: str = "",
    ) -> BlastRadiusReport:
        """Promote suspected → confirmed using investigation results."""
        confirmed = (
            str(findings.get("root_cause", "")).strip()
            or summary.strip()
            or preliminary.technical.suspected_root_cause
        )

        technical = TechnicalImpact(
            service=preliminary.technical.service,
            endpoint=preliminary.technical.endpoint,
            error_codes=preliminary.technical.error_codes,
            suspected_root_cause=preliminary.technical.suspected_root_cause,
            confirmed_root_cause=confirmed,
            affected_file=preliminary.technical.affected_file,
            symptoms=preliminary.technical.symptoms,
            fix_pr_url=pr_url or preliminary.technical.fix_pr_url,
            status="confirmed",
        )

        return BlastRadiusReport(
            alert_title=preliminary.alert_title,
            severity=preliminary.severity,
            technical=technical,
            business=preliminary.business,
        )

    # ------------------------------------------------------------------
    # Builders
    # ------------------------------------------------------------------

    @classmethod
    def _build_technical(cls, payload: dict, triage: dict, service: str) -> TechnicalImpact:
        body = str(payload.get("body", ""))
        suspected = (
            str(triage.get("summary", "")).strip()
            or body.strip()
            or payload.get("title", "")
        )

        # Best-effort extraction from the alert body
        error_codes = re.findall(r"\b(?:5\d{2}|4\d{2})\b", body)
        symptoms: list[str] = []
        atype = triage.get("alert_type", "")
        if atype and atype != "unknown":
            symptoms.append(f"{atype} signature detected")

        return TechnicalImpact(
            service=service,
            endpoint="",
            error_codes=sorted(set(error_codes)),
            suspected_root_cause=suspected,
            symptoms=symptoms,
            status="suspected",
        )

    @classmethod
    def _build_business(cls, payload: dict, triage: dict, service: str) -> BusinessImpact:
        sev = str(triage.get("severity", "high")).lower()
        stuck, data_source = cls._resolve_stuck_customers(payload, service, sev)

        avg_order = float(os.getenv("AVG_ORDER_VALUE_USD", "29.99"))
        attempts = float(os.getenv("CHECKOUT_ATTEMPTS_PER_CUSTOMER_PER_MIN", "0.35"))
        bleed_per_min = round(stuck * avg_order * attempts, 2)
        loss_30 = round(bleed_per_min * 30, 2)

        runbook = RUNBOOKS.get(service, RUNBOOKS["default"])
        mttr_min = float(os.getenv("RUNBOOK_MTTR_SAVINGS_MINUTES", "14"))
        savings = round(bleed_per_min * mttr_min, 2) or float(
            runbook.get("estimated_savings_usd", 1000)
        )

        return BusinessImpact(
            affected_customers=stuck,
            affected_services=[service] if service else [],
            financial_bleed_rate_usd_per_min=bleed_per_min,
            estimated_loss_next_30_min_usd=loss_30,
            recommended_runbook_title=str(runbook.get("title", "Execute incident runbook")),
            recommended_runbook_action=str(runbook.get("action", "")),
            recommended_runbook_url=str(payload.get("url", "")),
            runbook_estimated_savings_usd=savings,
            data_source=data_source,
        )

    @classmethod
    def _resolve_stuck_customers(
        cls, payload: dict, service: str, severity: str
    ) -> tuple[int, str]:
        # 1. Try live Datadog error count
        dd_count = cls._query_datadog_error_count(service)
        if dd_count is not None:
            return dd_count, "datadog"

        # 2. Parse affected users / error rate hints from the alert body
        body = str(payload.get("body", ""))
        users_match = re.search(r"(\d[\d,]*)\s*(?:users|customers)", body, re.I)
        if users_match:
            try:
                return max(1, int(users_match.group(1).replace(",", ""))), "simulated"
            except ValueError:
                pass

        # 3. Severity-based fallback
        return _SEV_STUCK_FALLBACK.get(severity, 42), "simulated"

    @classmethod
    def _query_datadog_error_count(cls, service: str) -> Optional[int]:
        api_key = os.getenv("DD_API_KEY", "")
        app_key = os.getenv("DD_APP_KEY", "")
        if not api_key or not app_key or not service or service == "unknown-service":
            return None

        site = os.getenv("DD_SITE", "datadoghq.com")
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=15)
        query = f"sum:trace.http.request.errors{{service:{service}}}.as_count()"

        try:
            resp = requests.get(
                f"https://api.{site}/api/v1/query",
                params={"from": int(start.timestamp()), "to": int(end.timestamp()), "query": query},
                headers={"DD-API-KEY": api_key, "DD-APPLICATION-KEY": app_key},
                timeout=10,
            )
            if resp.status_code != 200:
                return None
            series = resp.json().get("series", [])
            if not series:
                return None
            points = series[0].get("pointlist", [])
            total = sum(p[1] for p in points if p[1] is not None)
            return max(1, int(total)) if total > 0 else None
        except requests.RequestException as exc:
            logger.debug("Datadog metrics enrichment skipped: %s", exc)
            return None

    @classmethod
    def _map_severity(cls, raw: str) -> str:
        mapping = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
        return mapping.get(str(raw).lower(), "High")


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def format_blast_radius_card(report: BlastRadiusReport) -> str:
    """Return a judge-friendly multi-line card with WHAT BROKE + WHAT IT COSTS."""
    t = report.technical
    b = report.business

    root_cause = (
        t.confirmed_root_cause
        if t.status == "confirmed" and t.confirmed_root_cause
        else t.suspected_root_cause
    )
    status_label = "CONFIRMED" if t.status == "confirmed" else "SUSPECTED"

    lines = [
        "",
        "=" * 42,
        "  FINANCIAL BLAST RADIUS COPILOT",
        "=" * 42,
        "",
        f"🚨 {report.severity} Alert: {report.alert_title}",
        "",
        "WHAT BROKE",
        f"  Status:      {status_label}",
        f"  Service:     {t.service}" + (f" ({t.endpoint})" if t.endpoint else ""),
    ]

    if t.affected_file:
        lines.append(f"  File:        {t.affected_file}")
    if t.error_codes:
        lines.append(f"  Error codes: {', '.join(t.error_codes)}")
    if t.symptoms:
        lines.append(f"  Symptoms:    {'; '.join(t.symptoms[:3])}")

    lines.append(f"  Root cause:  {root_cause}")

    if t.fix_pr_url:
        lines.append(f"  Fix PR:      {t.fix_pr_url}")

    lines.extend([
        "",
        "WHAT IT COSTS",
        f"  Customers stuck right now:     {b.affected_customers}",
        f"  Financial bleed rate:        ${b.financial_bleed_rate_usd_per_min:,.0f}/min",
        f"  Projected loss (30 min):       ${b.estimated_loss_next_30_min_usd:,.0f}",
        f"  Data source:                 {b.data_source}",
        "",
        "RECOMMENDED ACTION",
        f"  Runbook: {b.recommended_runbook_title}",
        f"  Action:  {b.recommended_runbook_action}",
    ])

    if b.recommended_runbook_url:
        lines.append(f"  URL:     {b.recommended_runbook_url}")

    lines.append(
        f"  Estimated savings if applied now: ~${b.runbook_estimated_savings_usd:,.0f}"
    )
    lines.append("")
    lines.append("=" * 42)
    lines.append("")

    return "\n".join(lines)


def format_blast_radius_context(report: BlastRadiusReport) -> str:
    """Short block injected into the Bedrock investigator prompt."""
    t = report.technical
    b = report.business
    return (
        "BLAST RADIUS CONTEXT (use these numbers in your final summary — do NOT invent):\n"
        f"WHAT BROKE (suspected): {t.suspected_root_cause}\n"
        f"WHAT IT COSTS: {b.affected_customers} customers stuck, "
        f"${b.financial_bleed_rate_usd_per_min:,.0f}/min bleed rate, "
        f"${b.estimated_loss_next_30_min_usd:,.0f} projected loss over 30 min\n"
        f"RECOMMENDED ACTION: {b.recommended_runbook_title} "
        f"(saves ~${b.runbook_estimated_savings_usd:,.0f})"
    )
