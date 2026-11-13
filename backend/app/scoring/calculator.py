"""Explainable Phishing Risk Scoring Engine.

Implements category-grouped diminishing returns aggregation, mathematical caps,
corroboration requirements, and severity classification bounded strictly within [0, 100].
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.detection.engine import TriggeredFinding


@dataclass
class CategoryScoreDetail:
    category: str
    category_cap: float
    raw_rule_sum: float
    diminishing_score: float
    rules_triggered_count: int


@dataclass
class RiskScoreResult:
    final_score: float
    severity_level: str  # low, moderate, high, critical
    category_scores: dict[str, float]
    category_details: list[CategoryScoreDetail]
    triggered_rules: list[TriggeredFinding]
    formula_explanation: str
    is_corroborated_threat: bool


class PhishingRiskScorer:
    """Calculates normalized, explainable risk scores [0, 100] from detection findings."""

    # Maximum score contribution per category (prevents single-vector bias)
    CATEGORY_CAPS: dict[str, float] = {
        "URL": 40.0,
        "ATTACH": 40.0,
        "AUTH": 35.0,
        "SENDER": 30.0,
        "HEADER": 20.0,
        "CONTENT": 20.0,
    }

    SEVERITY_BANDS = [
        (0.0, 29.9, "low"),
        (30.0, 59.9, "moderate"),
        (60.0, 84.9, "high"),
        (85.0, 100.0, "critical"),
    ]

    def calculate(self, findings: list[TriggeredFinding]) -> RiskScoreResult:
        """Compute the final risk score with category diminishing returns."""
        # Deduplicate findings by rule_id (take the highest effective score if duplicate)
        deduped_findings: dict[str, TriggeredFinding] = {}
        for f in findings:
            if f.rule_id not in deduped_findings:
                deduped_findings[f.rule_id] = f
            elif f.effective_score > deduped_findings[f.rule_id].effective_score:
                deduped_findings[f.rule_id] = f

        active_findings = list(deduped_findings.values())

        # Group findings by category
        grouped: dict[str, list[TriggeredFinding]] = {cat: [] for cat in self.CATEGORY_CAPS}
        for f in active_findings:
            if f.category in grouped:
                grouped[f.category].append(f)
            else:
                grouped.setdefault("CONTENT", []).append(f)

        category_details: list[CategoryScoreDetail] = []
        category_scores: dict[str, float] = {}
        total_raw = 0.0

        for cat, cat_findings in grouped.items():
            cap = self.CATEGORY_CAPS[cat]
            if not cat_findings:
                category_scores[cat] = 0.0
                category_details.append(
                    CategoryScoreDetail(
                        category=cat,
                        category_cap=cap,
                        raw_rule_sum=0.0,
                        diminishing_score=0.0,
                        rules_triggered_count=0,
                    )
                )
                continue

            raw_sum = sum(f.effective_score for f in cat_findings)

            # Diminishing returns formula:
            # Score_c = Cap_c * (1 - product(1 - (Effective_r / (Cap_c + 15))))
            product_factor = 1.0
            divisor = cap + 15.0
            for f in cat_findings:
                ratio = min(0.9, f.effective_score / divisor)
                product_factor *= (1.0 - ratio)

            diminishing_score = cap * (1.0 - product_factor)
            diminishing_score = min(cap, diminishing_score)
            diminishing_score = round(diminishing_score, 1)

            category_scores[cat] = diminishing_score
            total_raw += diminishing_score

            category_details.append(
                CategoryScoreDetail(
                    category=cat,
                    category_cap=cap,
                    raw_rule_sum=round(raw_sum, 1),
                    diminishing_score=diminishing_score,
                    rules_triggered_count=len(cat_findings),
                )
            )

        # Corroboration requirement:
        # A Critical score (>85) cannot be reached unless indicators exist in at least 2 distinct categories
        # or multiple high/critical severity rules are triggered.
        active_categories = [cat for cat, score in category_scores.items() if score > 0]
        critical_or_high_rules = [f for f in active_findings if f.severity in ("critical", "high")]
        is_corroborated = len(active_categories) >= 2 or len(critical_or_high_rules) >= 2

        # Clamp raw score within [0, 100]
        final_score = min(100.0, max(0.0, round(total_raw, 1)))

        # If score exceeds 85 but lacks corroboration across categories, cap at 84 (High)
        if final_score >= 85.0 and not is_corroborated:
            final_score = 84.0

        # Determine severity band
        severity_level = "low"
        for low_bound, high_bound, label in self.SEVERITY_BANDS:
            if low_bound <= final_score <= high_bound:
                severity_level = label
                break

        formula_explanation = (
            f"Final Risk Score: {final_score}/100 ({severity_level.upper()}). "
            f"Calculated across {len(active_findings)} triggered rule(s) grouped into "
            f"{len(active_categories)} active threat category/categories. "
            f"Category contributions: "
            + ", ".join(f"{cat}: {score}" for cat, score in category_scores.items() if score > 0)
            + (" (None)" if not any(category_scores.values()) else "")
            + ". Diminishing returns scaling prevents single-vector heuristic inflation."
        )

        return RiskScoreResult(
            final_score=final_score,
            severity_level=severity_level,
            category_scores=category_scores,
            category_details=category_details,
            triggered_rules=active_findings,
            formula_explanation=formula_explanation,
            is_corroborated_threat=is_corroborated,
        )

