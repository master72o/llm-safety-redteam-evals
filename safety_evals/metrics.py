"""
Metrics Calculator for Safety Red-Team Evals.
"""

from typing import List, Dict, Any
from safety_evals.schema import (
    AttackEvaluationResult,
    DefenseVariant,
    AttackCategory,
    SeverityLevel,
)


class SafetyMetricsCalculator:
    """Aggregates defense efficacy metrics and vulnerability distributions."""

    @staticmethod
    def calculate_defense_metrics(evaluations: List[AttackEvaluationResult]) -> Dict[str, Any]:
        if not evaluations:
            return {"total_attacks": 0, "defense_success_rate": 0.0}

        total = len(evaluations)
        def_successes = sum(1 for e in evaluations if e.defense_success)
        vuln_count = sum(1 for e in evaluations if e.vulnerability_detected)
        crit_count = sum(1 for e in evaluations if e.severity == SeverityLevel.CRITICAL)

        def_success_rate = def_successes / total
        attack_success_rate = 1.0 - def_success_rate
        vuln_rate = vuln_count / total

        # Category Breakdown
        cat_metrics = {}
        for cat in AttackCategory:
            cat_evals = [e for e in evaluations if e.category == cat]
            if cat_evals:
                cat_total = len(cat_evals)
                cat_vuln = sum(1 for e in cat_evals if e.vulnerability_detected)
                cat_asr = cat_vuln / cat_total
                cat_metrics[cat.value] = {
                    "total": cat_total,
                    "vulnerabilities": cat_vuln,
                    "attack_success_rate": round(cat_asr, 4),
                    "defense_success_rate": round(1.0 - cat_asr, 4),
                }

        # Severity Breakdown
        sev_counts = {s.value: 0 for s in SeverityLevel}
        for e in evaluations:
            s_val = e.severity.value if isinstance(e.severity, SeverityLevel) else str(e.severity)
            sev_counts[s_val] = sev_counts.get(s_val, 0) + 1

        return {
            "total_attacks": total,
            "defense_successes": def_successes,
            "defense_success_rate": round(def_success_rate, 4),
            "attack_success_rate": round(attack_success_rate, 4),
            "vulnerability_rate": round(vuln_rate, 4),
            "critical_breaches": crit_count,
            "category_metrics": cat_metrics,
            "severity_distribution": sev_counts,
        }

    @classmethod
    def calculate_suite_metrics(
        cls, all_evaluations: Dict[DefenseVariant, List[AttackEvaluationResult]]
    ) -> Dict[str, Any]:
        suite_metrics = {}
        for def_variant, evals in all_evaluations.items():
            key = def_variant.value if isinstance(def_variant, DefenseVariant) else str(def_variant)
            suite_metrics[key] = cls.calculate_defense_metrics(evals)
        return suite_metrics


MetricsCalculator = SafetyMetricsCalculator
