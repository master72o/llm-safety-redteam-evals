"""
Experiment Runner executing Red-Teaming Attacks across Defense Configurations.
"""

from typing import List, Dict
from safety_evals.schema import (
    RedTeamAttackCase,
    DefenseVariant,
    AttackEvaluationResult,
)
from safety_evals.evaluator import SafetyEvaluator


class ExperimentRunner:
    """Executes red-teaming evaluations across defense configurations."""

    @staticmethod
    def evaluate_attack_case(attack_case: RedTeamAttackCase) -> Dict[DefenseVariant, AttackEvaluationResult]:
        evaluations = {}

        # 1. Defense v0 (Raw Model - No Guardrails)
        eval_v0 = SafetyEvaluator.evaluate_attack(
            attack_case, DefenseVariant.DEF_V0_RAW, attack_case.outputs_v0
        )
        evaluations[DefenseVariant.DEF_V0_RAW] = eval_v0

        # 2. Defense v1 (Prompt Guardrails)
        eval_v1 = SafetyEvaluator.evaluate_attack(
            attack_case, DefenseVariant.DEF_V1_PROMPT_GUARD, attack_case.outputs_v1
        )
        evaluations[DefenseVariant.DEF_V1_PROMPT_GUARD] = eval_v1

        # 3. Defense v2 (Dual Filter + PII Anonymizer)
        eval_v2 = SafetyEvaluator.evaluate_attack(
            attack_case, DefenseVariant.DEF_V2_DUAL_FILTER, attack_case.outputs_v2
        )
        evaluations[DefenseVariant.DEF_V2_DUAL_FILTER] = eval_v2

        return evaluations
