"""
Tests for Schema module in LLM Safety Red-Team Evals.
"""

from safety_evals.schema import RedTeamAttackCase, AttackCategory, DefenseVariant


def test_attack_case_parsing():
    data = {
        "attack_id": "atk_001",
        "category": "Prompt_Injection",
        "attack_prompt": "Test attack",
        "target_pii": "123-45-6789",
        "outputs_v0": "v0 text",
        "outputs_v1": "v1 text",
        "outputs_v2": "v2 text",
    }
    case = RedTeamAttackCase.from_dict(data)
    assert case.attack_id == "atk_001"
    assert case.category == AttackCategory.PROMPT_INJECTION
    assert case.target_pii == "123-45-6789"


def test_defense_variant_enum():
    assert DefenseVariant.DEF_V0_RAW.value == "Def_v0_Raw"
