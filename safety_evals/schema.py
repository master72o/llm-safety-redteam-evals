"""
Data Schemas for LLM Safety Red-Team Evals Framework.
"""

from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List


class AttackCategory(str, Enum):
    PROMPT_INJECTION = "Prompt_Injection"
    JAILBREAK_DAN = "Jailbreak_DAN"
    PII_LEAKAGE = "PII_Leakage"
    HARMFUL_CONTENT = "Harmful_Content"
    SYSTEM_PROMPT_EXTRACTION = "System_Prompt_Extraction"


class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    SAFE = "Safe"


class DefenseVariant(str, Enum):
    DEF_V0_RAW = "Def_v0_Raw"
    DEF_V1_PROMPT_GUARD = "Def_v1_PromptGuard"
    DEF_V2_DUAL_FILTER = "Def_v2_DualFilter"


@dataclass
class RedTeamAttackCase:
    __test__ = False

    attack_id: str
    category: AttackCategory
    attack_prompt: str
    target_pii: Optional[str] = None
    system_prompt_target: Optional[str] = None
    outputs_v0: str = ""
    outputs_v1: str = ""
    outputs_v2: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RedTeamAttackCase":
        cat_raw = data.get("category", "Prompt_Injection")
        try:
            cat = AttackCategory(cat_raw)
        except ValueError:
            cat = AttackCategory.PROMPT_INJECTION

        return cls(
            attack_id=data["attack_id"],
            category=cat,
            attack_prompt=data["attack_prompt"],
            target_pii=data.get("target_pii"),
            system_prompt_target=data.get("system_prompt_target"),
            outputs_v0=data.get("outputs_v0", ""),
            outputs_v1=data.get("outputs_v1", ""),
            outputs_v2=data.get("outputs_v2", ""),
        )


@dataclass
class AttackEvaluationResult:
    attack_id: str
    category: AttackCategory
    defense_variant: DefenseVariant
    output: str
    refusal_detected: bool
    pii_leaked: bool
    system_prompt_leaked: bool
    harmful_content_detected: bool
    vulnerability_detected: bool
    severity: SeverityLevel
    defense_success: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "category": self.category.value if isinstance(self.category, AttackCategory) else str(self.category),
            "defense_variant": self.defense_variant.value if isinstance(self.defense_variant, DefenseVariant) else str(self.defense_variant),
            "refusal_detected": bool(self.refusal_detected),
            "pii_leaked": bool(self.pii_leaked),
            "system_prompt_leaked": bool(self.system_prompt_leaked),
            "harmful_content_detected": bool(self.harmful_content_detected),
            "vulnerability_detected": bool(self.vulnerability_detected),
            "severity": self.severity.value if isinstance(self.severity, SeverityLevel) else str(self.severity),
            "defense_success": bool(self.defense_success),
            "output": self.output,
        }


class SafetyDataset:
    """Loader and container for red-teaming attack dataset."""

    def __init__(self, cases: List[RedTeamAttackCase]):
        self.cases = cases

    @classmethod
    def from_jsonl(cls, file_path: str) -> "SafetyDataset":
        import json
        cases = []
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    cases.append(RedTeamAttackCase.from_dict(json.loads(line)))
        return cls(cases=cases)
