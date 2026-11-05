"""Modelos de dados e sistema de classificação de risco baseado em evidências."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class RiskLevel(IntEnum):
    SEGURO = 0
    BAIXO = 1
    MEDIO = 2
    ALTO = 3
    CRITICO = 4

    @property
    def label(self) -> str:
        return {0: "SEGURO", 1: "BAIXO", 2: "MÉDIO", 3: "ALTO", 4: "CRÍTICO"}[int(self)]


SCORE_THRESHOLDS = ((80, RiskLevel.CRITICO), (50, RiskLevel.ALTO),
                    (25, RiskLevel.MEDIO), (10, RiskLevel.BAIXO))
STRONG_EVIDENCE_WEIGHT = 60  # evidência isolada que já sustenta ALTO/CRÍTICO


@dataclass
class Evidence:
    code: str
    description: str
    weight: int
    category: str | None = None


@dataclass
class Finding:
    path: str
    size: int = 0
    sha256: str = ""
    signature: str = ""
    category: str = "Indefinido"
    evidences: list[Evidence] = field(default_factory=list)
    score: int = 0
    risk: RiskLevel = RiskLevel.SEGURO
    extra: dict = field(default_factory=dict)

    def add(self, code: str, description: str, weight: int, category: str | None = None) -> None:
        if not any(e.code == code for e in self.evidences):
            self.evidences.append(Evidence(code, description, weight, category))

    def finalize(self) -> "Finding":
        positive = [e for e in self.evidences if e.weight > 0]
        self.score = max(0, sum(e.weight for e in self.evidences))
        risk = RiskLevel.SEGURO
        for limit, level in SCORE_THRESHOLDS:
            if self.score >= limit:
                risk = level
                break
        strong = any(e.weight >= STRONG_EVIDENCE_WEIGHT for e in positive)
        # Classificação alta exige evidência forte ou indicadores independentes.
        if risk == RiskLevel.CRITICO and not strong:
            risk = RiskLevel.ALTO
        if risk >= RiskLevel.ALTO and not strong and len(positive) < 2:
            risk = RiskLevel.MEDIO
        self.risk = risk
        with_cat = [e for e in positive if e.category]
        if with_cat:
            self.category = max(with_cat, key=lambda e: e.weight).category  # type: ignore[assignment]
        return self

    @property
    def justification(self) -> str:
        if not self.evidences:
            return "Nenhum indicador relevante encontrado."
        return "; ".join(e.description for e in sorted(self.evidences, key=lambda e: -e.weight))

    def to_dict(self) -> dict:
        return {
            "path": self.path, "size": self.size, "sha256": self.sha256,
            "signature": self.signature, "category": self.category,
            "score": self.score, "risk": self.risk.label,
            "justification": self.justification,
            "evidences": [e.__dict__ for e in self.evidences],
        }


def merge_evidences(dst: "Finding", src: "Finding") -> None:
    """Incorpora as evidências de `src` em `dst` (sem duplicar códigos)."""
    for e in src.evidences:
        dst.add(e.code, e.description, e.weight, e.category)
    for attr in ("sha256", "signature", "size"):
        if getattr(src, attr) and not getattr(dst, attr):
            setattr(dst, attr, getattr(src, attr))
