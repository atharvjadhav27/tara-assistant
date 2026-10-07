"""Deterministic risk determination (ISO/SAE 21434 style).

Impact (S/F/O/P categories) -> overall impact rating (max of categories).
Attack feasibility: attack-potential approach (elapsed time, expertise, knowledge, window, equipment).
Risk value: matrix lookup (impact x feasibility) -> 1..5. The LLM may only *propose* the inputs;
the risk value is always computed here.
"""
IMPACT_LEVELS = ["Negligible", "Moderate", "Major", "Severe"]
IMPACT_CATEGORIES = ["safety", "financial", "operational", "privacy"]
FEASIBILITY_LEVELS = ["Very low", "Low", "Medium", "High"]

FACTORS = {
    "time": {"<=1 day": 0, "<=1 week": 1, "<=1 month": 4, "<=6 months": 17, ">6 months": 19},
    "expertise": {"Layman": 0, "Proficient": 3, "Expert": 6, "Multiple experts": 8},
    "knowledge": {"Public": 0, "Restricted": 3, "Confidential": 7, "Strictly confidential": 11},
    "window": {"Unlimited": 0, "Easy": 1, "Moderate": 4, "Difficult": 10},
    "equipment": {"Standard": 0, "Specialized": 4, "Bespoke": 7, "Multiple bespoke": 9},
}

# rows: impact; columns: feasibility Very low, Low, Medium, High
RISK_MATRIX = {
    "Negligible": [1, 1, 1, 1],
    "Moderate": [1, 2, 2, 3],
    "Major": [1, 2, 3, 4],
    "Severe": [2, 3, 4, 5],
}
RISK_LABELS = {1: "Very low", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}


class RiskInputError(ValueError):
    pass


def overall_impact(impact: dict) -> str:
    levels = []
    for cat in IMPACT_CATEGORIES:
        v = impact.get(cat)
        if v not in IMPACT_LEVELS:
            raise RiskInputError(f"Invalid impact rating for {cat}: {v!r}")
        levels.append(IMPACT_LEVELS.index(v))
    return IMPACT_LEVELS[max(levels)]


def attack_potential(factors: dict) -> int:
    total = 0
    for name, table in FACTORS.items():
        v = factors.get(name)
        if v not in table:
            raise RiskInputError(f"Invalid attack-potential factor {name}: {v!r}")
        total += table[v]
    return total


def feasibility_rating(potential: int) -> str:
    if potential <= 13:
        return "High"
    if potential <= 19:
        return "Medium"
    if potential <= 24:
        return "Low"
    return "Very low"


def risk_value(impact_rating: str, feasibility: str) -> int:
    return RISK_MATRIX[impact_rating][FEASIBILITY_LEVELS.index(feasibility)]


def compute(impact: dict, factors: dict) -> dict:
    imp = overall_impact(impact)
    pot = attack_potential(factors)
    feas = feasibility_rating(pot)
    val = risk_value(imp, feas)
    return {"overall_impact": imp, "attack_potential": pot, "feasibility": feas,
            "risk_value": val, "risk_label": RISK_LABELS[val]}
