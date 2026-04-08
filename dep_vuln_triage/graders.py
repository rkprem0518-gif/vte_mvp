import re
from packaging.version import Version, InvalidVersion
from .models import Action, Reward

def _parse_version(v: str) -> Version | None:
    try:
        return Version(v)
    except InvalidVersion:
        return None

def _version_gte(v1: str, v2: str) -> bool:
    pv1, pv2 = _parse_version(v1), _parse_version(v2)
    if pv1 and pv2:
        return pv1 >= pv2
    return False

def _version_lte(v1: str, v2: str) -> bool:
    pv1, pv2 = _parse_version(v1), _parse_version(v2)
    if pv1 and pv2:
        return pv1 <= pv2
    return False

def _get_cve_for_package(package: str, cve_db: list) -> dict | None:
    for cve in cve_db:
        if cve["package"] == package:
            return cve
    return None

def _compute_completion_bonus(state: dict, scenario: dict) -> float:
    required = set(scenario.get("vulnerable_packages", []))
    flagged = set(state.get("already_flagged", []))
    if not required:
        return 0.0
    ratio = len(required & flagged) / len(required)
    return round(ratio * 0.20, 2)

def _build_feedback(breakdown: dict, action: Action) -> str:
    if not breakdown:
        return "No correct logic applied. Review the request details."
    reasons = []
    if "correct_flag" in breakdown: reasons.append("Correctly flagged.")
    if "duplicate_flag" in breakdown: reasons.append("Already flagged.")
    if "false_positive" in breakdown: reasons.append("False positive flag.")
    if "correct_cve_cited" in breakdown: reasons.append("Correct CVE cited.")
    if "severity_mentioned" in breakdown: reasons.append("Severity correctly assessed.")
    if "valid_trace" in breakdown: reasons.append("Dependency correctly traced.")
    if "useless_trace" in breakdown: reasons.append("Trace yielded no useful info.")
    if "valid_upgrade" in breakdown: reasons.append("Valid minimal upgrade proposed.")
    if "upgrade_too_high" in breakdown: reasons.append("Upgrade valid but not minimal.")
    if "invalid_upgrade" in breakdown: reasons.append("Invalid or unsafe upgrade proposed.")
    if "correct_safe_mark" in breakdown: reasons.append("Correctly marked as safe.")
    if "incorrect_safe_mark" in breakdown: reasons.append("Incorrectly marked as safe.")
    if "completion_bonus" in breakdown: reasons.append("Bonus awarded for completion.")
    return " ".join(reasons)

def compute_step_reward(action: Action, state: dict, scenario: dict, cve_db: list) -> Reward:
    breakdown = {}
    total = 0.0

    if not isinstance(action.reason, str): action.reason = ""

    if action.action_type == "flag_vulnerable":
        vulnerable_packages = scenario.get("vulnerable_packages", [])
        if action.package in vulnerable_packages:
            if action.package not in state.get("already_flagged", []):
                breakdown["correct_flag"] = 0.35
                total += 0.35
                correct_cve = _get_cve_for_package(action.package, cve_db)
                if correct_cve:
                    if action.cve_id and action.cve_id == correct_cve["cve_id"]:
                        breakdown["correct_cve_cited"] = 0.10
                        total += 0.10
                    if correct_cve["severity"].lower() in action.reason.lower():
                        breakdown["severity_mentioned"] = 0.05
                        total += 0.05
            else:
                breakdown["duplicate_flag"] = -0.05
                total -= 0.05
        else:
            breakdown["false_positive"] = -0.15
            total -= 0.15

    elif action.action_type == "trace_dependency":
        if action.package in scenario.get("traceable_packages", []):
            breakdown["valid_trace"] = 0.20
            total += 0.20
        else:
            breakdown["useless_trace"] = -0.05
            total -= 0.05

    elif action.action_type == "propose_upgrade":
        upgrade_map = scenario.get("required_upgrades", {})
        if action.package in upgrade_map:
            required = upgrade_map[action.package]
            if action.proposed_version and _version_gte(action.proposed_version, required["min_safe"]):
                if _version_lte(action.proposed_version, required["max_allowed"]):
                    breakdown["valid_upgrade"] = 0.30
                    total += 0.30
                else:
                    breakdown["upgrade_too_high"] = 0.10 
                    total += 0.10
            else:
                breakdown["invalid_upgrade"] = -0.10
                total -= 0.10
        else:
            breakdown["invalid_upgrade"] = -0.10
            total -= 0.10

    elif action.action_type == "mark_safe":
        safe_packages = scenario.get("safe_packages", [])
        if action.package in safe_packages:
            breakdown["correct_safe_mark"] = 0.05
            total += 0.05
        else:
            breakdown["incorrect_safe_mark"] = -0.10
            total -= 0.10

    elif action.action_type == "submit":
        completion_bonus = _compute_completion_bonus(state, scenario)
        breakdown["completion_bonus"] = completion_bonus
        total += completion_bonus

    value = max(0.01, min(0.99, total))
    feedback = _build_feedback(breakdown, action)
    return Reward(value=value, breakdown=breakdown, feedback=feedback)
