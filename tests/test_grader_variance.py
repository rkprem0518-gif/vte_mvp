def test_graders_produce_variance():
    from dep_vuln_triage.graders import compute_step_reward
    from dep_vuln_triage.models import Action
    
    scenario = {
        "task_id": "single_flag",
        "vulnerable_packages": ["requests"],
        "safe_packages": ["flask"],
        "required_upgrades": {
            "requests": {"min_safe": "2.31.0", "max_allowed": "2.32.3"}
        }
    }
    
    cve_db = [
        {
            "cve_id": "CVE-2023-32681",
            "package": "requests",
            "affected_versions": ["<2.31.0"],
            "fixed_version": "2.31.0",
            "latest_stable": "2.31.0",
            "severity": "medium",
            "cvss_score": 6.1,
            "description": "Leaking Proxy-Authorization header in Python requests."
        }
    ]
    
    state_empty = {"already_flagged": []}
    state_flagged = {"already_flagged": ["requests"]}
    
    action_correct = Action(action_type="flag_vulnerable", package="requests", reason="Has CVE-2023-32681", cve_id="CVE-2023-32681")
    action_wrong = Action(action_type="flag_vulnerable", package="flask", reason="Just guessing")
    action_duplicate = Action(action_type="flag_vulnerable", package="requests", reason="Dupe")
    
    reward_correct = compute_step_reward(action_correct, state_empty, scenario, cve_db)
    reward_wrong = compute_step_reward(action_wrong, state_empty, scenario, cve_db)
    reward_duplicate = compute_step_reward(action_duplicate, state_flagged, scenario, cve_db)
    
    scores = {reward_correct.value, reward_wrong.value, reward_duplicate.value}
    
    assert len(scores) >= 2, f"Grader must return different scores for different inputs, got {scores}"
    assert all(0.0 <= s <= 1.0 for s in scores), f"All scores must be in [0.0, 1.0], got {scores}"
    print("Variance test passed successfully.")
