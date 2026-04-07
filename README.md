---
title: dep-vuln-triage
colorFrom: blue
colorTo: green
sdk: docker
pinned: false
tags:
  - openenv
---

# dep-vuln-triage

This is a real-world dependency vulnerability triage environment simulating a DevSecOps workflow. An AI agent is tasked with taking a software project's dependency manifest and a CVE database, identifying vulnerable packages, tracing transitive risks, and proposing minimal safe upgrade plans. This directly mimics tools like Dependabot, Snyk, and npm audit. Ideal for the Meta x Hugging Face OpenEnv Hackathon.

## Observation Space

| Field | Type | Description |
|---|---|---|
| task_id | str | Current task name |
| task_name | str | Current task description |
| manifest | dict[str,str] | Package name -> pinned version |
| dependency_graph | dict[str,list[str]] | Direct -> transitive dependencies |
| cve_database | list[CVERecord] | Full CVE database (40 entries) |
| current_step | int | Steps taken so far |
| max_steps | int | Episode step limit |
| episode_done | bool | True if the episode has finished |
| last_action_result | str | Grader feedback from the previous step |

## Action Space

| action_type | Required Fields | Description |
|---|---|---|
| flag_vulnerable | package, reason | Mark package as vulnerable |
| trace_dependency | package, reason | Reveal its transitive dependencies |
| propose_upgrade | package, reason, proposed_version | Suggest a safe semantic version |
| mark_safe | package, reason | Mark as not vulnerable |
| submit | package, reason | End episode, trigger scoring |

## Tasks

### Task 1: single_flag (Difficulty: Easy)
Identify the single directly vulnerable package in the manifest. Expected difficulty is easy. A perfect agent will flag the directly vulnerable requirement with the exact CVE matching it, citing the vulnerability in its reasoning.
Baseline score: TBD

### Task 2: transitive_trace (Difficulty: Medium)
No direct CVEs exist in the root manifest. Find vulnerable transitive dependencies by tracing the graph using the `trace_dependency` action, and effectively flag them. Expected difficulty is medium. A perfect agent traces to dependencies not in the top-level manifest and flags them accurately.
Baseline score: TBD

### Task 3: minimal_upgrade (Difficulty: Hard)
Three packages are vulnerable. Propose minimal safe upgrades using `propose_upgrade` for all three such that they pass security compliance while maintaining compatibility constraints. A perfect agent proposes exact minimum safe versions.
Baseline score: TBD

## Reward Function

The reward at each step comprises partial credit elements for accurate DevSecOps deductions:
* correct_flag: +0.35
* cve_cited: +0.10
* severity_mentioned: +0.05
* false_positive: -0.15
* valid_upgrade: +0.30
* completion_bonus: Up to +0.20 when submitted based on overall completeness.

Every step returns a dense reward signal based on accurate triaging behavior.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/rkprem0518-gif/vte_mvp.git
cd vte_mvp/dep-vuln-triage

# Build and run the Docker container locally
docker build -t dep-vuln-triage .
docker run -p 7860:7860 dep-vuln-triage

# Validate the OpenEnv configuration
openenv validate

# Run inference
export OPENAI_API_KEY="your_groq_api_key_here"
export API_BASE_URL="https://api.groq.com/openai/v1"
export MODEL_NAME="llama3-70b-8192"
python inference.py
```

## Baseline Scores

| Task | Model | Score | Steps |
|---|---|---|---|
| single_flag | llama3-70b-8192 | TBD | TBD |
| transitive_trace | llama3-70b-8192 | TBD | TBD |
| minimal_upgrade | llama3-70b-8192 | TBD | TBD |

## License and Author
MIT License.
Author: Prem Tawar
