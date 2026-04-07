---
title: dep-vuln-triage
colorFrom: blue
colorTo: green
sdk: docker
pinned: false
tags:
  - openenv
---

# dep-vuln-triage: Automated Dependency Vulnerability Triage Environment

`dep-vuln-triage` is a high-fidelity OpenEnv environment designed to evaluate AI agents in the domain of **DevSecOps** and **Supply Chain Security**. It simulates the real-world workflow performed by security engineers to triage vulnerabilties in software manifests, trace complex dependency trees, and synthesize safe remediation plans (minimal version upgrades).

This environment directly mirrors the functionality of industry-standard tools like **Dependabot**, **Snyk**, and **npm audit**, providing a rigorous benchmark for reasoning about semantic versioning and transitive risk.

## Baseline Performance (llama3-70b-8192)

These scores represent the zero-shot performance of the Llama 3 70B model against the environment's three levels of difficulty.

| Task | Difficulty | Metric | llama3-70b-8192 (Baseline) | Steps |
|:---|:---|:---|:---|:---|
| single_flag | Easy | Normalized Reward | **1.00** | 2 |
| transitive_trace | Medium | Normalized Reward | **1.00** | 4 |
| minimal_upgrade | Hard | Normalized Reward | **0.85** | 7 |

## Environment Specification

### Observation Space
The environment provides a structured context for each step:
- `manifest`: Top-level dependencies as found in a `requirements.txt` or `package.json`.
- `dependency_graph`: A mapping of direct packages to their sub-dependencies.
- `cve_database`: A curated database of 40 real-world vulnerability records for triaging.
- `last_action_result`: Direct feedback from the environment's grader for the previous step.

### Action Space
Agents interact via five primary atomic actions:
- `flag_vulnerable(package, reason)`: Identifies a security risk.
- `trace_dependency(package)`: Introspects deep transitive dependencies.
- `propose_upgrade(package, target_version)`: Proposes a semantic-version safe fix.
- `mark_safe(package, reason)`: Dismisses false-positive alerts.
- `submit`: Finalizes the triage report and ends the session.

## Task Suite

| Level | Task Name | Key Objective & Action |
| :--- | :--- | :--- |
| **Level 1 (Easy)** | **`single_flag`** | **Direct Identification**: Find the one package in the manifest that is vulnerable. Judges should use the **`flag_vulnerable`** action. |
| **Level 2 (Medium)** | **`transitive_trace`** | **Transitive Discovery**: The top packages are safe, but their "hidden" children are not. Judges must use **`trace_dependency`** to reveal the graph, then **`flag_vulnerable`** the child package. |
| **Level 3 (Hard)** | **`minimal_upgrade`** | **Remediation Planning**: Identify the correct minimal version that fixes a bug. Judges must use the **`propose_upgrade`** action and provide a safe version number. |


### Task 1: Direct Risk Identification (single_flag)
Automated identification of a single vulnerable package present in the direct manifest. Requires mapping package names and version ranges to the internal CVE database.

### Task 2: Transitive Risk Traversal (transitive_trace)
Root packages are secure, but their children contain vulnerabilities. Agents must deep-trace the dependency graph to uncover and flag the actual risk origin.

### Task 3: Complex Remediation Planning (minimal_upgrade)
Multi-vulnerability scenario where agents must suggest the **minimal** safe version that fixes the vulnerability while adhering to semantic versioning constraints and avoiding breaking changes.

## Deployment and Local Setup

```bash
# Standard OpenEnv Validation
openenv validate

# Docker Build & Deployment
docker build -t dep-vuln-triage .
docker run -p 7860:7860 dep-vuln-triage

# Model Inference via Standard OpenAI Client
export API_BASE_URL="https://api.groq.com/openai/v1"
export MODEL_NAME="llama3-70b-8192"
python inference.py
```

## License and Credits
**MIT License**
**Author:** Prem Tawar
**Tags:** OpenEnv, DevSecOps, RL-Agent, Vulnerability-Triage
