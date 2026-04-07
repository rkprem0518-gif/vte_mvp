from pydantic import BaseModel, ConfigDict
from typing import Literal

class CVERecord(BaseModel):
    model_config = ConfigDict(extra='forbid')
    cve_id: str
    package: str
    affected_versions: list[str]
    fixed_version: str
    latest_stable: str
    severity: Literal["low", "medium", "high", "critical"]
    cvss_score: float
    description: str

class Observation(BaseModel):
    model_config = ConfigDict(extra='forbid')
    task_id: str
    task_name: str
    manifest: dict[str, str]
    dependency_graph: dict[str, list[str]]
    cve_database: list[CVERecord]
    current_step: int
    max_steps: int
    episode_done: bool
    last_action_result: str | None = None
    flagged_packages: list[str] = []
    proposed_upgrades: list[str] = []

class Action(BaseModel):
    model_config = ConfigDict(extra='ignore')
    action_type: Literal[
        "flag_vulnerable",
        "trace_dependency",
        "propose_upgrade",
        "mark_safe",
        "submit"
    ]
    package: str | None = ""
    reason: str | None = ""
    proposed_version: str | None = None
    cve_id: str | None = None

class Reward(BaseModel):
    model_config = ConfigDict(extra='forbid')
    value: float
    breakdown: dict[str, float]
    feedback: str

class EpisodeResult(BaseModel):
    model_config = ConfigDict(extra='forbid')
    task_id: str
    final_score: float
    steps_taken: int
    actions_taken: list[dict]
    reward_history: list[float]
    success: bool
