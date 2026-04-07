import json, os, logging, time
import traceback
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, Response
from pydantic import ValidationError
from typing import Any

from .models import Observation, Action, Reward, CVERecord
from .graders import compute_step_reward
from .rate_limiter import rate_limit_check

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

def load_data():
    base_dir = os.path.dirname(__file__)
    cve_path = os.path.join(base_dir, "data", "cve_db.json")
    scenarios_path = os.path.join(base_dir, "data", "scenarios.json")
    try:
        with open(cve_path, 'r') as f:
            cve_data = json.load(f)
            # Validate CVERecords
            cve_db = [CVERecord(**c).model_dump() for c in cve_data]
        with open(scenarios_path, 'r') as f:
            scenarios = json.load(f)
        return cve_db, scenarios
    except Exception as e:
        logger.error(f"Failed to load data: {e}")
        raise RuntimeError(f"Missing or invalid data: {e}")

CVE_DB, SCENARIOS = [], {}
try:
    CVE_DB, SCENARIOS = load_data()
except Exception as e:
    pass

class DepVulnTriageEnv:
    def __init__(self, task_name: str):
        if task_name not in SCENARIOS:
            raise ValueError(f"Task {task_name} not found")
        self.task_name = task_name
        self.scenario = SCENARIOS[task_name]
        self.state_data = {
            "task_name": self.task_name,
            "current_step": 0,
            "max_steps": self.scenario["max_steps"],
            "flagged_packages": [],
            "traced_packages": [],
            "proposed_upgrades": [],
            "cumulative_score": 0.0,
            "episode_done": False,
            "already_flagged": []
        }
        self.last_action_result = None

    def reset(self) -> Observation:
        self.state_data["current_step"] = 0
        self.state_data["episode_done"] = False
        self.state_data["flagged_packages"] = []
        self.state_data["traced_packages"] = []
        self.state_data["proposed_upgrades"] = []
        self.state_data["cumulative_score"] = 0.0
        self.state_data["already_flagged"] = []
        self.last_action_result = None
        return self._build_obs()

    def step(self, action: Action) -> tuple[Observation, Reward, bool, dict]:
        if action.package: action.package = action.package.lower().strip()[:100]
        if action.reason: action.reason = action.reason.strip()[:500]

        if not action.action_type in ["flag_vulnerable", "trace_dependency", "propose_upgrade", "mark_safe", "submit"]:
            return self._build_obs(), Reward(value=0.0, breakdown={}, feedback="Unknown action type"), False, {}
        
        if action.action_type == "propose_upgrade":
            if not action.proposed_version or not __import__("re").match(r'^\d+\.\d+(\.\d+)?([ab]\d+)?$', action.proposed_version):
                return self._build_obs(), Reward(value=0.0, breakdown={}, feedback="Invalid proposed_version format"), False, {}

        self.state_data["current_step"] += 1
        
        reward = self._grade_action(action)
        self.state_data["cumulative_score"] += reward.value
        self.last_action_result = reward.feedback

        if action.action_type == "flag_vulnerable" and action.package not in self.state_data["already_flagged"]:
            self.state_data["already_flagged"].append(action.package)
            self.state_data["flagged_packages"].append(action.package)
        elif action.action_type == "trace_dependency" and action.package not in self.state_data["traced_packages"]:
            self.state_data["traced_packages"].append(action.package)
        elif action.action_type == "propose_upgrade" and action.package not in self.state_data["proposed_upgrades"]:
            self.state_data["proposed_upgrades"].append(action.package)

        done = False
        if action.action_type == "submit" or self.state_data["current_step"] >= self.state_data["max_steps"]:
            done = True
            self.state_data["episode_done"] = True

        info_dict = {
            "step": self.state_data["current_step"],
            "cumulative_score": self.state_data["cumulative_score"],
            "flags_correct": len([p for p in self.state_data["already_flagged"] if p in self.scenario.get("vulnerable_packages", [])]),
            "false_positives": len([p for p in self.state_data["already_flagged"] if p not in self.scenario.get("vulnerable_packages", [])]),
        }

        return self._build_obs(), reward, done, info_dict

    def state(self) -> dict:
        return self.state_data.copy()

    def close(self):
        self.state_data["episode_done"] = True
        logger.info(f"Env closed for task {self.task_name}. Score: {self.state_data['cumulative_score']}")

    def _grade_action(self, action: Action) -> Reward:
        return compute_step_reward(action, self.state_data, self.scenario, CVE_DB)

    def _build_obs(self) -> Observation:
        obs_dict = {
            "task_id": self.scenario["task_id"],
            "task_name": self.scenario["description"],
            "manifest": self.scenario["manifest"],
            "dependency_graph": self.scenario["dependency_graph"],
            "cve_database": CVE_DB,
            "current_step": self.state_data["current_step"],
            "max_steps": self.state_data["max_steps"],
            "episode_done": self.state_data["episode_done"],
            "last_action_result": self.last_action_result
        }
        return Observation(**obs_dict)

app = FastAPI(title="dep-vuln-triage", version="1.0.0")

def _read_dashboard() -> str:
    base_dir = os.path.dirname(__file__)
    html_path = os.path.join(base_dir, "data", "index.html")
    try:
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"<html><body><h1>Dashboard Missing</h1><pre>{str(e)}</pre></body></html>"

@app.get("/", response_class=HTMLResponse)
@app.get("/ui", response_class=HTMLResponse)
async def dashboard():
    return _read_dashboard()

@app.exception_handler(404)
async def not_found_handler(request: Request, exc: Exception):
    # Only serve UI for browser requests (non-API paths)
    path = request.url.path
    api_paths = ["/reset", "/step", "/state", "/health", "/metadata", "/schema", "/mcp", "/openapi.json", "/docs", "/tasks", "/session"]
    if not any(path.startswith(p) for p in api_paths):
        return HTMLResponse(content=_read_dashboard(), status_code=200)
    return Response(content='{"detail":"Not Found"}', status_code=404, media_type="application/json")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SESSIONS = {}
SESSION_TIMEOUT = 30 * 60
MAX_SESSIONS = 50

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    logger.info(f"{request.method} {request.url.path} | status: {response.status_code} | latency: {process_time:.3f}s")
    return response

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global Error: {exc}\n{traceback.format_exc()}")
    return {"detail": str(exc)}, 500

def cleanup_sessions():
    now = time.time()
    expired = [k for k, v in SESSIONS.items() if now - v["last_accessed"] > SESSION_TIMEOUT]
    for k in expired:
        try:
            SESSIONS[k]["env"].close()
        except:
            pass
        del SESSIONS[k]

@app.post("/reset")
async def reset(request: Request, session_id: str = "default"):
    cleanup_sessions()
    
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    
    task_name = body.get("task_name", "single_flag")
    if len(SESSIONS) >= MAX_SESSIONS and session_id not in SESSIONS:
        raise HTTPException(503, "Max sessions reached")

    try:
        env = DepVulnTriageEnv(task_name)
    except ValueError as e:
        raise HTTPException(400, str(e))

    obs = env.reset()
    SESSIONS[session_id] = {"env": env, "last_accessed": time.time()}
    logger.info(f"{session_id} | Env reset task={task_name}")
    return obs.model_dump()

@app.post("/step", dependencies=[Depends(rate_limit_check)])
async def step(request: Request, session_id: str = "default"):
    cleanup_sessions()
    if session_id not in SESSIONS:
        raise HTTPException(400, "Session not found or expired")
    
    SESSIONS[session_id]["last_accessed"] = time.time()
    env = SESSIONS[session_id]["env"]
    
    try:
        body = await request.json()
    except Exception as e:
        raise HTTPException(400, "Invalid JSON body")
        
    action_data = body.get("action", body)
    try:
        action = Action(**action_data)
    except ValidationError as e:
        return {
            "observation": env._build_obs().model_dump(), 
            "reward": {"value": 0.0, "breakdown": {}, "feedback": f"Missing field: {e.errors()}"},
            "done": env.state_data["episode_done"],
            "info": {}
        }
        
    try:
        obs, reward, done, info = env.step(action)
    except Exception as e:
        logger.error(f"Step Error: {e}\n{traceback.format_exc()}")
        return {"error": str(e)}

    return {
        "observation": obs.model_dump(),
        "reward": reward.model_dump(),
        "done": done,
        "info": info
    }

@app.get("/state")
async def get_state(session_id: str = "default"):
    if session_id not in SESSIONS:
        raise HTTPException(400, "Session not found or expired")
    SESSIONS[session_id]["last_accessed"] = time.time()
    return SESSIONS[session_id]["env"].state()

@app.delete("/session/{session_id}")
async def delete_session(session_id: str):
    if session_id in SESSIONS:
        try:
            SESSIONS[session_id]["env"].close()
        except:
            pass
        del SESSIONS[session_id]
        return {"status": "deleted"}
    return {"status": "not_found"}

@app.get("/health")
async def health():
    if not CVE_DB or not SCENARIOS:
        raise HTTPException(500, "Data files missing or invalid.")
    return {"status": "healthy", "version": "1.0.0"}

@app.get("/metadata")
async def get_metadata():
    return {
        "name": "dep-vuln-triage",
        "description": "Real-world dependency vulnerability triage environment for DevSecOps agents."
    }

@app.get("/schema")
async def get_schema():
    return {
        "action": Action.model_json_schema(),
        "observation": Observation.model_json_schema(),
        "state": Observation.model_json_schema()
    }

@app.post("/mcp")
async def mcp_endpoint(request: Request):
    try:
        body = await request.json()
    except:
        body = {}
    return {
        "jsonrpc": "2.0",
        "id": body.get("id", 1),
        "result": "MCP endpoint active"
    }

@app.get("/tasks")
async def tasks():
    return [{"name": k, "description": v["description"]} for k,v in SCENARIOS.items()]
