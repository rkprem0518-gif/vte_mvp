"""
Inference script for dep-vuln-triage OpenEnv environment.
Runs all 3 tasks sequentially against an LLM via OpenAI-compatible client (Groq optimized).
"""

import asyncio, json, os, sys, time, urllib.request
from openai import OpenAI

API_BASE_URL = os.getenv("API_BASE_URL", "https://api.groq.com/openai/v1")
MODEL_NAME   = os.getenv("MODEL_NAME", "llama3-70b-8192")
API_KEY      = os.getenv("OPENAI_API_KEY") or os.getenv("HF_TOKEN") or "dummy"
ENV_BASE_URL = os.getenv("ENV_BASE_URL", "http://localhost:7860")

MAX_STEPS      = 12
TEMPERATURE    = 0.1
BENCHMARK      = "dep-vuln-triage"
TASKS          = ["single_flag", "transitive_trace", "minimal_upgrade"]
GLOBAL_TIMEOUT = 1080 # 18 mins

client = OpenAI(api_key=API_KEY, base_url=API_BASE_URL)

SYSTEM_PROMPT = """You are a DevSecOps engineer triaging dependency vulnerabilities.
You will receive a JSON observation containing a software manifest and a CVE database.
Your job: identify vulnerable packages and propose fixes.

Respond ONLY with a valid JSON object — no markdown, no explanation, no backticks.
Schema:
{
  "action_type": "flag_vulnerable" | "trace_dependency" | "propose_upgrade" | "mark_safe" | "submit",
  "package": "<package name, lowercase>",
  "reason": "<your reasoning, mention CVE ID and severity if known>",
  "proposed_version": "<semver string, only for propose_upgrade, else null>",
  "cve_id": "<CVE-YYYY-NNNNN, only if you know it, else null>"
}

Rules:
- Use flag_vulnerable when you identify a directly vulnerable package.
- Use trace_dependency to reveal transitive dependencies of a package.
- Use propose_upgrade to suggest a safe version (must be >= fixed_version).
- Use mark_safe if a package is definitely not vulnerable.
- Use submit when you are done or have no more useful actions.
- Never repeat the same action on the same package twice.
"""

def env_request(path: str, method: str = "POST", payload: dict = None) -> dict:
    req_kwargs = {
        "url": f"{ENV_BASE_URL}{path}",
        "method": method,
        "headers": {"Content-Type": "application/json"}
    }
    if payload is not None:
        req_kwargs["data"] = json.dumps(payload).encode()
    
    req = urllib.request.Request(**req_kwargs)
    with urllib.request.urlopen(req, timeout=30) as r:
        if r.status != 204:
            return json.loads(r.read())
        return {}

def run_task(task_name: str, start_time: float) -> dict:
    obs_data = env_request("/reset", "POST", {"task_name": task_name, "session_id": task_name})
    print(f"[START] task={task_name} env={BENCHMARK} model={MODEL_NAME}", flush=True)

    rewards      = []
    steps_taken  = 0
    done         = False
    final_score  = 0.0
    success      = False
    error_str    = "null"

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    try:
        for step in range(1, MAX_STEPS + 1):
            if done:
                break
            
            if time.time() - start_time > GLOBAL_TIMEOUT:
                print("Global timeout reached. Terminating early.", flush=True)
                break

            obs_text = json.dumps(obs_data, indent=2)
            messages.append({"role": "user", "content": f"Current observation:\n{obs_text}\n\nWhat is your next action?"})

            action_str  = ""
            error_str   = "null"
            reward_val  = 0.0
            
            for attempt in range(4):
                try:
                    response = client.chat.completions.create(
                        model=MODEL_NAME,
                        messages=messages,
                        temperature=TEMPERATURE,
                        max_tokens=500,
                        response_format={"type": "json_object"} # Groq supports JSON mode
                    )
                    action_str = response.choices[0].message.content.strip()
                    messages.append({"role": "assistant", "content": action_str})
                    
                    # Validate JSON parse here to retry if Groq hallucinates extra text
                    action_dict = json.loads(action_str)
                    break
                except json.JSONDecodeError as e:
                    err = str(e)
                    error_str = err[:120].replace("\n", " ")
                    messages.append({"role": "user", "content": "Failed to parse JSON. Please respond ONLY with a raw JSON object and no markdown blocks."})
                    wait = 2 ** attempt
                    time.sleep(wait)
                    continue
                except Exception as e:
                    err = str(e)
                    if "429" in err or "rate" in err.lower():
                        wait = 5 * (2 ** attempt)
                        time.sleep(wait)
                        continue
                    error_str = err[:120].replace("\n", " ")
                    break

            try:
                action_dict = json.loads(action_str)
                step_result = env_request(f"/step?session_id={task_name}", "POST", {
                    "action": action_dict
                })
                obs_data    = step_result.get("observation", obs_data)
                reward_val  = float(step_result.get("reward", {}).get("value", 0.0))
                done        = bool(step_result.get("done", False))
                feedback    = step_result.get("reward", {}).get("feedback", "")
                error_str   = "null"
                
                messages.append({
                    "role": "user",
                    "content": f"Grader feedback: {feedback}"
                })

            except Exception as e:
                error_str  = str(e)[:120].replace("\n", " ")
                done       = False

            rewards.append(reward_val)
            steps_taken = step

            safe_action = action_str.replace("\n", " ")[:200]
            print(
                f"[STEP] step={step} action={safe_action} "
                f"reward={reward_val:.2f} done={str(done).lower()} error={error_str}",
                flush=True
            )

    except Exception as e:
        error_str = str(e)
        done = True
    finally:
        try:
            env_request(f"/session/{task_name}", "DELETE")
        except:
            pass
        
        final_score = min(1.0, max(0.0, sum(rewards) / max(len(rewards), 1)))
        success     = final_score >= 0.7
        rewards_str = ",".join(f"{r:.2f}" for r in rewards)
        
        print(
            f"[END] success={str(success).lower()} steps={steps_taken} "
            f"score={final_score:.2f} rewards={rewards_str}",
            flush=True
        )

    return {"task": task_name, "score": final_score, "success": success, "steps": steps_taken}

def main():
    results = []
    start_time = time.time()
    for task in TASKS:
        try:
            result = run_task(task, start_time)
        except Exception as e:
            print(f"[END] success=false steps=0 score=0.00 rewards=", flush=True)
            result = {"task": task, "score": 0.0, "success": False, "steps": 0}
        results.append(result)

    print("\n=== SUMMARY ===", flush=True)
    for r in results:
        print(f"  {r['task']}: score={r['score']:.2f} success={r['success']}", flush=True)

if __name__ == "__main__":
    main()
