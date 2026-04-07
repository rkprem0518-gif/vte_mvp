import collections
import time
import threading
from fastapi import Request, HTTPException, Depends

class RateLimiter:
    def __init__(self, max_calls: int = 60, period_seconds: int = 60):
        self.max_calls = max_calls
        self.period_seconds = period_seconds
        self.history = collections.defaultdict(collections.deque)
        self.lock = threading.Lock()

    def is_allowed(self, session_id: str) -> bool:
        with self.lock:
            now = time.time()
            q = self.history[session_id]
            while q and now - q[0] > self.period_seconds:
                q.popleft()
            if len(q) < self.max_calls:
                q.append(now)
                return True
            return False

    def wait_time(self, session_id: str) -> float:
        with self.lock:
            now = time.time()
            q = self.history[session_id]
            while q and now - q[0] > self.period_seconds:
                q.popleft()
            if len(q) >= self.max_calls:
                return max(0.0, self.period_seconds - (now - q[0]))
            return 0.0

global_limiter = RateLimiter(max_calls=60, period_seconds=60)

def get_limiter():
    return global_limiter

async def rate_limit_check(session_id: str = "default", limiter: RateLimiter = Depends(get_limiter)):
    if not limiter.is_allowed(session_id):
        wait = limiter.wait_time(session_id)
        raise HTTPException(
            status_code=429, 
            detail=f"Rate limit exceeded. Retry in {wait:.1f}s",
            headers={"Retry-After": str(int(wait) + 1)}
        )
