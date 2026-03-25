"""
Deliverable 9: Chaos Scheduler — Python microservice with APScheduler
Schedules hourly/daily/weekly chaos experiments, GameDay mode, blackout windows,
and emergency kill switch.
"""
import asyncio
import json
import os
import logging
from datetime import datetime
from contextlib import asynccontextmanager

import docker
import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("chaos_scheduler")

CHAOS_ENGINE_URL = os.getenv("CHAOS_ENGINE_URL", "http://chaos-experiment-engine:8020")
PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://prometheus:9090")
ENV = os.getenv("CHAOS_ENV", "dev")

# Blackout windows config (hour ranges in UTC when chaos is blocked)
BLACKOUT_WINDOWS = [
    {"name": "maintenance", "start_hour": 2, "end_hour": 4, "days": [6]},  # Sunday 2-4 AM UTC
]

SCENARIOS_FILE = "/app/scenarios.json"
scheduler = AsyncIOScheduler()


# ═══ Helpers ═══
async def check_health_gate() -> bool:
    """Block experiments if any service health < 80%."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{PROMETHEUS_URL}/api/v1/query", params={"query": "up"})
            if resp.status_code == 200:
                results = resp.json().get("data", {}).get("result", [])
                total = len(results)
                healthy = sum(1 for r in results if r.get("value", [0, "0"])[1] == "1")
                pct = (healthy / total * 100) if total > 0 else 100
                if pct < 80:
                    logger.warning(f"Health gate BLOCKED: {pct:.0f}% healthy")
                    return False
    except Exception as e:
        logger.warning(f"Health check failed: {e}")
    return True


def in_blackout_window() -> bool:
    now = datetime.utcnow()
    for window in BLACKOUT_WINDOWS:
        if now.weekday() in window.get("days", range(7)):
            if window["start_hour"] <= now.hour < window["end_hour"]:
                logger.info(f"In blackout window: {window['name']}")
                return True
    return False


def load_scenarios() -> list:
    try:
        if os.path.exists(SCENARIOS_FILE):
            with open(SCENARIOS_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return []


async def run_scenario(scenario: dict, dry_run: bool = False):
    """Submit a scenario to the Chaos Experiment Engine."""
    if not await check_health_gate():
        logger.warning(f"Skipping scenario {scenario['name']} — health gate blocked")
        return
    if in_blackout_window():
        logger.warning(f"Skipping scenario {scenario['name']} — blackout window active")
        return

    payload = {
        "scenario_id": scenario["scenario_id"],
        "name": scenario["name"],
        "target_service": scenario["target_service"],
        "mitre_ttp": scenario.get("mitre_ttp", ""),
        "attack_phase": scenario.get("attack_phase", ""),
        "injection_type": scenario.get("injection_type", "security"),
        "blast_radius": scenario.get("blast_radius", "low"),
        "hypothesis": scenario.get("expected_behavior", ""),
        "dry_run": dry_run,
    }
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(f"{CHAOS_ENGINE_URL}/experiments/start", json=payload)
            logger.info(f"Scheduled experiment: {scenario['name']} → {resp.status_code}")
    except Exception as e:
        logger.error(f"Failed to start scheduled experiment: {e}")


# ═══ Scheduled Jobs ═══
async def hourly_micro_experiment():
    """Run a single low-blast-radius experiment every hour (dev only)."""
    if ENV != "dev":
        return
    scenarios = load_scenarios()
    low_scenarios = [s for s in scenarios if s.get("blast_radius") == "low"]
    if low_scenarios:
        import random
        scenario = random.choice(low_scenarios)
        logger.info(f"[HOURLY] Running micro-experiment: {scenario['name']}")
        await run_scenario(scenario)


async def daily_service_experiment():
    """Run medium-blast-radius experiments daily across the stack."""
    scenarios = load_scenarios()
    medium_scenarios = [s for s in scenarios if s.get("blast_radius") in ("low", "medium")]
    if medium_scenarios:
        import random
        batch = random.sample(medium_scenarios, min(3, len(medium_scenarios)))
        for scenario in batch:
            logger.info(f"[DAILY] Running experiment: {scenario['name']}")
            await run_scenario(scenario)
            await asyncio.sleep(60)


async def weekly_full_chaos():
    """Run full stack chaos simulation weekly."""
    scenarios = load_scenarios()
    for scenario in scenarios[:5]:
        logger.info(f"[WEEKLY] Running experiment: {scenario['name']}")
        await run_scenario(scenario)
        await asyncio.sleep(120)


async def on_docker_compose_up():
    """Detect docker-compose up and run baseline chaos suite."""
    try:
        client = docker.from_env()
        events = client.events(decode=True, filters={"event": "start"})
        for event in events:
            container_name = event.get("Actor", {}).get("Attributes", {}).get("name", "")
            if "cybershield" in container_name.lower() or "pariraksakah" in container_name.lower():
                logger.info(f"Detected container start: {container_name}")
                scenarios = load_scenarios()
                if scenarios:
                    logger.info("Running baseline chaos suite on stack up...")
                    await run_scenario(scenarios[0], dry_run=True)
    except Exception as e:
        logger.error(f"Docker event listener failed: {e}")


# ═══ FastAPI App ═══
@asynccontextmanager
async def lifespan(app: FastAPI):
    scheduler.add_job(hourly_micro_experiment, IntervalTrigger(hours=1), id="hourly_micro")
    scheduler.add_job(daily_service_experiment, CronTrigger(hour=10, minute=0), id="daily_service")
    scheduler.add_job(weekly_full_chaos, CronTrigger(day_of_week="fri", hour=14), id="weekly_full")
    scheduler.start()
    logger.info("Chaos Scheduler started with hourly/daily/weekly jobs")
    yield
    scheduler.shutdown()

app = FastAPI(title="Chaos Scheduler", version="1.0.0", lifespan=lifespan)


@app.get("/health")
async def health():
    jobs = scheduler.get_jobs()
    return {"status": "healthy", "service": "chaos-scheduler", "scheduled_jobs": len(jobs)}


class GameDayRequest(BaseModel):
    scenarios: Optional[list] = None
    approval_token: Optional[str] = None

@app.post("/gameday/start")
async def start_gameday(req: GameDayRequest):
    """Launch full coordinated GameDay chaos across entire stack."""
    if not await check_health_gate():
        raise HTTPException(503, "System health below 80% — GameDay blocked")
    scenarios = req.scenarios or load_scenarios()
    logger.info(f"GAMEDAY STARTED — {len(scenarios)} scenarios queued")
    for scenario in scenarios:
        await run_scenario(scenario)
        await asyncio.sleep(30)
    return {"status": "gameday_started", "scenarios": len(scenarios)}


@app.post("/chaos/kill-all")
async def kill_all():
    """Emergency kill switch — stop all experiments within 5 seconds."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.post(f"{CHAOS_ENGINE_URL}/chaos/kill-all")
            return {"status": "kill_signal_sent", "engine_response": resp.json()}
    except Exception as e:
        return {"status": "kill_signal_failed", "error": str(e)}


@app.get("/schedule")
async def list_schedule():
    jobs = scheduler.get_jobs()
    return {"jobs": [{"id": j.id, "next_run": str(j.next_run_time), "trigger": str(j.trigger)} for j in jobs]}


@app.get("/metrics")
async def prometheus_metrics():
    from fastapi.responses import PlainTextResponse
    jobs = scheduler.get_jobs()
    return PlainTextResponse(
        f'chaos_scheduled_jobs {len(jobs)}\nchaos_scheduler_env{{env="{ENV}"}} 1\n',
        media_type="text/plain",
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("CHAOS_SCHEDULER_PORT", "8022")))
