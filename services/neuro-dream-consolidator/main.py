from fastapi import FastAPI, BackgroundTasks
from dream_core import DreamCore

app = FastAPI(title="Dream Consolidation Engine")
dreamer = DreamCore()

@app.post("/dream/start")
async def start_dream(bg_tasks: BackgroundTasks):
    if dreamer.is_dreaming:
        return {"status": "Already dreaming", "phase": dreamer.current_phase}
    
    bg_tasks.add_task(dreamer.run_dream_cycle)
    return {"status": "Dream cycle initiated"}

@app.get("/dream/status")
async def status():
    return {"is_dreaming": dreamer.is_dreaming, "current_phase": dreamer.current_phase}

@app.get("/dream/history")
async def history():
    return {"message": "Query `dream_consolidation_log` in TimescaleDB for historical data."}

@app.post("/dream/abort")
async def abort_dream():
    success = dreamer.abort()
    return {"status": "Aborted" if success else "Was not dreaming"}

@app.get("/dream/insights")
async def get_insights():
    return {"latest_insights": dreamer.insights}
