from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
import json
from pathlib import Path
from typing import List, Dict, Any
import uvicorn

app = FastAPI()

DATA_DIR = Path("/data")
STATIC_DIR = Path("/app/static")

@app.get("/api/data")
async def get_data():
    """Scans the data directory and returns all JSON reports."""
    reports = []
    if not DATA_DIR.exists():
        return {"error": "Data directory not found"}

    for file_path in DATA_DIR.rglob("*.json"):
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                reports.append(data)
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
            
    return reports

# Serve static files
if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

@app.exception_handler(404)
async def custom_404_handler(request, exc):
    if STATIC_DIR.exists():
        return FileResponse(str(STATIC_DIR / "index.html"))
    return {"error": "Not found"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=80)
