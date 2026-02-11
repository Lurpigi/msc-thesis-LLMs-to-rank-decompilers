from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os
import json
from pathlib import Path
from typing import List, Dict, Any
import uvicorn

app = FastAPI()

GHIDRA_DATA_DIR = Path("/data/ghidra")
DOGBOLT_DATA_DIR = Path("/data/dogbolt")
STATIC_DIR = Path("/app/static")

@app.get("/api/data")
async def get_ghidra_data():
    """Scans the ghidra data directory and returns all JSON reports."""
    reports = []
    # Fallback to /data for backward compatibility or if not explicitly split
    search_dir = GHIDRA_DATA_DIR if GHIDRA_DATA_DIR.exists() else Path("/data")
    
    if not search_dir.exists():
        return {"error": "Ghidra data directory not found"}

    for file_path in search_dir.rglob("*.json"):
        # Skip dogbolt_report.json if it happens to be here
        if file_path.name == "dogbolt_report.json":
            continue
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                reports.append(data)
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
            
    return reports

@app.get("/api/dogbolt-data")
async def get_dogbolt_data():
    """Reads dogbolt_report.json and groups it by model_id and binary."""
    report_file = DOGBOLT_DATA_DIR / "dogbolt_report.json"
    if not report_file.exists():
        # Try fallback if not in subdirectory
        report_file = Path("/data/dogbolt_report.json")
        if not report_file.exists():
            return {"error": "Dogbolt report file not found"}

    try:
        with open(report_file, "r") as f:
            data = json.load(f)
            
        # The JSON is already grouped by model_id: { "model_id": [ { "binary": "...", ... }, ... ] }
        # Re-grouping for better frontend consumption if needed, 
        # but the user said "grouping data for model_id and for binary (in the JSON we have three element for one single binary)"
        
        structured_data = {}
        for model_id, items in data.items():
            structured_data[model_id] = {}
            for item in items:
                binary = item.get("binary")
                if binary not in structured_data[model_id]:
                    structured_data[model_id][binary] = []
                structured_data[model_id][binary].append(item)
        
        return structured_data
    except Exception as e:
        return {"error": str(e)}

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
