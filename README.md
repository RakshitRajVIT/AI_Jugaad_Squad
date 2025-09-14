# AI for Digital Security — MVP

Single-file Streamlit demo: app.py

## What it does
- Generates or accepts CSV logs.
- Extracts per-IP features (requests, avg bytes, URL heuristics, payload entropy, keywords).
- Runs IsolationForest to flag anomalous IPs.
- Shows flagged raw rows and allows CSV export.
- Includes a short demo script for judges.

## Files
- app.py  — main Streamlit app
- requirements.txt — Python dependencies

## Quick local run (Linux / macOS)
1. Create & activate venv (recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate