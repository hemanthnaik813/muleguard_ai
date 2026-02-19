from fastapi import FastAPI, UploadFile, File
import shutil
import os
import pandas as pd
import numpy as np
import networkx as nx

from app.services.graph_builder import build_transaction_graph
from app.services.cycle_detector import detect_cycles
from app.services.ring_manager import assign_ring_ids
from app.services.smurf_detector import detect_smurfing
from app.services.shell_detector import detect_shell_chains
from app.services.anomaly_detector import detect_anomalies_with_scores
from app.services.scoring_engine import calculate_suspicion_scores

from app.database import init_db, SessionLocal, SuspiciousHistory


app = FastAPI()
init_db()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "data", "uploads")

REQUIRED_COLUMNS = [
    "transaction_id",
    "sender_id",
    "receiver_id",
    "amount",
    "timestamp"
]


@app.get("/")
def read_root():
    return {"message": "MuleGuard AI Backend is running 🚀"}


@app.post("/upload/")
async def upload_file(file: UploadFile = File(...)):

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    file_location = os.path.join(UPLOAD_FOLDER, file.filename)

    # Save file
    with open(file_location, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Read CSV
    try:
        df = pd.read_csv(file_location)
    except Exception as e:
        return {"error": f"Failed to read CSV: {str(e)}"}

    # Validate columns
    missing_columns = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing_columns:
        return {"error": "Invalid CSV format", "missing_columns": missing_columns}

    # Convert timestamp
    try:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    except Exception:
        return {"error": "Invalid timestamp format"}

    # ------------------------------------------------
    # BUILD GRAPH
    # ------------------------------------------------
    G = build_transaction_graph(df)

    degree_centrality = nx.degree_centrality(G)
    betweenness_centrality = nx.betweenness_centrality(G, normalized=True)
    pagerank_scores = nx.pagerank(G)

    # ------------------------------------------------
    # PATTERN DETECTION
    # ------------------------------------------------
    cycles = detect_cycles(G)
    fraud_rings, suspicious_accounts = assign_ring_ids(cycles)

    smurf_rings, smurf_accounts = detect_smurfing(df)
    fraud_rings.extend(smurf_rings)

    for acc in smurf_accounts:
        if not any(existing["account_id"] == acc["account_id"] for existing in suspicious_accounts):
            suspicious_accounts.append(acc)

    shell_rings, shell_accounts = detect_shell_chains(G)
    fraud_rings.extend(shell_rings)

    for acc in shell_accounts:
        if not any(existing["account_id"] == acc["account_id"] for existing in suspicious_accounts):
            suspicious_accounts.append(acc)

    # ------------------------------------------------
    # ML ANOMALY
    # ------------------------------------------------
    anomaly_scores = detect_anomalies_with_scores(G, df)

    # ------------------------------------------------
    # DATABASE SESSION START
    # ------------------------------------------------
    db = SessionLocal()

    # ------------------------------------------------
    # HYBRID SCORING (includes memory boost)
    # ------------------------------------------------
    suspicious_accounts = calculate_suspicion_scores(
        suspicious_accounts,
        df,
        degree_centrality,
        betweenness_centrality,
        pagerank_scores,
        anomaly_scores,
        db
    )

    # ------------------------------------------------
    # DYNAMIC THRESHOLD
    # ------------------------------------------------
    if suspicious_accounts:
        scores = [acc["suspicion_score"] for acc in suspicious_accounts]
        dynamic_threshold = max(40, np.percentile(scores, 70))
    else:
        dynamic_threshold = 40

    suspicious_accounts = [
        acc for acc in suspicious_accounts
        if acc["suspicion_score"] >= dynamic_threshold
    ]

    # ------------------------------------------------
    # CLEAN RINGS
    # ------------------------------------------------
    valid_account_ids = {acc["account_id"] for acc in suspicious_accounts}

    fraud_rings = [
        ring for ring in fraud_rings
        if any(member in valid_account_ids for member in ring["member_accounts"])
    ]

    # ------------------------------------------------
    # SAVE / UPDATE PERSISTENT MEMORY
    # ------------------------------------------------
    for acc in suspicious_accounts:

        record = db.query(SuspiciousHistory).filter(
            SuspiciousHistory.account_id == acc["account_id"]
        ).first()

        if record:
            record.last_score = acc["suspicion_score"]
            record.times_flagged += 1
        else:
            new_record = SuspiciousHistory(
                account_id=acc["account_id"],
                last_score=acc["suspicion_score"],
                times_flagged=1
            )
            db.add(new_record)

    db.commit()
    db.close()

    # ------------------------------------------------
    # SYSTEM METRICS
    # ------------------------------------------------
    high_risk = sum(1 for acc in suspicious_accounts if acc["risk_level"] == "HIGH")
    medium_risk = sum(1 for acc in suspicious_accounts if acc["risk_level"] == "MEDIUM")
    low_risk = sum(1 for acc in suspicious_accounts if acc["risk_level"] == "LOW")

    fraud_density = round((len(suspicious_accounts) / G.number_of_nodes()) * 100, 2)

    system_metrics = {
        "total_accounts": G.number_of_nodes(),
        "total_transactions": G.number_of_edges(),
        "high_risk_accounts": high_risk,
        "medium_risk_accounts": medium_risk,
        "low_risk_accounts": low_risk,
        "fraud_density_percentage": fraud_density,
        "dynamic_threshold_used": round(dynamic_threshold, 2)
    }

    # ------------------------------------------------
    # RESPONSE
    # ------------------------------------------------
    return {
        "filename": file.filename,
        "rows": len(df),
        "nodes": G.number_of_nodes(),
        "edges": G.number_of_edges(),
        "rings_detected": len(fraud_rings),
        "suspicious_accounts_count": len(suspicious_accounts),
        "fraud_rings": fraud_rings,
        "suspicious_accounts": suspicious_accounts,
        "system_metrics": system_metrics,
        "message": "Hybrid Fraud Intelligence Engine completed 🚀🔥"
    }

@app.get("/history/")
def get_suspicion_history():
    db = SessionLocal()

    records = db.query(SuspiciousHistory).all()

    history = []
    for r in records:
        history.append({
            "account_id": r.account_id,
            "last_score": r.last_score,
            "times_flagged": r.times_flagged,
            "last_flagged_at": r.last_flagged_at
        })

    db.close()

    return {
        "total_records": len(history),
        "history": history
    }
