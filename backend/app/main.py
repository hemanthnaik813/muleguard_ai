from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import shutil
import os
import pandas as pd
import numpy as np
import networkx as nx
import time

from app.services.graph_builder import build_transaction_graph
from app.services.cycle_detector import detect_cycles
from app.services.ring_manager import assign_ring_ids
from app.services.smurf_detector import detect_smurfing
from app.services.shell_detector import detect_shell_chains
from app.services.anomaly_detector import detect_anomalies_with_scores
from app.services.scoring_engine import calculate_suspicion_scores
from app.database import init_db, SessionLocal, SuspiciousHistory


# =====================================================
# APP INITIALIZATION
# =====================================================
app = FastAPI(title="MuleGuard AI Backend")

# =====================================================
# CORS (OPEN FOR DEV + RENDER SAFE)
# =====================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change to frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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


# =====================================================
# HEALTH CHECK
# =====================================================
@app.get("/")
def health_check():
    return {"status": "OK", "message": "MuleGuard AI Backend running 🚀"}


# =====================================================
# UPLOAD ENDPOINT
# =====================================================
@app.post("/upload/")
async def upload_file(file: UploadFile = File(...)):
    start_time = time.time()
    db = None

    try:
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        file_path = os.path.join(UPLOAD_FOLDER, file.filename)

        # Save file
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Read CSV
        df = pd.read_csv(file_path)

        # Validate required columns
        missing_columns = [col for col in REQUIRED_COLUMNS if col not in df.columns]
        if missing_columns:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Invalid CSV format",
                    "missing_columns": missing_columns
                }
            )

        # Convert timestamp safely
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

        if df["timestamp"].isnull().any():
            raise HTTPException(
                status_code=400,
                detail="Invalid timestamp format in CSV"
            )

        # =====================================================
        # BUILD GRAPH
        # =====================================================
        G = build_transaction_graph(df)

        degree_centrality = nx.degree_centrality(G)
        betweenness_centrality = nx.betweenness_centrality(G, normalized=True)
        pagerank_scores = nx.pagerank(G)

        # =====================================================
        # PATTERN DETECTION
        # =====================================================
        cycles = detect_cycles(G)
        fraud_rings, suspicious_accounts = assign_ring_ids(cycles)

        smurf_rings, smurf_accounts = detect_smurfing(df)
        fraud_rings.extend(smurf_rings)
        suspicious_accounts.extend(smurf_accounts)

        shell_rings, shell_accounts = detect_shell_chains(G)
        fraud_rings.extend(shell_rings)
        suspicious_accounts.extend(shell_accounts)

        # Remove duplicate accounts
        unique_accounts = {}
        for acc in suspicious_accounts:
            unique_accounts[acc["account_id"]] = acc
        suspicious_accounts = list(unique_accounts.values())

        # =====================================================
        # ANOMALY DETECTION
        # =====================================================
        anomaly_scores = detect_anomalies_with_scores(G, df)

        # =====================================================
        # DATABASE MEMORY
        # =====================================================
        db = SessionLocal()

        suspicious_accounts = calculate_suspicion_scores(
            suspicious_accounts,
            df,
            degree_centrality,
            betweenness_centrality,
            pagerank_scores,
            anomaly_scores,
            db
        )

        # Dynamic threshold
        if suspicious_accounts:
            scores = [acc["suspicion_score"] for acc in suspicious_accounts]
            dynamic_threshold = max(40, np.percentile(scores, 70))
        else:
            dynamic_threshold = 40

        suspicious_accounts = [
            acc for acc in suspicious_accounts
            if acc["suspicion_score"] >= dynamic_threshold
        ]

        # Clean rings
        valid_ids = {acc["account_id"] for acc in suspicious_accounts}
        fraud_rings = [
            ring for ring in fraud_rings
            if any(member in valid_ids for member in ring["member_accounts"])
        ]

        # Save history safely
        for acc in suspicious_accounts:
            record = db.query(SuspiciousHistory).filter(
                SuspiciousHistory.account_id == acc["account_id"]
            ).first()

            if record:
                record.last_score = acc["suspicion_score"]
                record.times_flagged += 1
            else:
                db.add(SuspiciousHistory(
                    account_id=acc["account_id"],
                    last_score=acc["suspicion_score"],
                    times_flagged=1
                ))

        db.commit()

        processing_time = round(time.time() - start_time, 2)

        # =====================================================
        # FIX: JSON SERIALIZATION ISSUE
        # Convert timestamp to string
        # =====================================================
        df["timestamp"] = df["timestamp"].astype(str)

        # =====================================================
        # RESPONSE
        # =====================================================
        return JSONResponse({
            "fraud_rings": fraud_rings,
            "suspicious_accounts": suspicious_accounts,
            "summary": {
                "total_accounts_analyzed": G.number_of_nodes(),
                "total_transactions": G.number_of_edges(),
                "suspicious_accounts_flagged": len(suspicious_accounts),
                "fraud_rings_detected": len(fraud_rings),
                "processing_time_seconds": processing_time
            },
            "raw_transactions": df.to_dict(orient="records"),
            "message": "Hybrid Fraud Intelligence Engine completed 🚀🔥"
        })

    except HTTPException as e:
        raise e

    except Exception as e:
        print("🔥 ERROR:", e)
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if db:
            db.close()


# =====================================================
# HISTORY ENDPOINT
# =====================================================
@app.get("/history/")
def get_history():
    db = SessionLocal()
    try:
        records = db.query(SuspiciousHistory).all()

        history = [
            {
                "account_id": r.account_id,
                "last_score": r.last_score,
                "times_flagged": r.times_flagged,
                "last_flagged_at": r.last_flagged_at
            }
            for r in records
        ]

        return {
            "total_records": len(history),
            "history": history
        }

    finally:
        db.close()
