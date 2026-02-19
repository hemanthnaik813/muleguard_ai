from app.database import SuspiciousHistory


def calculate_suspicion_scores(
    suspicious_accounts,
    df,
    degree_centrality,
    betweenness_centrality,
    pagerank_scores,
    anomaly_scores,
    db
):
    """
    Hybrid Fraud Scoring Engine

    Combines:
    - Pattern detection
    - Graph centrality
    - ML anomaly scoring
    - Persistent suspicion memory
    """

    # ------------------------------------------------
    # Calculate transaction counts
    # ------------------------------------------------
    transaction_counts = {}

    for _, row in df.iterrows():
        sender = row["sender_id"]
        receiver = row["receiver_id"]

        transaction_counts[sender] = transaction_counts.get(sender, 0) + 1
        transaction_counts[receiver] = transaction_counts.get(receiver, 0) + 1

    # ------------------------------------------------
    # Score each suspicious account
    # ------------------------------------------------
    for account in suspicious_accounts:

        raw_score = 0
        explanation_parts = []

        account_id = account["account_id"]
        patterns = account.get("detected_patterns", [])

        # ------------------------------------------------
        # Pattern-Based Scoring
        # ------------------------------------------------

        if "cycle" in patterns:
            raw_score += 50
            explanation_parts.append("Participates in circular routing pattern")

        if "smurfing" in patterns:
            if transaction_counts.get(account_id, 0) > 2:
                raw_score += 45
                explanation_parts.append("Acts as smurfing aggregator")
            else:
                raw_score += 35
                explanation_parts.append("Participates as smurfing feeder")

        if "shell_chain" in patterns:
            raw_score += 25
            explanation_parts.append("Involved in shell layering chain")

        # ------------------------------------------------
        # ML Anomaly Contribution (Proportional Boost)
        # ------------------------------------------------

        anomaly_value = anomaly_scores.get(account_id, 0)

        # IsolationForest: negative = more anomalous
        if anomaly_value < 0:
            anomaly_boost = abs(anomaly_value) * 50
            raw_score += anomaly_boost
            explanation_parts.append("Statistically abnormal transaction behavior")

        # ------------------------------------------------
        # Graph Centrality Boost
        # ------------------------------------------------

        deg = degree_centrality.get(account_id, 0)
        bet = betweenness_centrality.get(account_id, 0)
        pr = pagerank_scores.get(account_id, 0)

        if deg > 0.1:
            raw_score += 5
            explanation_parts.append("High connectivity in transaction graph")

        if bet > 0.05:
            raw_score += 10
            explanation_parts.append("Acts as bridge between transaction paths")

        if pr > 0.05:
            raw_score += 5
            explanation_parts.append("High influence score (PageRank)")

        # ------------------------------------------------
        # High Activity Boost
        # ------------------------------------------------

        if transaction_counts.get(account_id, 0) > 5:
            raw_score += 10
            explanation_parts.append("High transaction activity")

        # ------------------------------------------------
        # Persistent Suspicion Memory Boost
        # ------------------------------------------------

        history_record = db.query(SuspiciousHistory).filter(
            SuspiciousHistory.account_id == account_id
        ).first()

        if history_record:
            memory_boost = history_record.times_flagged * 5
            raw_score += memory_boost
            explanation_parts.append(
                f"Previously flagged {history_record.times_flagged} time(s)"
            )

        # ------------------------------------------------
        # Risk Level Classification
        # ------------------------------------------------

        if raw_score >= 70:
            risk_level = "HIGH"
        elif raw_score >= 50:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # ------------------------------------------------
        # Assign final values
        # ------------------------------------------------

        account["suspicion_score"] = round(raw_score, 2)
        account["risk_level"] = risk_level
        account["explanation"] = "; ".join(explanation_parts)

    return suspicious_accounts
