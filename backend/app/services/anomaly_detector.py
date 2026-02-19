import numpy as np
from sklearn.ensemble import IsolationForest

def detect_anomalies_with_scores(G, df):

    accounts = list(G.nodes())
    features = []

    for account in accounts:

        in_degree = G.in_degree(account)
        out_degree = G.out_degree(account)

        sent_amount = df[df["sender_id"] == account]["amount"].sum()
        received_amount = df[df["receiver_id"] == account]["amount"].sum()

        transaction_count = in_degree + out_degree

        features.append([
            in_degree,
            out_degree,
            sent_amount,
            received_amount,
            transaction_count
        ])

    features = np.array(features)

    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(features)

    anomaly_scores = model.decision_function(features)

    anomaly_dict = {}

    for i, account in enumerate(accounts):
        anomaly_dict[account] = anomaly_scores[i]

    return anomaly_dict
