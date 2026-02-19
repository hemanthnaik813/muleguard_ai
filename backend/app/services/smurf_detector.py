from collections import defaultdict
from datetime import timedelta

def detect_smurfing(df, min_senders=5, time_window_hours=72):
    """
    Detects fan-in smurfing pattern:
    Many senders → one receiver within time window
    """

    smurf_rings = []
    suspicious_accounts = {}

    grouped = df.groupby("receiver_id")

    ring_counter = 1

    for receiver, group in grouped:
        unique_senders = group["sender_id"].unique()

        if len(unique_senders) >= min_senders:
            timestamps = group["timestamp"].sort_values()

            time_diff = timestamps.max() - timestamps.min()

            if time_diff <= timedelta(hours=time_window_hours):

                ring_id = f"SMURF_{ring_counter:03d}"
                ring_counter += 1

                ring_members = list(unique_senders) + [receiver]

                smurf_rings.append({
                    "ring_id": ring_id,
                    "member_accounts": ring_members,
                    "pattern_type": "smurfing"
                })

                for account in ring_members:
                    suspicious_accounts[account] = {
                        "account_id": account,
                        "detected_patterns": ["smurfing"],
                        "ring_id": ring_id
                    }

    return smurf_rings, list(suspicious_accounts.values())
