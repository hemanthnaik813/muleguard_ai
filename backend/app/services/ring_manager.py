def assign_ring_ids(cycles):
    """
    Assigns unique Ring IDs to each detected cycle
    Returns:
        fraud_rings (list)
        suspicious_accounts (dict)
    """

    fraud_rings = []
    suspicious_accounts = {}

    for i, cycle in enumerate(cycles, start=1):
        ring_id = f"RING_{i:03d}"

        # Add fraud ring
        fraud_rings.append({
            "ring_id": ring_id,
            "member_accounts": cycle,
            "pattern_type": "cycle"
        })

        # Mark each account suspicious
        for account in cycle:
            if account not in suspicious_accounts:
                suspicious_accounts[account] = {
                    "account_id": account,
                    "detected_patterns": [],
                    "ring_id": ring_id
                }

            suspicious_accounts[account]["detected_patterns"].append("cycle")

    return fraud_rings, list(suspicious_accounts.values())
