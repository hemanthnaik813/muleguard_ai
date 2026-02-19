import networkx as nx

def detect_shell_chains(G, min_length=4):
    """
    Detects shell layering chains.
    Returns:
        shell_rings (list)
        suspicious_accounts (list)
    """

    shell_rings = []
    suspicious_accounts = []
    ring_counter = 1

    # Find all simple paths up to length 6
    for source in G.nodes():
        for target in G.nodes():
            if source != target:
                try:
                    paths = nx.all_simple_paths(G, source, target, cutoff=6)
                    for path in paths:
                        if len(path) >= min_length:

                            # Check intermediate nodes (excluding first and last)
                            intermediate_nodes = path[1:-1]

                            valid_shell = True
                            for node in intermediate_nodes:
                                if G.in_degree(node) > 2 or G.out_degree(node) > 2:
                                    valid_shell = False
                                    break

                            if valid_shell:
                                ring_id = f"SHELL_{ring_counter:03d}"
                                ring_counter += 1

                                shell_rings.append({
                                    "ring_id": ring_id,
                                    "member_accounts": path,
                                    "pattern_type": "shell_chain"
                                })

                                for account in path:
                                    suspicious_accounts.append({
                                        "account_id": account,
                                        "detected_patterns": ["shell_chain"],
                                        "ring_id": ring_id
                                    })

                except nx.NetworkXNoPath:
                    continue

    return shell_rings, suspicious_accounts
