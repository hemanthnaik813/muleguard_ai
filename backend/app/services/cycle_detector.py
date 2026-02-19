import networkx as nx

def detect_cycles(G, min_length=3, max_length=5):
    """
    Detect cycles in directed graph between min_length and max_length
    Returns list of cycles
    """

    cycles = list(nx.simple_cycles(G))

    filtered_cycles = []

    for cycle in cycles:
        if min_length <= len(cycle) <= max_length:
            filtered_cycles.append(cycle)

    return filtered_cycles
