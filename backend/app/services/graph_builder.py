import networkx as nx

def build_transaction_graph(df):
    """
    Builds a directed graph from transaction DataFrame
    """

    G = nx.DiGraph()

    for _, row in df.iterrows():
        sender = row["sender_id"]
        receiver = row["receiver_id"]
        amount = row["amount"]
        timestamp = row["timestamp"]

        # Add nodes
        G.add_node(sender)
        G.add_node(receiver)

        # Add edge with attributes
        G.add_edge(
            sender,
            receiver,
            amount=amount,
            timestamp=timestamp
        )

    return G
