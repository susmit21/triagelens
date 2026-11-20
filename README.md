# TriageLens

TriageLens is a multi-agent system that checks new CVEs against a synthetic company
cloud network, ranks them by real exposure (can an attacker actually reach the asset?),
recommends a mitigation plan, and asks a human analyst to approve before anything is
drafted. Built as a CMU Agentic AI capstone project using the Anthropic Python SDK,
Chroma for RAG, and Streamlit for the UI.

Work in progress.

**Routing assumption:** the synthetic environment has no route tables. An asset
in the public subnet with a public IP is treated as internet-routable when its
security group allows the connection.
