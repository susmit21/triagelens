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

**Rules baseline:** `python scripts/rules_baseline.py` runs the plain-code triage tools
against `data/answer_key.json` with no LLM and currently matches all 8 answer-key rows.
Note: the ranking rules were written with knowledge of the answer key, so this 8/8 figure
is not a held-out result — it confirms internal consistency, not generalisation accuracy.
