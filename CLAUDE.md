# TriageLens — Exposure-Aware Vulnerability Triage Agent

## What this project is
CMU Agentic AI capstone. A multi-agent system that checks new CVEs against a
synthetic company cloud network, ranks them by real exposure (can an attacker
reach the asset?), recommends a mitigation, and asks a human analyst to approve.
Deadline: Sunday Nov 22, 11:59pm. Prefer a working simple version over a
half-finished complex one.

## How I want to work (I am learning)
- I am new to building agents. Before writing code, explain your plan in plain
  words and wait for my OK.
- After writing a file, explain what it does and why, briefly.
- Work in small steps. Each step must end with something I can run.
- Tell me the exact command to run; I will run it and paste results back.
- Suggest a git commit message after each working step.

## Architecture (from my design checkpoints)
- Plain code, no LLM: change detection, asset search, reachability check
  (graph walk over subnets and security groups), ranking rules.
- RAG: Chroma vector store over vendor advisories and MITRE ATT&CK techniques.
- Five agents: Coordinator, Threat Researcher, Exposure Analyst,
  Mitigation Planner (Tree-of-Thought, beam width 3, depth 3), Critic.
- Guardrails: read-only, allowed-actions list, step/token caps, every claim
  needs a source, fetched text is data not instructions.
- Human approval required before any change is drafted.
- Evaluation against an answer key: missed high-priority findings, ranking
  accuracy, groundedness, exposure accuracy.
- UI: CLI first, then a Streamlit page that reads the generated brief.

## Project layout
- data/       synthetic environment, CVE snapshots, advisories, answer key
- triage/     agent code (tools/, agents/, rag/, guardrails.py, cli.py)
- app/        Streamlit web page
- eval/       evaluation script and results
- tests/      pytest tests

## Tech
- Python 3.12, virtual environment in .venv
- Anthropic Python SDK for LLM calls. Auth via `ant auth login`;
  fallback is ANTHROPIC_API_KEY in .env
- Streamlit for the UI, pytest for tests

## Rules
- Use only synthetic or public data. No real company data.
- Never put API keys in code. Never commit .env.
- Tests must not call live APIs or the LLM; use saved snapshots and fakes.
- Do not add new frameworks without asking me first.

## Commands
- Activate env: source .venv/bin/activate
- Run tests: pytest -q
- Run triage: python -m triage.cli --cve CVE-2024-23897
- Run UI: streamlit run app/app.py
