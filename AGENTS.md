# AGENTS.md — shared rules for every AI coding agent (Claude Code, Codex, etc.)

## Project
quantum-audit: (1) Shor's algorithm breaking a toy RSA key in Qiskit, (2) a passive TLS scanner that grades public
websites on post-quantum readiness, (3) a research study of ~100 sites.
Read `PLAN.md` (blueprint + milestones) and `docs/RESEARCH.md` (findings) before starting any task.

## The human
Vik is learning quantum computing and does not write the code himself. He must be able to explain every file.
- Explain what you're about to build and why before writing it; summarize what each part does after.
- Keep code simple, readable, and well-commented. Prefer clarity over cleverness.
- Point out anything you're unsure about instead of guessing.

## Hard rules
1. **Passive scanning only.** At most one TLS handshake per host per scan, no port scanning, vulnerability probing,
   brute forcing, or heavy traffic. Batch scans: ≥1 s delay between hosts, low concurrency.
2. **No secrets in the repo.** IBM Quantum tokens etc. come from environment variables / `.env` (gitignored).
3. **Honest claims.** Shor's here only breaks toy keys (N = 15, 21). Never imply it can break real encryption.
4. **Stay in your lane.** Only edit the files for the milestone/module you were assigned. If you need to change a file
   owned by another task, say so instead of editing it.
5. **Small commits.** Commit after each working step with a clear message. Run tests before committing.

## Conventions
- Python 3.10+, package code in `quantum_audit/`, tests in `tests/` (pytest), demos in `demos/`, research in `research/`.
- Dependencies go in `requirements.txt`.
- Use the project virtual environment: `source venv/bin/activate`.
