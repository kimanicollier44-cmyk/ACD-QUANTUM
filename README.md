# ACD-Quantum

![ACD-Quantum Cover](assets/cover.png)

## What is this?

**ACD-Quantum** is a Quantum Cyber Security structure tree and migration toolkit: the **Top 15 National (USA)** and **Top 15 International** bodies, standards and industry players that govern the post-quantum transition — plus working tools built on that map.

One `main.py`, pure Python standard library, zero dependencies, offline and deterministic. It prints the full structure tree, scans a cryptographic inventory for quantum-vulnerable algorithms, scores PQC migration readiness and generates a phased migration plan, simulates the BB84 quantum key distribution protocol with eavesdropper detection via QBER, simulates a QRNG (honestly labelled as a simulation), and calculates Harvest-Now-Decrypt-Later risk with the Mosca inequality.

The five branches are: **PQC** (NIST FIPS 203 ML-KEM / 204 ML-DSA / 205 SLH-DSA, plus HQC), **QKD**, **QRNG**, **Crypto Discovery / Agility**, and **HNDL Defense**.

> Honest limits: the QKD and QRNG modules are classical simulations of quantum protocols. They use no real quantum hardware and produce no true quantum randomness. Real migration must use validated implementations of the NIST standards.

## 🧰 Tech Stack Badges & Full Architecture Tech Stack

![CI](https://img.shields.io/badge/CI-ci.yml-blue)
![Docker Publish](https://img.shields.io/badge/Docker%20Publish-docker--publish.yml-blue)
![Python 3.12](https://img.shields.io/badge/Python-3.12-blue)
![Docker](https://img.shields.io/badge/Docker-ready-blue)
![Dependencies](https://img.shields.io/badge/dependencies-zero-green)
![License](https://img.shields.io/badge/License-MIT-green)

### 💻 Core Programming Languages & Core Systems

- **Python 3.12** — the entire project is ONE file, `main.py`, pure standard library (`argparse`, `hashlib`, `random`, `sys`)
- **Deterministic engines** — seeded BB84 simulation, SHA-256 counter-expansion QRNG simulation, Mosca HNDL calculator
- **Data-first design** — the Top 15 National / International structure trees are typed data in `main.py`, rendered as text trees

### ⛓️ Web3 & Infrastructure

- **N/A — honestly.** ACD-Quantum has no blockchain, token, wallet or Web3 component. Its infrastructure relevance is the cryptography that Web3 (and everything else) must migrate: RSA/ECC key exchange and signatures are quantum-vulnerable wherever they are used.

### ⚙️ Platform Support

- Linux, macOS, Windows — anywhere Python 3.12 runs
- Docker (`python:3.12-slim`) — see Install
- Terminal / CLI only; no network access required or used

### 🛠️ DevOps

- GitHub Actions `ci.yml` — pytest on Python 3.12 (workflow file is pasted by the repo owner; the GitHub App cannot write workflow files)
- GitHub Actions `docker-publish.yml` — publishes the Docker image (owner-pasted)
- `pytest` test suite in `tests/test_main.py`

### ☁️ Cloud

- Cloud-agnostic: runs locally, in CI, or in any container runtime. No cloud account, no network calls, no secrets needed.

## How it works — step by step

1. **Structure tree** — `python main.py tree` prints the five branches (PQC, QKD, QRNG, Agility, HNDL) and both Top 15 lists with each body's role: NIST writes the standards (FIPS 203/204/205), NSA mandates CNSA 2.0 for National Security Systems, CISA pushes migration to critical infrastructure, OMB forces the federal deadline; internationally, ISO/IEC, ITU-T, IETF and ETSI carry those algorithms into global standards and protocols.
2. **Crypto inventory scan** — `python main.py scan --algos RSA-2048,ECDSA,AES-256,ML-KEM-768` classifies every algorithm: RSA/ECC/DH family = `vulnerable` (Shor), MD5/SHA-1/DES = `broken`, AES-128/SHA-256 = `weakened` (Grover), AES-256/SHA-384/SHA-512 = `cnsa_ok`, ML-KEM/ML-DSA/SLH-DSA/HQC/LMS/XMSS = `pqc_safe`, anything else = `unknown`.
3. **Readiness score** — the scanner's safe share is weighted with inventory completeness and crypto-agility into a 0–100 score and grade (AT RISK → READY).
4. **Migration plan** — `python main.py plan` generates 5 phases (Discover → Prioritise HNDL-first → Replace vulnerable public-key → Strengthen symmetric + hybrid → Agility + verify), naming your actual vulnerable and weakened items.
5. **BB84 QKD simulation** — Alice and Bob exchange seeded random bits/bases; with `--eve`, an intercept-resend eavesdropper raises the quantum bit error rate (QBER) to ~25%, crossing the 11% threshold — the eavesdropper is detected and the key is aborted.
6. **QRNG simulation** — bytes are expanded deterministically from SHA-256(seed ‖ counter) and explicitly labelled: *simulation — NOT true quantum randomness*.
7. **HNDL risk** — `python main.py hndl --shelf-life 10 --migration 4 --crqc 12` applies the Mosca inequality: if shelf-life + migration time > years to a cryptanalytically relevant quantum computer (X + Y > Z), the data is already at risk.
8. **Self-checks** — every run of the demo ends with the built-in verification suite, printing `CHECKS 30/30`.

### Flowchart — main.py

```mermaid
flowchart TD
    A[CLI: main.py mode] --> B{Mode}
    B -->|tree| C[Render National + International Top 15]
    B -->|scan| D[Classify algorithms<br/>vulnerable / weakened / cnsa_ok / pqc_safe]
    B -->|plan| E[Readiness score] --> F[5-phase migration plan]
    B -->|qkd| G[BB84 simulation] --> H{QBER > 11%?}
    H -->|yes| I[Eve detected - key aborted]
    H -->|no| J[Sifted key kept]
    B -->|qrng| K[SHA-256 counter expansion<br/>labelled simulation]
    B -->|hndl| L[Mosca: X + Y > Z ?]
    B -->|demo / checks| M[Run all + self-checks] --> N[CHECKS 30/30]
```

## 10 reasons this is cool

1. The whole US + global quantum-security power structure in one printable tree.
2. One Python file, zero dependencies — it runs anywhere, forever.
3. A crypto scanner that speaks plain status: vulnerable, weakened, CNSA-ok, PQC-safe.
4. Readiness is a number, not a vibe — 0–100 with a grade.
5. The migration plan names *your* vulnerable algorithms, not generic advice.
6. You can watch an eavesdropper get caught by physics — QBER jumps to ~25% with Eve on.
7. Honest QRNG: simulated, labelled simulated, never oversold.
8. The Mosca inequality turns "quantum risk" into one arithmetic check.
9. Fully deterministic — same seed, same result, byte-for-byte, so tests are exact.
10. Self-verifying: every demo run ends with `CHECKS 30/30`.

## 10 problems it solves

1. "Who actually governs post-quantum migration?" — answered, National + International, Top 15 each.
2. Inventories full of RSA/ECC nobody has catalogued — the scanner classifies them instantly.
3. Not knowing where to start migration — Phase 0–4 plan in dependency order.
4. Long-life data silently exposed to Harvest-Now-Decrypt-Later — the HNDL calculator flags it.
5. AES-128 / SHA-256 estates that look "fine" — flagged `weakened` under Grover, with the AES-256 / SHA-384 fix.
6. QKD explained only in papers — BB84 runs here, with and without an eavesdropper.
7. Fake "quantum random" claims — this project's QRNG is labelled a simulation, modelling honest labelling.
8. Vendor-locked PQC tooling — zero-dependency stdlib code you can read in one sitting.
9. Compliance drift against CNSA 2.0 / FIPS 203-205 — statuses map directly to those suites.
10. Training: new engineers get the map, the threat model and the tools in one repo.

## Install — step by step

```bash
# 1. Clone
git clone https://github.com/kimanicollier44-cmyk/ACD-QUANTUM.git
cd ACD-QUANTUM

# 2. Run the demo + self-checks (no installs needed)
python3 main.py

# 3. Explore the modes
python3 main.py tree
python3 main.py scan --algos RSA-2048,ECDSA,AES-256,ML-KEM-768
python3 main.py plan --algos RSA-2048,AES-128
python3 main.py qkd --eve
python3 main.py qrng
python3 main.py hndl --shelf-life 10 --migration 4 --crqc 12
python3 main.py checks

# 4. Run the tests (only dev dependency)
pip install pytest
python -m pytest -q

# 5. Or run in Docker
docker build -t acd-quantum .
docker run --rm acd-quantum
```

## Requirements

- Python 3.12+ (standard library only — `requirements.txt` is intentionally dependency-free for runtime)
- `pytest` for the test suite only
- Docker (optional) for the container run
- No network, no accounts, no secrets

## Project structure

```
ACD-Quantum/
├── main.py                  # ONE file: tree data, scanner, readiness, plan, BB84, QRNG, HNDL, checks, CLI
├── README.md                # This file
├── ABOUT.txt                # Exactly-350-character repo About description
├── tests/
│   └── test_main.py         # pytest suite (23 tests)
├── assets/
│   └── cover.png            # Cover image, 2736x912 (official remix of Darion's own art)
├── conftest.py              # Puts the repo root on sys.path for pytest imports
├── Dockerfile               # python:3.12-slim, runs the demo + checks
├── requirements.txt         # Runtime: stdlib only (comment file)
└── .gitignore
```

## License

MIT
