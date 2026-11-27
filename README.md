# ACD-Quantum

![ACD-Quantum Cover](ACD-Quantum%20cover.png)

<p align="center">
  <img src="1795749636374.jpg" alt="ACD-Quantum Original Art" width="420">
</p>

## What is this?

**ACD-Quantum** is a Quantum Cyber Security structure tree and migration toolkit: the **Top 15 National (USA)** and **Top 15 International** bodies, standards and industry players that govern the post-quantum transition — plus working tools built on that map.

One `main.py`, pure Python standard library, zero dependencies, offline and deterministic. It prints the full structure tree, scans a cryptographic inventory for quantum-vulnerable algorithms, scores PQC migration readiness and generates a phased migration plan, simulates the BB84 quantum key distribution protocol with eavesdropper detection via QBER, simulates a QRNG (honestly labelled as a simulation), and calculates Harvest-Now-Decrypt-Later risk with the Mosca inequality.

The five branches are: **PQC** (NIST FIPS 203 ML-KEM / 204 ML-DSA / 205 SLH-DSA, plus HQC), **QKD**, **QRNG**, **Crypto Discovery / Agility**, and **HNDL Defense**.

**Merged in:** a **Google Earth layer** (real HQ coordinates for all 30 bodies, KML export for Google Earth, haversine distances), the **Gemini Argon 4 Extended Thinking DECIDER** seat (MAP→MODEL→STRESS→DECIDE, trace-hashed, tighten-only, names-only key, no live calls), the **SIx Neural Core** as the interface core driving every run (5-state machine + hash-chained audit ledger), a **Recommended Quantum Docker Images** catalog of Darion's own `credkellar/` fleet with a branch/topic recommendation engine, a **Google Maps Street View Service layer** (offline-faithful models of `StreetViewService.getPanorama`, `StreetViewPanorama` options/events and a custom panorama provider for all 30 bodies, plus a standalone Street View HTML generator), and a **Perfect Map layer** (the full Maps JavaScript API feature model — map options, 30 markers with InfoWindows, bounds fitting, Traffic/Transit/Bicycling/KML layers, map events, offline geocoding — and one combined map + Street View HTML page where clicking a marker opens that body's panorama).

**Merge 7 — media + sensing layer:** **voice recognition** (speech-to-intent over supplied transcripts: wake phrases, a command grammar routed to the existing CLI modes, slot extraction, speaker diarization, and a synthetic voiceprint similarity model), a **speech speaker** (TTS voice presets, SSML-like speech plans with clamped rate/pitch/volume, an utterance queue, and a speak-the-verdict helper), **audio** (real stdlib WAV generation + analysis — duration, RMS, peak, dBFS, silence — a codec model and labelled loudness targets), **Bluetooth** (BLE + Classic device/profile model with standard service UUIDs, a labelled synthetic scan with RSSI distance estimates, pairing-security assessment and a bonding store), and a **3D 8K cinematic camera** model (8K UHD/DCI, 24–120 fps, stereo depth budgets, FOV/framing calculators, colour pipelines, bitrate + storage estimates, and capture plans tied to a body's Earth coordinates and Street View pano). Honest labelling throughout: these are models, specs, plans and text/sample-data processing — **no real microphone, speaker hardware, Bluetooth radio or camera is accessed**, the Bluetooth scan is synthetic, and the voiceprints are synthetic demo vectors, never real biometric identification.

**Merge 8 — Monad chain layer:** the **Monad** blockchain merged as a full offline chain layer built on the verified Monad catalog parameters — **10,000 TPS** throughput, **300 ms** block frequency, **600 ms** finality, **MonadBFT** consensus, **RaptorCast** block propagation, asynchronous / deferred execution, **optimistic parallel execution**, **MonadDB**, and **100% EVM compatibility** (mainnet chain ID **143**, testnet **10143**, native token **MON**, 100B fixed supply, 18 decimals). It ships a deterministic TPS simulator (anything above 10,000 TPS is flagged `EXCEEDS_CATALOG_CEILING`), an optimistic parallel-execution simulator with conflict re-execution and speedup figures, an EIP-1559 transaction + lifecycle model (mempool → proposed via RaptorCast → voted via MonadBFT → finalized at 600 ms), validator / staking quorum math (n=100 → quorum 67, fault tolerance 33), bridge and MEV risk models, a smart-contract quantum audit checklist, and the full recommended-features catalog — every entry status `merged`. The ACD tie-in: EVM accounts sign with **ECDSA / secp256k1**, which the existing scanner classifies **quantum-vulnerable**, so the layer adds per-account quantum-exposure reports (an exposed EVM public key is a Shor target once a CRQC arrives), a 5-phase PQC migration path for chain users, and an Argon 4 chain decision that stays **NO-GO** on ECDSA exposure (tighten-only, can never override). Honest labelling: this is offline models and simulations only — **no live RPC calls, no keys, no real transactions**; throughput and latency figures are simulated estimates against the published catalog parameters, not live network measurements.

**Merge 9 — Knowledge layer:** six of Darion's infographics merged as one offline catalog of **154 entries** — the **13 Must-Have AI Tools for Cybersecurity** (CrowdStrike Charlotte AI, SentinelOne Purple AI, Darktrace, Wiz, Microsoft Security Copilot, Palo Alto Cortex, IBM QRadar Advisor, Cisco AI Security, Vectra AI, Acronis Cyber Protect AI, Cybereason, Pentera, Guardz) with category coverage-gap checks and need-based recommendations; the **Claude Secret Codes** (14 prompt codes — the source lists `/artifacts` twice, #8 build and #10 review, and both are stored and flagged honestly); the **80 Secret Codes of Google Gemini** in 8 groups (entries #61–#71 are partially cut off in the source photo and are flagged `source_partially_visible`); a combined **94-code prompt registry** with cross-source lookup; **The Ultimate AI Glossary** (18 terms with plain definitions and a deterministic seeded quiz); the **Cybersecurity Career Reality** stack (15 layers, credit **@hacktanic**) with a path-progress checker; and **What Cybersecurity Actually Is** (14 real domains, credit **@hacktanic** — "Hacking" is only the popular umbrella misconception). The perfect-merge tie-in: every AI tool is cross-linked to its closest cyber domain(s), and every domain lists its tools. Honest labelling: this is catalog / reference data transcribed from the infographics — **ACD-Quantum does not call any vendor API live**; the prompt codes are a registry, not commands sent to any model.

> Honest limits: the QKD and QRNG modules are classical simulations of quantum protocols. They use no real quantum hardware and produce no true quantum randomness. Real migration must use validated implementations of the NIST standards.

## 🧰 Tech Stack Badges & Full Architecture Tech Stack

![CI](https://img.shields.io/badge/CI-ci.yml-blue)
![Docker Publish](https://img.shields.io/badge/Docker%20Publish-docker--publish.yml-blue)
![Python 3.12](https://img.shields.io/badge/Python-3.12-blue)
![Docker](https://img.shields.io/badge/Docker-ready-blue)
![Dependencies](https://img.shields.io/badge/dependencies-zero-green)
![License](https://img.shields.io/badge/License-MIT-green)

### 💻 Core Programming Languages & Core Systems

- **Python 3.12** — the entire project is ONE file, `main.py`, pure standard library (`argparse`, `hashlib`, `json`, `math`, `os`, `random`, `sys`, `xml`)
- **Deterministic engines** — seeded BB84 simulation, SHA-256 counter-expansion QRNG simulation, Mosca HNDL calculator
- **Data-first design** — the Top 15 National / International structure trees are typed data in `main.py`, rendered as text trees
- **Google Earth / KML** — HQ lat/lon for all 30 bodies, well-formed KML 2.2 export (one Placemark per body), haversine great-circle distances; no Google API key or network needed
- **Gemini Argon 4 Extended Thinking** — DECIDER seat (`gemini-argon-4`, engine gemini-2.5-pro, model google/gemini-carbon-4-extended-pro-thinking), MAP→MODEL→STRESS→DECIDE with sha256 trace, tiers 2048/8192/32768 by stakes, `GEMINI_API_KEY` names/presence-only, **no live calls**, tighten-only (`can_override=False`)
- **SIx Neural Core** — Darion's SIx interface core ported to pure stdlib: 5-state machine (IDLE/LISTENING/THINKING/RESPONDING/LEARNING) with SIx's legal-transition map, logical ticks, per-state behaviour params, plus SIx's hash-chained audit ledger
- **Docker fleet catalog** — 29 recommended quantum images from Darion's own `credkellar/` Docker Hub fleet (snapshot Nov 2026)
- **Google Maps Street View Service (modelled)** — `StreetViewService.getPanorama` request/response model (location or pano id, radius 50 default, source default/outdoor, status OK / ZERO_RESULTS / UNKNOWN_ERROR), `StreetViewPanorama` options with docs defaults + heading wrap / pitch clamp validation, a custom panorama provider, the six documented `*_changed` events on an offline panorama model, and a standalone HTML generator that loads the real Maps JavaScript API (placeholder credential only — `YOUR_API_KEY`, key name `GOOGLE_MAPS_API_KEY`)
- **Google Maps Perfect Map (modelled)** — `MapOptions` model (map types, all controls, gesture handling, min/max zoom, restriction), 30 markers (label `ACD`, DROP animation) with InfoWindow content, `LatLngBounds` fitting overall + per region, Traffic/Transit/Bicycling layer toggles, a `KmlLayer` for `earth/ACD-QUANTUM.kml`, a cover-image `GroundOverlay` example, the map event set on an offline map model, forward/reverse geocoding over the body data, and a combined map + Street View HTML generator (marker click → that body's panorama, the docs' side-by-side pattern)
- **Media + sensing layer (modelled)** — voice recognition (wake phrases `ACD` / `hey ACD` / `ok ACD`, grammar → CLI modes, algorithm/body/distance slots, exact/fuzzy/unknown confidence, diarization, synthetic voiceprints with cosine match + UNKNOWN below threshold), speech speaker (4 TTS presets, SSML-like plans, FIFO utterance queue, verdict speaker), audio (stdlib `wave`/`struct` tone generation + WAV analysis, WAV/FLAC/MP3/AAC/Opus codec model, −16 LUFS podcast / −14 streaming labelled targets, mic→recognition→speaker pipeline spec), Bluetooth (BLE + Classic, 0x180D/0x180F/0x180A + A2DP/HFP/AVRCP/LE Audio/Auracast, synthetic scan, log-distance RSSI→distance, LE Secure Connections vs legacy pairing assessment — Just Works flagged WEAK, bonding store), 3D 8K cinematic camera (7680×4320 / 8192×4320, 24/30/60/120 fps, stereo interaxial + convergence + depth budget, FOV/framing math, RAW/LOG/HDR10/HLG pipelines, storage estimator, RAW+JPEG photo bursts, gimbal/IBIS/EIS modes, per-body capture plans)

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
8. **Google Earth layer** — `python main.py earth` lists all 30 HQs by region with coordinates; `python main.py kml --out acd-quantum.kml` exports a Google Earth file with 30 placemarks; `python main.py distance --body-a NIST --body-b ETSI` computes the great-circle distance (Gaithersburg → Sophia Antipolis ≈ 6,734 km).
9. **Argon 4 DECIDER** — `python main.py decide --algos RSA-2048,AES-256` runs MAP (scan) → MODEL (readiness) → STRESS (negative controls: an attempt to flip RSA-2048 to "safe" and an attempt to raise the score are both rejected) → DECIDE (GO / CONDITIONAL GO / NO-GO + required actions), sealed with a sha256 trace hash. It signs off every migration plan and every HNDL verdict, and it can only ever tighten.
10. **SIx Neural Core run cycle** — `python main.py six` drives a full run through the core: LISTENING = inventory intake, THINKING = the Argon DECIDE pipeline, RESPONDING = plan/report output, LEARNING = append the run to the hash-chained audit ledger. `python main.py ledger` shows the chain and verifies it — mutate any entry and verification fails.
11. **Docker image recommendations** — `python main.py images` prints the full fleet catalog; `python main.py recommend --topic QRNG` ranks images per branch/topic (QRNG → quantumrandom-lab first; QKD → quantumrepeater-lab, bellpair-factory; PQC → quantumshor-lab, magicstate-lab); `python main.py compose --topic QKD` prints a ready docker-compose snippet.
12. **Street View layer** — `python main.py streetview` prints the panorama table for all 30 bodies (deterministic pano id, HQ coordinates, default POV heading = bearing toward the nearest neighbouring body, pitch 10, status OK); `python main.py streetview NIST` prints one body's full panorama data — links to its two nearest neighbours with real bearing headings, tiles spec, image date, validated options, and the honest motion-tracking note (real device motion tracking needs an HTTPS browser page; this layer models the option flags). `python main.py streetview --html --out streetview.html` generates a standalone page that uses the real Maps JavaScript API exactly as documented: `StreetViewService.getPanorama` with radius 50 + outdoor source, OK / not-found handling, and a picker covering all 30 bodies.
13. **Perfect Map layer** — `python main.py map` prints the map summary: 30 ACD-labelled markers grouped by region, overall and per-region bounds fits with suggested zooms, and the KML layer URL. `python main.py map --html --out map.html` generates the perfect-merge page: a `google.maps.Map` with every marker + InfoWindow, map-type switcher and all controls, the KML layer on the repo's own `earth/ACD-QUANTUM.kml`, and a linked Street View panel — click a marker and that body's panorama opens. Both HTML generators carry only the `YOUR_API_KEY` placeholder; add your own Google Maps key (kept under the name `GOOGLE_MAPS_API_KEY`) to use them live.
14. **Media + sensing layer** — `python main.py voice "ACD scan RSA-2048 and AES-256"` parses a transcript through the SIx states (LISTENING → THINKING → RESPONDING): wake phrase detected, intent `scan`, algorithm slots extracted, confidence scored; unknown commands return a labelled no-match. `python main.py speaker` lists the TTS presets and renders the Argon verdict as an SSML-like speech plan (`--say "..."` plans any text, with rate/pitch/volume clamped). `python main.py audio --out tone.wav` generates a 440 Hz test tone and analyses it (16 kHz mono WAV, RMS ≈ 0.354, peak 0.5, duration 1.0 s) against the codec model and loudness targets. `python main.py bluetooth` prints the labelled synthetic scan (5 devices, RSSI → distance) and the pairing assessment — Just Works / legacy PIN flagged **WEAK** (no MITM protection), Numeric Comparison / Passkey / OOB **STRONG**. `python main.py camera` prints the 3D 8K spec and storage table (8K DCI 24 fps: RAW ≈ 18,345.89 GB/hour vs H.265 ≈ 458.64 GB/hour); `python main.py camera --plan NIST` builds a capture plan for filming NIST HQ from its Earth coordinates and Street View pano id. All of it is models/specs/plans — no microphone, speaker, radio or camera hardware is touched.
15. **Monad chain layer** — `python main.py monad` prints the chain profile (mainnet 143 / testnet 10143, MON token, performance catalog) and the recommended-features catalog, all status `merged`. `python main.py monad-tps` runs the deterministic throughput simulation at 300 ms blocks (~3,000 tx/block at the 10,000 TPS ceiling; targets above the ceiling are flagged). `python main.py monad-parallel` simulates optimistic parallel execution — a conflicting batch re-executes and still beats serial (x2.0), a disjoint batch runs clean (x4.0). `python main.py monad-risk <address>` audits an EVM account: ECDSA flagged quantum-vulnerable by the scanner, exposure class, contract audit checklist, and the Argon 4 chain verdict (NO-GO on exposed keys). `python main.py monad-plan` prints the 5-phase PQC migration path for chain users. Voice routes too: "ACD monad tps", "check monad". All offline — no live RPC, no keys, no real transactions.
16. **Knowledge layer (Merge 9)** — `python main.py aitools` prints the 13-tool catalog with each tool's cyber domain(s); `python main.py codes` prints all 94 prompt codes (14 Claude + 80 Gemini, duplicates and partially-visible entries flagged honestly); `python main.py glossary` prints the 18-term AI glossary (`python main.py glossary rag` defines one term); `python main.py career` prints the 15-layer career stack by @hacktanic; `python main.py cybermap` prints the 14 real cyber domains with their tools; `python main.py knowledge` prints the unified Merge 9 summary — counts (13 + 14 + 80 + 18 + 15 + 14 = 154 entries) and both cross-references (tool → domains, domain → tools). Voice routes too: "ACD ai tools", "ACD glossary", "ACD career", "ACD knowledge". Catalog data only — no live vendor calls.
17. **Self-checks** — every run of the demo ends with the built-in verification suite, printing `CHECKS 123/123`.

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
    B -->|demo / checks| M[Run all + self-checks] --> N[CHECKS 105/105]
```

### Flowchart — merged flow (SIx core + Argon 4 + Earth + fleet)

```mermaid
flowchart LR
    A[SIx Core: IDLE] --> B[LISTENING<br/>inventory intake]
    B --> C[THINKING<br/>Argon 4: MAP - MODEL - STRESS - DECIDE]
    C --> D{DECIDE verdict}
    D -->|NO-GO / CONDITIONAL| E[Required actions<br/>tighten-only]
    D -->|GO| F[RESPONDING<br/>plan / report output]
    E --> F
    F --> G[LEARNING<br/>hash-chained audit ledger]
    G --> A
    C -.-> H[Google Earth layer<br/>30 HQs - KML - distances]
    F -.-> I[Docker fleet<br/>recommend / compose]
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
10. Self-verifying: every demo run ends with `CHECKS 105/105`.

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

## 🐳 Recommended Quantum Docker Images

Darion's own published quantum fleet on Docker Hub, under `credkellar/` — catalog snapshot **Nov 2026** (fleet verified live 2026-11-17: 37 images, 2,262 pulls; per-image pull counts are not embedded, except superconductor-lab noted as the top fleet puller on that check). ACD-Quantum recommends from this fleet by branch or topic: `python main.py recommend --topic PQC|QKD|QRNG|AGILITY|HNDL`, and `python main.py compose --topic QKD` prints a docker-compose snippet for the top picks.

| Image | Category | Pull |
|---|---|---|
| Superconductor-Lab | Hardware simulation | `docker pull credkellar/superconductor-lab:latest` — top fleet puller (150 pulls, Nov 17 check) |
| QuantumAnnealer-Lab | Optimisation | `docker pull credkellar/quantumannealer-lab:latest` |
| QuantumSensor-Lab | Sensing | `docker pull credkellar/quantumsensor-lab:latest` |
| QuantumRandom-Lab | Randomness | `docker pull credkellar/quantumrandom-lab:latest` |
| QuantumHall-Lab | Condensed matter simulation | `docker pull credkellar/quantumhall-lab:latest` |
| LevitDock-X | Physics / levitation | `docker pull credkellar/levitdock-x:latest` |
| NanoBits-Q | Nanotech simulation | `docker pull credkellar/nanobits-q:latest` |
| MagChip-Q | Quantum hardware | `docker pull credkellar/magchip-q:latest` |
| QEC-Fortress | Quantum error correction | `docker pull credkellar/qec-fortress:latest` |
| BellPair-Factory | Entanglement / networking | `docker pull credkellar/bellpair-factory:latest` |
| TimeCrystal-Q | Condensed matter simulation | `docker pull credkellar/timecrystal-q:latest` |
| QuantumRepeater-Lab | Entanglement / networking | `docker pull credkellar/quantumrepeater-lab:latest` |
| TopologicalQubit-Lab | Quantum error correction | `docker pull credkellar/topologicalqubit-lab:latest` |
| QuantumShor-Lab | Cryptography / security | `docker pull credkellar/quantumshor-lab:latest` |
| QuantumField-Lab | Field simulation | `docker pull credkellar/quantumfield-lab:latest` |
| BosonSampling-Lab | Photonic sampling | `docker pull credkellar/bosonsampling-lab:latest` |
| Wormhole-Lab | Quantum gravity simulation | `docker pull credkellar/wormhole-lab:latest` |
| GravWave-Lab | Sensing | `docker pull credkellar/gravwave-lab:latest` |
| AnalogueGravity-Lab | Quantum gravity simulation | `docker pull credkellar/analoguegravity-lab:latest` |
| QuantumScars-Lab | Many-body simulation | `docker pull credkellar/quantumscars-lab:latest` |
| MagicState-Lab | Quantum error correction | `docker pull credkellar/magicstate-lab:latest` |
| Superfluid-Lab | Condensed matter simulation | `docker pull credkellar/superfluid-lab:latest` |
| KibbleZurek-Lab | Phase transitions | `docker pull credkellar/kibblezurek-lab:latest` |
| TopologicalInsulator-Lab | Materials simulation | `docker pull credkellar/topologicalinsulator-lab:latest` |
| QuantumThermodynamics-Lab | Thermodynamics | `docker pull credkellar/quantumthermodynamics-lab:latest` |
| QuantumTunnel-X | Tunnelling simulation | `docker pull credkellar/quantumtunnel-x:latest` |
| CasimirX | Quantum vacuum physics | `docker pull credkellar/casimirx:latest` |
| AcousticLev-Lab | Physics / levitation | `docker pull credkellar/acousticlev-lab:latest` |
| ACD-Quantum | Cryptography / security | `docker pull credkellar/acd-quantum:latest` |

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
python3 main.py earth
python3 main.py kml --out acd-quantum.kml
python3 main.py distance --body-a NIST --body-b ETSI
python3 main.py decide --algos RSA-2048,AES-256
python3 main.py six
python3 main.py ledger
python3 main.py images
python3 main.py recommend --topic QRNG
python3 main.py compose --topic QKD
python3 main.py streetview
python3 main.py streetview NIST
python3 main.py streetview --html --out streetview.html
python3 main.py map
python3 main.py map --html --out map.html
python3 main.py voice "ACD scan RSA-2048 and AES-256"
python3 main.py voice --demo
python3 main.py speaker
python3 main.py speaker --say "ACD Quantum is ready."
python3 main.py audio --out tone.wav
python3 main.py bluetooth
python3 main.py camera
python3 main.py camera --plan NIST
python3 main.py monad
python3 main.py monad --tps
python3 main.py monad-tps
python3 main.py monad-parallel
python3 main.py monad-risk 0x1234567890AbcdEF1234567890aBcdef12345678
python3 main.py monad-plan
python3 main.py aitools
python3 main.py codes
python3 main.py glossary
python3 main.py glossary rag
python3 main.py career
python3 main.py cybermap
python3 main.py knowledge
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
├── main.py                  # ONE file: tree, scanner, plan, BB84, QRNG, HNDL, Earth/KML, Argon 4, SIx core, fleet, Street View, Perfect Map, media layer (voice/speaker/audio/Bluetooth/8K camera), Monad chain layer, checks, CLI
├── README.md                # This file
├── ABOUT.txt                # Exactly-350-character repo About description
├── tests/
│   └── test_main.py         # pytest suite (96 tests)
├── assets/
│   └── cover.png            # Cover image, 2736x912 (official remix of Darion's own art)
├── conftest.py              # Puts the repo root on sys.path for pytest imports
├── Dockerfile               # python:3.12-slim, runs the demo + checks
├── requirements.txt         # Runtime: stdlib only (comment file)
└── .gitignore
```

## License

MIT
