#!/usr/bin/env python3
"""
ACD-Quantum - Quantum Cyber Security Structure Tree
Top 15 National (USA) + Top 15 International.

ONE main.py, pure Python stdlib, zero dependencies, offline, deterministic.

Features:
  1. Full structure tree data + printable tree (national / international)
  2. Crypto inventory scanner (quantum-vulnerable vs CNSA-ok vs PQC-safe)
  3. PQC migration readiness scoring + phased migration plan generator
  4. BB84 QKD simulation with eavesdropper detection via QBER (seeded)
  5. QRNG simulation via SHA-256 counter expansion (labelled simulation)
  6. HNDL risk calculator (Mosca inequality: shelf-life + migration > CRQC time)
  7. Self-checks runner printing CHECKS x/x

Honest limits: this is an educational / planning tool. The QKD and QRNG
modules are classical simulations of quantum protocols - they do not use
real quantum hardware, do not produce true quantum randomness, and do not
by themselves make any real system quantum-safe. Real migration must use
validated implementations of the NIST standards.
"""

import argparse
import hashlib
import random
import sys

# --------------------------------------------------------------------------
# 1. Structure tree data
# --------------------------------------------------------------------------

BRANCHES = [
    {"id": "PQC", "name": "Post-Quantum Cryptography",
     "detail": "NIST-standardised algorithms replacing RSA/ECC: ML-KEM, ML-DSA, SLH-DSA, HQC."},
    {"id": "QKD", "name": "Quantum Key Distribution",
     "detail": "Physics-based key exchange (BB84, E91); eavesdropping shows up as QBER."},
    {"id": "QRNG", "name": "Quantum Random Number Generation",
     "detail": "Randomness from quantum processes; simulated here, labelled as simulation."},
    {"id": "AGILITY", "name": "Crypto Discovery / Inventory / Agility",
     "detail": "Find every algorithm/key/certificate in use, then swap algorithms without rewrites."},
    {"id": "HNDL", "name": "Harvest-Now-Decrypt-Later Defense",
     "detail": "Attackers store ciphertext today to decrypt with a future CRQC; prioritise long-life data."},
]

NATIONAL_TOP15 = [
    {"rank": 1, "name": "White House / ONCD", "category": "Policy / Command",
     "role": "NSM-10 (2022) sets US policy and the 2035 mitigation goal."},
    {"rank": 2, "name": "OMB", "category": "Policy / Command",
     "role": "Binding federal migration memoranda; agencies must inventory cryptography."},
    {"rank": 3, "name": "NQCO", "category": "Policy / Command",
     "role": "National Quantum Coordination Office; coordinates federal quantum work."},
    {"rank": 4, "name": "NIST", "category": "Standards",
     "role": "FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA, plus HQC selected."},
    {"rank": 5, "name": "NSA", "category": "Standards",
     "role": "CNSA 2.0 suite for National Security Systems; National Manager for NSS."},
    {"rank": 6, "name": "NCCoE", "category": "Standards",
     "role": "NIST National Cybersecurity Center of Excellence; PQC migration practice guides."},
    {"rank": 7, "name": "CISA", "category": "Defense / Enforcement",
     "role": "Leads PQC migration guidance for critical infrastructure."},
    {"rank": 8, "name": "DHS", "category": "Defense / Enforcement",
     "role": "Department-wide post-quantum transition preparation."},
    {"rank": 9, "name": "DoD / DISA", "category": "Defense / Enforcement",
     "role": "Military systems, identity cards and platforms move to CNSA 2.0."},
    {"rank": 10, "name": "FBI / Intelligence Community", "category": "Defense / Enforcement",
     "role": "Quantum threat intelligence and counter-intelligence."},
    {"rank": 11, "name": "U.S. Department of the Treasury", "category": "Sectors / Oversight",
     "role": "Financial-services sector risk management for quantum threats."},
    {"rank": 12, "name": "DOE / National Labs", "category": "Sectors / Oversight",
     "role": "Energy sector and national-lab QKD / quantum networking testbeds."},
    {"rank": 13, "name": "GSA / FedRAMP", "category": "Sectors / Oversight",
     "role": "Federal procurement and cloud authorisation require PQC readiness."},
    {"rank": 14, "name": "GAO", "category": "Sectors / Oversight",
     "role": "Government Accountability Office; oversight of strategy and migration cost."},
    {"rank": 15, "name": "US Industry Leaders", "category": "Industry",
     "role": "Microsoft, Google, IBM, Cisco, Cloudflare, SandboxAQ, QuSecure, Entrust, Keyfactor, DigiCert."},
]

INTERNATIONAL_TOP15 = [
    {"rank": 1, "name": "ISO/IEC JTC 1 SC 27", "category": "Global Standards",
     "role": "International cryptographic standards; ISO/IEC 23837 QKD evaluation."},
    {"rank": 2, "name": "ITU-T SG17 / SG13", "category": "Global Standards",
     "role": "UN telecom security: X.1710 QKD security framework, Y.3800 QKD networks."},
    {"rank": 3, "name": "IETF", "category": "Global Standards",
     "role": "Embeds PQC into TLS, IKEv2, SSH and X.509 / CMS protocols."},
    {"rank": 4, "name": "ETSI", "category": "Global Standards",
     "role": "Europe: TR 103 619 migration strategies, TS 103 744 hybrid key exchange."},
    {"rank": 5, "name": "IEEE", "category": "Global Standards",
     "role": "Quantum computing and QKD standardisation work."},
    {"rank": 6, "name": "ENISA / EU Commission", "category": "Regional Authorities",
     "role": "EU coordinated implementation roadmap for PQC transition."},
    {"rank": 7, "name": "UK NCSC", "category": "Regional Authorities",
     "role": "UK National Cyber Security Centre PQC migration guidance and timelines."},
    {"rank": 8, "name": "Germany BSI", "category": "Regional Authorities",
     "role": "TR-02102 cryptographic recommendations, hybrid PQC guidance."},
    {"rank": 9, "name": "France ANSSI", "category": "Regional Authorities",
     "role": "Early hybrid-PQC position papers and national guidance."},
    {"rank": 10, "name": "Canada CCCS / CSE", "category": "Regional Authorities",
     "role": "ITSM.40.001 roadmap for Government of Canada PQC migration."},
    {"rank": 11, "name": "Australia ASD / ACSC", "category": "Regional Authorities",
     "role": "Planning guidance for post-quantum cryptography transition."},
    {"rank": 12, "name": "Japan CRYPTREC / IPA", "category": "Regional Authorities",
     "role": "Japanese cryptographic algorithm evaluation and promotion."},
    {"rank": 13, "name": "South Korea KISA / NSR", "category": "Regional Authorities",
     "role": "Korean PQC competition and national transition programme."},
    {"rank": 14, "name": "China CCSA / MIIT", "category": "Regional Authorities",
     "role": "Chinese QKD networks and quantum communications standardisation."},
    {"rank": 15, "name": "GSMA / FS-ISAC + Global Industry", "category": "Sector / Industry",
     "role": "Telco and finance sector guidance; PQShield, ID Quantique, Arqit, Toshiba, QNu Labs, Thales."},
]


def get_branches():
    return list(BRANCHES)


def get_national():
    return list(NATIONAL_TOP15)


def get_international():
    return list(INTERNATIONAL_TOP15)


def render_tree(scope="all"):
    """Return a printable text tree for scope: national, international or all."""
    lines = ["ACD-Quantum - Quantum Cyber Security Structure Tree", ""]
    lines.append("Branches:")
    for i, b in enumerate(BRANCHES):
        prefix = "  \\-- " if i == len(BRANCHES) - 1 else "  |-- "
        lines.append(f"{prefix}{b['id']}: {b['name']} - {b['detail']}")
    lines.append("")
    if scope in ("all", "national"):
        lines.append("TOP 15 NATIONAL (USA)")
        for item in NATIONAL_TOP15:
            lines.append(f"  {item['rank']:>2}. [{item['category']}] {item['name']} - {item['role']}")
        lines.append("")
    if scope in ("all", "international"):
        lines.append("TOP 15 INTERNATIONAL")
        for item in INTERNATIONAL_TOP15:
            lines.append(f"  {item['rank']:>2}. [{item['category']}] {item['name']} - {item['role']}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------------
# 2. Crypto inventory scanner
# --------------------------------------------------------------------------

# status: vulnerable | weakened | cnsa_ok | pqc_safe | broken | unknown
_ALGO_TABLE = {
    "rsa": ("vulnerable", "Shor breaks RSA; replace with ML-KEM / ML-DSA."),
    "rsa-1024": ("vulnerable", "Shor breaks RSA; also too small classically."),
    "rsa-2048": ("vulnerable", "Shor breaks RSA-2048 on a CRQC."),
    "rsa-3072": ("vulnerable", "Shor breaks RSA-3072 on a CRQC."),
    "rsa-4096": ("vulnerable", "Shor breaks RSA-4096 on a CRQC."),
    "ecc": ("vulnerable", "Shor breaks elliptic-curve cryptography."),
    "ecdsa": ("vulnerable", "Shor breaks ECDSA signatures."),
    "ecdh": ("vulnerable", "Shor breaks ECDH key exchange."),
    "p-256": ("vulnerable", "Shor breaks NIST P-256."),
    "p-384": ("vulnerable", "Shor breaks NIST P-384; CNSA 1.0 only, not CNSA 2.0."),
    "p-521": ("vulnerable", "Shor breaks NIST P-521."),
    "x25519": ("vulnerable", "Shor breaks X25519 key exchange."),
    "dh": ("vulnerable", "Shor breaks finite-field Diffie-Hellman."),
    "diffie-hellman": ("vulnerable", "Shor breaks finite-field Diffie-Hellman."),
    "dsa": ("vulnerable", "Shor breaks DSA."),
    "elgamal": ("vulnerable", "Shor breaks ElGamal."),
    "md5": ("broken", "MD5 is classically broken; do not use."),
    "sha-1": ("broken", "SHA-1 is classically broken; do not use."),
    "sha1": ("broken", "SHA-1 is classically broken; do not use."),
    "des": ("broken", "DES is classically broken (56-bit)."),
    "3des": ("weakened", "3DES is deprecated and weak; replace with AES-256."),
    "aes-128": ("weakened", "Grover halves effective strength to ~64 bits; prefer AES-256."),
    "aes-192": ("weakened", "Grover reduces effective strength; prefer AES-256."),
    "sha-256": ("weakened", "Grover reduces preimage strength; SHA-384 preferred for CNSA."),
    "sha256": ("weakened", "Grover reduces preimage strength; SHA-384 preferred for CNSA."),
    "aes-256": ("cnsa_ok", "CNSA 2.0 approved symmetric cipher."),
    "aes256": ("cnsa_ok", "CNSA 2.0 approved symmetric cipher."),
    "sha-384": ("cnsa_ok", "CNSA 2.0 approved hash."),
    "sha384": ("cnsa_ok", "CNSA 2.0 approved hash."),
    "sha-512": ("cnsa_ok", "CNSA 2.0 approved hash."),
    "sha512": ("cnsa_ok", "CNSA 2.0 approved hash."),
    "chacha20": ("cnsa_ok", "Symmetric cipher; Grover-only impact, use 256-bit key."),
    "ml-kem": ("pqc_safe", "FIPS 203 post-quantum key encapsulation."),
    "ml-kem-768": ("pqc_safe", "FIPS 203 post-quantum key encapsulation."),
    "ml-kem-1024": ("pqc_safe", "FIPS 203, CNSA 2.0 preferred parameter set."),
    "kyber": ("pqc_safe", "Kyber is the algorithm standardised as ML-KEM (FIPS 203)."),
    "kyber1024": ("pqc_safe", "Kyber1024 is the basis for ML-KEM-1024 (FIPS 203)."),
    "ml-dsa": ("pqc_safe", "FIPS 204 post-quantum signatures."),
    "ml-dsa-87": ("pqc_safe", "FIPS 204, CNSA 2.0 preferred parameter set."),
    "dilithium": ("pqc_safe", "Dilithium is the algorithm standardised as ML-DSA (FIPS 204)."),
    "slh-dsa": ("pqc_safe", "FIPS 205 hash-based post-quantum signatures."),
    "sphincs+": ("pqc_safe", "SPHINCS+ is the scheme standardised as SLH-DSA (FIPS 205)."),
    "hqc": ("pqc_safe", "HQC selected by NIST as an additional KEM (code-based)."),
    "falcon": ("pqc_safe", "Falcon / FN-DSA post-quantum signatures (forthcoming standard)."),
    "lms": ("pqc_safe", "Stateful hash-based signatures, SP 800-208, CNSA 2.0 for firmware."),
    "xmss": ("pqc_safe", "Stateful hash-based signatures, SP 800-208, CNSA 2.0 for firmware."),
}

_SAFE_STATUSES = {"cnsa_ok", "pqc_safe"}
_BAD_STATUSES = {"vulnerable", "broken"}


def _normalise(name):
    return str(name).strip().lower().replace("_", "-").replace(" ", "")


# Re-normalise keys consistently (keys above contain hyphens/spaces variants).
_ALGO_LOOKUP = {}
for _k, _v in _ALGO_TABLE.items():
    _ALGO_LOOKUP[_normalise(_k)] = (_k, _v[0], _v[1])


def classify_algorithm(name):
    """Classify one algorithm name. Returns dict with name, status, detail."""
    key = _normalise(name)
    if key in _ALGO_LOOKUP:
        canon, status, detail = _ALGO_LOOKUP[key]
        return {"name": str(name), "canonical": canon, "status": status, "detail": detail}
    # Prefix fallbacks for parameterised names, e.g. rsa-8192, ml-kem-512.
    for prefix in ("rsa-", "ml-kem-", "ml-dsa-", "aes-", "sha-"):
        if key.startswith(prefix):
            base = prefix.rstrip("-")
            if base in _ALGO_LOOKUP:
                canon, status, detail = _ALGO_LOOKUP[base]
                return {"name": str(name), "canonical": canon, "status": status, "detail": detail}
    return {"name": str(name), "canonical": None, "status": "unknown",
            "detail": "Not in the ACD-Quantum table; inventory and assess manually."}


def scan_inventory(items):
    """Scan a list of algorithm names. Returns findings + summary counts."""
    findings = [classify_algorithm(x) for x in items]
    summary = {"total": len(findings), "vulnerable": 0, "broken": 0, "weakened": 0,
               "cnsa_ok": 0, "pqc_safe": 0, "unknown": 0}
    for f in findings:
        summary[f["status"]] = summary.get(f["status"], 0) + 1
    summary["safe"] = summary["cnsa_ok"] + summary["pqc_safe"]
    summary["at_risk"] = summary["vulnerable"] + summary["broken"]
    return {"findings": findings, "summary": summary}


# --------------------------------------------------------------------------
# 3. Migration readiness + phased plan
# --------------------------------------------------------------------------

def migration_readiness(items, has_inventory=True, has_agility=False, hndl_years_left=None):
    """
    Score 0-100. Weighted: 60% safe share of inventory, 15% inventory done,
    15% crypto-agility, 10% HNDL headroom (if supplied).
    Returns dict with score, grade, summary.
    """
    scan = scan_inventory(items)
    total = scan["summary"]["total"]
    safe_share = (scan["summary"]["safe"] / total) if total else 0.0
    score = 60.0 * safe_share
    if has_inventory:
        score += 15.0
    if has_agility:
        score += 15.0
    if hndl_years_left is None:
        score += 5.0  # neutral partial credit when unassessed
    elif hndl_years_left > 0:
        score += 10.0
    score = round(max(0.0, min(100.0, score)), 1)
    if score >= 85:
        grade = "READY"
    elif score >= 65:
        grade = "ADVANCED"
    elif score >= 40:
        grade = "IN PROGRESS"
    elif score >= 20:
        grade = "EARLY"
    else:
        grade = "AT RISK"
    return {"score": score, "grade": grade, "summary": scan["summary"],
            "safe_share": round(safe_share, 3)}


def generate_migration_plan(items, org="Organisation"):
    """Return a phased (0-4) migration plan tailored to the inventory findings."""
    scan = scan_inventory(items)
    bad = [f["name"] for f in scan["findings"] if f["status"] in _BAD_STATUSES]
    weak = [f["name"] for f in scan["findings"] if f["status"] == "weakened"]
    unknown = [f["name"] for f in scan["findings"] if f["status"] == "unknown"]
    plan = [
        {"phase": 0, "name": "Discover", "timeline": "Months 0-3",
         "actions": [f"{org}: complete cryptographic inventory (CBOM).",
                     "Locate all certificates, keys, libraries and protocols."] + 
                    ([f"Manually assess unknown items: {', '.join(unknown)}."] if unknown else [])},
        {"phase": 1, "name": "Prioritise (HNDL first)", "timeline": "Months 3-6",
         "actions": ["Rank data by shelf-life; longest-life data migrates first.",
                     "Run the HNDL / Mosca calculation for each critical system."]},
        {"phase": 2, "name": "Replace vulnerable public-key", "timeline": "Months 6-18",
         "actions": ([f"Replace quantum-vulnerable: {', '.join(bad)} with ML-KEM for key "
                      "establishment and ML-DSA / SLH-DSA for signatures."] if bad else
                     ["No quantum-vulnerable public-key algorithms found; keep monitoring."]),
         },
        {"phase": 3, "name": "Strengthen symmetric + hybrid", "timeline": "Months 12-24",
         "actions": ([f"Upgrade weakened items: {', '.join(weak)} to AES-256 / SHA-384."] if weak else
                     ["Symmetric suite already at AES-256 / SHA-384 level."]) +
                    ["Deploy hybrid (classical + PQC) key exchange during transition."]},
        {"phase": 4, "name": "Agility + verify", "timeline": "Months 18-36",
         "actions": ["Make algorithms configurable (crypto-agility); no hard-coded suites.",
                     "Re-scan inventory, track CNSA 2.0 / FIPS 203-205 compliance, repeat yearly."]},
    ]
    return plan


# --------------------------------------------------------------------------
# 4. BB84 QKD simulation
# --------------------------------------------------------------------------

def simulate_bb84(n_bits=256, eve=False, seed=42, qber_threshold=0.11):
    """
    Deterministic BB84 simulation (classical simulation of the protocol).
    Alice sends qubits in random bases; Bob measures in random bases.
    If eve=True, Eve does intercept-resend, which raises QBER to ~25%.
    QBER is measured on the sifted key; above threshold the key is aborted.
    """
    if n_bits <= 0:
        raise ValueError("n_bits must be positive")
    rng = random.Random(seed)
    alice_bits = [rng.randint(0, 1) for _ in range(n_bits)]
    alice_bases = [rng.randint(0, 1) for _ in range(n_bits)]
    bob_bases = [rng.randint(0, 1) for _ in range(n_bits)]

    received = []
    for i in range(n_bits):
        bit, basis = alice_bits[i], alice_bases[i]
        if eve:
            eve_basis = rng.randint(0, 1)
            if eve_basis != basis:
                bit = rng.randint(0, 1)  # Eve's wrong-basis result is random
            basis = eve_basis  # Eve resends in her own basis
        if bob_bases[i] != basis:
            received.append(rng.randint(0, 1))
        else:
            received.append(bit)

    sifted_alice, sifted_bob = [], []
    for i in range(n_bits):
        if alice_bases[i] == bob_bases[i]:
            sifted_alice.append(alice_bits[i])
            sifted_bob.append(received[i])
    errors = sum(1 for a, b in zip(sifted_alice, sifted_bob) if a != b)
    qber = (errors / len(sifted_alice)) if sifted_alice else 0.0
    detected = bool(eve and qber > qber_threshold)
    aborted = qber > qber_threshold
    return {
        "n_bits": n_bits, "eve_present": bool(eve), "seed": seed,
        "sifted_length": len(sifted_alice), "errors": errors,
        "qber": round(qber, 4), "qber_threshold": qber_threshold,
        "eavesdropper_detected": detected, "key_aborted": aborted,
        "sifted_key": "".join(str(b) for b in ([] if aborted else sifted_bob)),
        "note": "Classical simulation of BB84 - no real quantum hardware used.",
    }


# --------------------------------------------------------------------------
# 5. QRNG simulation (SHA-256 counter expansion)
# --------------------------------------------------------------------------

def qrng_bytes(n_bytes, seed="acd-quantum-default"):
    """
    SIMULATION ONLY: deterministic bytes from SHA-256(seed || counter).
    This mimics the interface of a QRNG for demos/tests. It is NOT true
    quantum randomness and must not be used as a real entropy source.
    """
    if n_bytes < 0:
        raise ValueError("n_bytes must be >= 0")
    out = bytearray()
    counter = 0
    seed_bytes = str(seed).encode("utf-8")
    while len(out) < n_bytes:
        out.extend(hashlib.sha256(seed_bytes + counter.to_bytes(8, "big")).digest())
        counter += 1
    return bytes(out[:n_bytes])


def qrng_hex(n_bytes, seed="acd-quantum-default"):
    return qrng_bytes(n_bytes, seed=seed).hex()


def qrng_label():
    return "simulation - SHA-256 counter expansion, NOT true quantum randomness"


# --------------------------------------------------------------------------
# 6. HNDL risk calculator (Mosca inequality)
# --------------------------------------------------------------------------

def hndl_risk(shelf_life_years, migration_years, crqc_years):
    """
    Mosca inequality: if X + Y > Z you are already at risk, where
      X = data shelf-life (years secrecy must last)
      Y = migration time (years to become quantum-safe)
      Z = years until a cryptanalytically relevant quantum computer
    """
    x, y, z = float(shelf_life_years), float(migration_years), float(crqc_years)
    total = x + y
    at_risk = total > z
    margin = round(z - total, 2)
    if at_risk and margin < -5:
        level = "CRITICAL"
    elif at_risk:
        level = "HIGH"
    elif margin <= 2:
        level = "MEDIUM"
    else:
        level = "LOW"
    return {"shelf_life_years": x, "migration_years": y, "crqc_years": z,
            "x_plus_y": total, "margin_years": margin, "at_risk": at_risk,
            "risk_level": level,
            "rule": "Mosca: risk if shelf-life + migration time > years to CRQC (X + Y > Z)"}


# --------------------------------------------------------------------------
# 7. Self-checks
# --------------------------------------------------------------------------

def run_checks():
    checks = []

    def check(name, ok):
        checks.append((name, bool(ok)))

    check("national list has exactly 15 entries", len(NATIONAL_TOP15) == 15)
    check("international list has exactly 15 entries", len(INTERNATIONAL_TOP15) == 15)
    check("national ranks are 1..15", [x["rank"] for x in NATIONAL_TOP15] == list(range(1, 16)))
    check("international ranks are 1..15", [x["rank"] for x in INTERNATIONAL_TOP15] == list(range(1, 16)))
    check("five branches defined", len(BRANCHES) == 5)
    check("NIST entry names FIPS 203/204/205",
          any("FIPS 203" in x["role"] and "FIPS 205" in x["role"] for x in NATIONAL_TOP15))
    check("tree renders national and international",
          "TOP 15 NATIONAL" in render_tree() and "TOP 15 INTERNATIONAL" in render_tree())
    check("RSA-2048 classified vulnerable", classify_algorithm("RSA-2048")["status"] == "vulnerable")
    check("ECDSA classified vulnerable", classify_algorithm("ECDSA")["status"] == "vulnerable")
    check("AES-256 classified cnsa_ok", classify_algorithm("AES-256")["status"] == "cnsa_ok")
    check("SHA-384 classified cnsa_ok", classify_algorithm("SHA-384")["status"] == "cnsa_ok")
    check("ML-KEM-1024 classified pqc_safe", classify_algorithm("ML-KEM-1024")["status"] == "pqc_safe")
    check("unknown algorithm handled", classify_algorithm("ROT13")["status"] == "unknown")
    scan = scan_inventory(["RSA-2048", "AES-256", "ML-KEM-768"])
    check("inventory scan counts at-risk = 1", scan["summary"]["at_risk"] == 1)
    check("inventory scan counts safe = 2", scan["summary"]["safe"] == 2)
    ready = migration_readiness(["ML-KEM-1024", "ML-DSA-87", "AES-256"], has_inventory=True, has_agility=True)
    check("all-PQC inventory scores high (>=85)", ready["score"] >= 85)
    legacy = migration_readiness(["RSA-2048", "ECDSA"], has_inventory=False)
    check("all-legacy inventory scores low (<20)", legacy["score"] < 20)
    plan = generate_migration_plan(["RSA-2048", "AES-128"])
    check("migration plan has 5 phases", len(plan) == 5 and [p["phase"] for p in plan] == [0, 1, 2, 3, 4])
    clean = simulate_bb84(512, eve=False, seed=7)
    check("BB84 without Eve: QBER below threshold", clean["qber"] <= clean["qber_threshold"])
    check("BB84 without Eve: key not aborted", clean["key_aborted"] is False and len(clean["sifted_key"]) > 100)
    eve_run = simulate_bb84(512, eve=True, seed=7)
    check("BB84 with Eve: QBER above threshold", eve_run["qber"] > eve_run["qber_threshold"])
    check("BB84 with Eve: detected and aborted", eve_run["eavesdropper_detected"] and eve_run["key_aborted"])
    check("BB84 is deterministic for a seed", simulate_bb84(128, seed=3) == simulate_bb84(128, seed=3))
    check("QRNG returns requested length", len(qrng_bytes(64, seed="t")) == 64)
    check("QRNG is deterministic for a seed", qrng_bytes(32, seed="a") == qrng_bytes(32, seed="a"))
    check("QRNG differs across seeds", qrng_bytes(32, seed="a") != qrng_bytes(32, seed="b"))
    check("QRNG labelled as simulation", "simulation" in qrng_label().lower())
    check("HNDL Mosca: 10+5 > 10 is at risk", hndl_risk(10, 5, 10)["at_risk"] is True)
    check("HNDL Mosca: 2+2 < 15 is not at risk", hndl_risk(2, 2, 15)["at_risk"] is False)
    check("HNDL Mosca margin computed", hndl_risk(2, 2, 15)["margin_years"] == 11.0)

    passed = sum(1 for _, ok in checks if ok)
    for name, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print(f"CHECKS {passed}/{len(checks)}")
    return passed == len(checks)


# --------------------------------------------------------------------------
# CLI / demo
# --------------------------------------------------------------------------

DEMO_INVENTORY = ["RSA-2048", "ECDSA", "ECDH", "AES-128", "SHA-256",
                  "AES-256", "SHA-384", "ML-KEM-768"]


def demo():
    print(render_tree())
    print("Crypto inventory scan (demo):", ", ".join(DEMO_INVENTORY))
    scan = scan_inventory(DEMO_INVENTORY)
    for f in scan["findings"]:
        print(f"  {f['name']:<14} {f['status']:<12} {f['detail']}")
    print("  Summary:", scan["summary"])
    print()
    ready = migration_readiness(DEMO_INVENTORY, has_inventory=True)
    print(f"Migration readiness: {ready['score']}/100 ({ready['grade']})")
    for step in generate_migration_plan(DEMO_INVENTORY, org="Example Org"):
        print(f"  Phase {step['phase']} - {step['name']} ({step['timeline']})")
        for action in step["actions"]:
            print(f"    - {action}")
    print()
    clean = simulate_bb84(256, eve=False, seed=42)
    eve_run = simulate_bb84(256, eve=True, seed=42)
    print(f"BB84 no Eve : sifted={clean['sifted_length']} QBER={clean['qber']} aborted={clean['key_aborted']}")
    print(f"BB84 Eve    : sifted={eve_run['sifted_length']} QBER={eve_run['qber']} "
          f"detected={eve_run['eavesdropper_detected']} aborted={eve_run['key_aborted']}")
    print(f"QRNG sample ({qrng_label()}): {qrng_hex(16, seed='demo')}")
    risk = hndl_risk(shelf_life_years=10, migration_years=4, crqc_years=12)
    print(f"HNDL example: X+Y={risk['x_plus_y']} vs Z={risk['crqc_years']} "
          f"-> at_risk={risk['at_risk']} ({risk['risk_level']})")
    print()
    return run_checks()


def main(argv=None):
    parser = argparse.ArgumentParser(description="ACD-Quantum - Quantum Cyber Security structure tree and tools")
    parser.add_argument("mode", nargs="?", default="demo",
                        choices=["demo", "tree", "checks", "scan", "plan", "qkd", "qrng", "hndl"])
    parser.add_argument("--scope", default="all", choices=["all", "national", "international"])
    parser.add_argument("--algos", default=",".join(DEMO_INVENTORY),
                        help="Comma-separated algorithm list for scan/plan")
    parser.add_argument("--eve", action="store_true", help="Add an eavesdropper to the QKD run")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--shelf-life", type=float, default=10)
    parser.add_argument("--migration", type=float, default=4)
    parser.add_argument("--crqc", type=float, default=12)
    args = parser.parse_args(argv)

    algos = [a.strip() for a in args.algos.split(",") if a.strip()]
    if args.mode == "tree":
        print(render_tree(args.scope), end="")
        return 0
    if args.mode == "checks":
        return 0 if run_checks() else 1
    if args.mode == "scan":
        scan = scan_inventory(algos)
        for f in scan["findings"]:
            print(f"{f['name']:<14} {f['status']:<12} {f['detail']}")
        print("Summary:", scan["summary"])
        return 0
    if args.mode == "plan":
        ready = migration_readiness(algos, has_inventory=True)
        print(f"Readiness: {ready['score']}/100 ({ready['grade']})")
        for step in generate_migration_plan(algos):
            print(f"Phase {step['phase']} - {step['name']} ({step['timeline']})")
            for action in step["actions"]:
                print(f"  - {action}")
        return 0
    if args.mode == "qkd":
        result = simulate_bb84(256, eve=args.eve, seed=args.seed)
        for k, v in result.items():
            print(f"{k}: {v}")
        return 0
    if args.mode == "qrng":
        print(qrng_label())
        print(qrng_hex(32, seed=str(args.seed)))
        return 0
    if args.mode == "hndl":
        result = hndl_risk(args.shelf_life, args.migration, args.crqc)
        for k, v in result.items():
            print(f"{k}: {v}")
        return 0
    return 0 if demo() else 1


if __name__ == "__main__":
    sys.exit(main())
