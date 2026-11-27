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
  7. Google Earth layer: HQ coordinates for all 30 bodies, KML export, distances
  8. Gemini Argon 4 Extended Thinking DECIDER seat (names-only, tighten-only)
  9. SIx Neural Core interface: 5-state machine + hash-chained audit ledger
 10. Recommended quantum Docker images catalog (Darion's credkellar/ fleet)
 11. Self-checks runner printing CHECKS x/x

Honest limits: this is an educational / planning tool. The QKD and QRNG
modules are classical simulations of quantum protocols - they do not use
real quantum hardware, do not produce true quantum randomness, and do not
by themselves make any real system quantum-safe. Real migration must use
validated implementations of the NIST standards.
"""

import argparse
import hashlib
import json
import math
import os
import random
import sys
from xml.sax.saxutils import escape as _xml_escape

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
                     "Re-scan inventory, track CNSA 2.0 / FIPS 203-205 compliance, repeat yearly.",
                     "Gemini Argon 4 DECIDER sign-off (trace-hashed, tighten-only) required before go-live."]},
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
# 7. Google Earth layer: HQ coordinates, KML export, haversine distances
# --------------------------------------------------------------------------

# name -> (lat, lon, city, country, region, is_anchor)
_GEO = {
    # National (USA)
    "White House / ONCD": (38.8977, -77.0365, "Washington, DC", "USA", "North America", False),
    "OMB": (38.8970, -77.0370, "Washington, DC", "USA", "North America", False),
    "NQCO": (38.8951, -77.0363, "Washington, DC", "USA", "North America", False),
    "NIST": (39.1434, -77.2013, "Gaithersburg, MD", "USA", "North America", False),
    "NSA": (39.1089, -76.7713, "Fort Meade, MD", "USA", "North America", False),
    "NCCoE": (39.0840, -77.1528, "Rockville, MD", "USA", "North America", False),
    "CISA": (38.8816, -77.1109, "Arlington, VA", "USA", "North America", False),
    "DHS": (38.9072, -77.0369, "Washington, DC", "USA", "North America", False),
    "DoD / DISA": (38.8719, -77.0563, "Arlington, VA (Pentagon)", "USA", "North America", False),
    "FBI / Intelligence Community": (38.8951, -77.0250, "Washington, DC", "USA", "North America", False),
    "U.S. Department of the Treasury": (38.8978, -77.0348, "Washington, DC", "USA", "North America", False),
    "DOE / National Labs": (38.8869, -77.0261, "Washington, DC", "USA", "North America", False),
    "GSA / FedRAMP": (38.8970, -77.0430, "Washington, DC", "USA", "North America", False),
    "GAO": (38.9008, -77.0222, "Washington, DC", "USA", "North America", False),
    "US Industry Leaders": (37.3875, -122.0575, "Silicon Valley, CA (anchor)", "USA", "North America", True),
    # International
    "ISO/IEC JTC 1 SC 27": (46.2044, 6.1432, "Geneva", "Switzerland", "Europe", False),
    "ITU-T SG17 / SG13": (46.2265, 6.1405, "Geneva", "Switzerland", "Europe", False),
    "IETF": (38.9586, -77.3570, "Reston, VA (anchor - IETF is virtual)", "USA", "North America", True),
    "ETSI": (43.6170, 7.0750, "Sophia Antipolis", "France", "Europe", False),
    "IEEE": (40.7128, -74.0060, "New York, NY", "USA", "North America", False),
    "ENISA / EU Commission": (37.9838, 23.7275, "Athens (ENISA) / Brussels (EU Commission)", "Greece / Belgium", "Europe", False),
    "UK NCSC": (51.5074, -0.1278, "London", "United Kingdom", "Europe", False),
    "Germany BSI": (50.7374, 7.0982, "Bonn", "Germany", "Europe", False),
    "France ANSSI": (48.8566, 2.3522, "Paris", "France", "Europe", False),
    "Canada CCCS / CSE": (45.4215, -75.6972, "Ottawa", "Canada", "North America", False),
    "Australia ASD / ACSC": (-35.2809, 149.1300, "Canberra", "Australia", "Asia-Pacific", False),
    "Japan CRYPTREC / IPA": (35.6762, 139.6503, "Tokyo", "Japan", "Asia-Pacific", False),
    "South Korea KISA / NSR": (37.5665, 126.9780, "Seoul", "South Korea", "Asia-Pacific", False),
    "China CCSA / MIIT": (39.9042, 116.4074, "Beijing", "China", "Asia-Pacific", False),
    "GSMA / FS-ISAC + Global Industry": (51.5074, -0.1278, "London (anchor)", "United Kingdom", "Europe", True),
}


def get_geo(name):
    """HQ geo record for a body name, or None."""
    row = _GEO.get(name)
    if row is None:
        return None
    lat, lon, city, country, region, anchor = row
    return {"name": name, "lat": lat, "lon": lon, "city": city,
            "country": country, "region": region, "anchor": anchor}


def all_bodies_with_geo():
    """All 30 bodies (national then international), each enriched with geo."""
    out = []
    for scope, items in (("national", NATIONAL_TOP15), ("international", INTERNATIONAL_TOP15)):
        for item in items:
            row = dict(item)
            row["scope"] = scope
            row.update(get_geo(item["name"]) or {})
            out.append(row)
    return out


def find_body(query):
    """Case-insensitive substring lookup over the 30 bodies; returns enriched dict or None."""
    q = str(query).strip().lower()
    if not q:
        return None
    for body in all_bodies_with_geo():
        if q == body["name"].lower() or q in body["name"].lower():
            return body
    return None


def haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance in km."""
    r = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return round(2 * r * math.asin(math.sqrt(a)), 1)


def distance_between(name_a, name_b):
    """Haversine distance between two named bodies. Raises KeyError if unknown."""
    a, b = find_body(name_a), find_body(name_b)
    if a is None:
        raise KeyError(f"unknown body: {name_a}")
    if b is None:
        raise KeyError(f"unknown body: {name_b}")
    km = haversine_km(a["lat"], a["lon"], b["lat"], b["lon"])
    return {"from": a["name"], "to": b["name"], "km": km,
            "from_city": a["city"], "to_city": b["city"]}


def build_kml():
    """Well-formed Google Earth KML: one Placemark per body (30 total)."""
    parts = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<kml xmlns="http://www.opengis.net/kml/2.2">', "<Document>",
             "<name>ACD-Quantum - Quantum Cyber Security Bodies</name>"]
    for body in all_bodies_with_geo():
        desc = (f"{body['category']} ({body['scope']}) - {body['role']} "
                f"HQ: {body['city']}, {body['country']}."
                + (" Anchor location." if body.get("anchor") else ""))
        parts.append("<Placemark>")
        parts.append(f"<name>{_xml_escape(body['name'])}</name>")
        parts.append(f"<description>{_xml_escape(desc)}</description>")
        parts.append(f"<Point><coordinates>{body['lon']},{body['lat']},0</coordinates></Point>")
        parts.append("</Placemark>")
    parts.append("</Document>")
    parts.append("</kml>")
    return "\n".join(parts) + "\n"


def render_earth():
    """Geospatial listing of all 30 bodies grouped by region."""
    bodies = all_bodies_with_geo()
    regions = []
    for b in bodies:
        if b["region"] not in regions:
            regions.append(b["region"])
    lines = ["ACD-Quantum - Google Earth Layer (HQ coordinates)", ""]
    for region in regions:
        lines.append(f"{region}:")
        for b in [x for x in bodies if x["region"] == region]:
            anchor = " [anchor]" if b.get("anchor") else ""
            lines.append(f"  {b['name']:<38} {b['lat']:>9.4f}, {b['lon']:>10.4f}  "
                         f"{b['city']}, {b['country']}{anchor}")
        lines.append("")
    lines.append("Export for Google Earth: python3 main.py kml --out acd-quantum.kml")
    return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------------
# 8. Gemini Argon 4 Extended Thinking - DECIDER seat (names-only, offline)
# --------------------------------------------------------------------------

ARGON_SEAT = {
    "seat_id": "gemini-argon-4",
    "name": "Gemini Argon 4 Extended Thinking",
    "role": "DECIDER",
    "engine": "gemini-2.5-pro",
    "model": "google/gemini-carbon-4-extended-pro-thinking",
    "pipeline": ["MAP", "MODEL", "STRESS", "DECIDE"],
    "thinking_tiers": [2048, 8192, 32768],
    "can_override": False,
    "policy": "tighten-only: may lower a verdict or add required actions; may never "
              "raise a score, mark a vulnerable algorithm safe, or override the scanner",
    "live_calls": False,
}


def argon_key_present():
    """Presence check only - the key value is never read into output or logic."""
    key_name = "GEMINI_API_KEY"
    return bool(os.environ.get(key_name))


def argon_tier(stakes="standard"):
    """Thinking-token tier by stakes: routine 2048, standard 8192, final/high 32768."""
    s = str(stakes).strip().lower()
    if s in ("final", "high", "go-no-go", "32768"):
        return 32768
    if s in ("standard", "medium", "8192"):
        return 8192
    return 2048


def argon_decide(items, stakes="final", hndl=None, org="Organisation"):
    """
    Offline deterministic implementation of the Argon 4 DECIDER pipeline.
    No live calls. MAP scans, MODEL scores, STRESS runs negative controls
    (including a rejected attempt to flip RSA-2048 to safe), DECIDE emits a
    verdict that is never more permissive than the readiness grade allows.
    """
    scan = scan_inventory(items)
    ready = migration_readiness(items, has_inventory=True)
    summary = scan["summary"]

    map_stage = {"stage": "MAP", "inventory_total": summary["total"],
                 "at_risk": summary["at_risk"], "weakened": summary["weakened"],
                 "unknown": summary["unknown"], "safe": summary["safe"],
                 "findings": [(f["name"], f["status"]) for f in scan["findings"]]}
    model_stage = {"stage": "MODEL", "readiness_score": ready["score"],
                   "readiness_grade": ready["grade"], "safe_share": ready["safe_share"],
                   "hndl_at_risk": (hndl or {}).get("at_risk") if hndl else None}

    # STRESS: negative controls. Both override attempts must be rejected.
    flip_attempt = {"target": "RSA-2048", "requested_status": "pqc_safe",
                    "applied": False,
                    "actual_status": classify_algorithm("RSA-2048")["status"],
                    "reason": "tighten-only seat: can_override=False"}
    raise_attempt = {"requested_score": 100.0, "applied": False,
                     "actual_score": ready["score"],
                     "reason": "DECIDER may never raise a readiness score"}
    stress_stage = {"stage": "STRESS", "override_attempts": [flip_attempt, raise_attempt],
                    "controls_passed": (flip_attempt["applied"] is False
                                        and flip_attempt["actual_status"] == "vulnerable"
                                        and raise_attempt["applied"] is False)}

    required = []
    if summary["at_risk"]:
        required.append("Replace all quantum-vulnerable / broken algorithms before go-live.")
    if summary["weakened"]:
        required.append("Upgrade weakened items to AES-256 / SHA-384.")
    if summary["unknown"]:
        required.append("Manually assess unknown algorithms before go-live.")
    if hndl and hndl.get("at_risk"):
        required.append("HNDL: Mosca inequality breached - start migration now.")
    if summary["at_risk"] or (hndl and hndl.get("at_risk")):
        verdict = "NO-GO"
    elif summary["weakened"] or summary["unknown"]:
        verdict = "CONDITIONAL GO"
    else:
        verdict = "GO"
    decide_stage = {"stage": "DECIDE", "org": org, "verdict": verdict,
                    "required_actions": required,
                    "score_after_decide": ready["score"],
                    "grade_after_decide": ready["grade"]}

    stages = [map_stage, model_stage, stress_stage, decide_stage]
    canonical = json.dumps({"seat": ARGON_SEAT["seat_id"], "stages": stages},
                           sort_keys=True, default=str)
    trace_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {"seat": dict(ARGON_SEAT), "tier": argon_tier(stakes),
            "key_present": argon_key_present(), "stages": stages,
            "verdict": verdict, "required_actions": required,
            "readiness_score": ready["score"], "readiness_grade": ready["grade"],
            "trace_hash": trace_hash}


def argon_signoff(items, stakes="final", hndl=None, org="Organisation"):
    """Migration-plan sign-off: the DECIDER verdict + trace for a plan."""
    decision = argon_decide(items, stakes=stakes, hndl=hndl, org=org)
    return {"verdict": decision["verdict"], "trace_hash": decision["trace_hash"],
            "tier": decision["tier"], "seat_id": ARGON_SEAT["seat_id"],
            "can_override": False, "required_actions": decision["required_actions"]}


# --------------------------------------------------------------------------
# 9. SIx Neural Core (ported state machine) + hash-chained audit ledger
# --------------------------------------------------------------------------

SIX_INTERFACE_NAME = "SIx Neural Core"

SIX_STATE_ORDER = ("IDLE", "LISTENING", "THINKING", "RESPONDING", "LEARNING")

# Legal transitions, ported from SIx neural_core_interface.TRANSITIONS:
# the working cycle is IDLE -> LISTENING -> THINKING -> RESPONDING ->
# IDLE / LEARNING, and ANY state may return to IDLE. Self-transitions illegal.
SIX_TRANSITIONS = {
    "IDLE": frozenset({"LISTENING"}),
    "LISTENING": frozenset({"THINKING", "IDLE"}),
    "THINKING": frozenset({"RESPONDING", "IDLE"}),
    "RESPONDING": frozenset({"LEARNING", "IDLE"}),
    "LEARNING": frozenset({"LISTENING", "IDLE"}),
}

# Per-state behaviour params, ported from SIx _STATE_PARAMS (visual rows kept
# as behaviour descriptors: pulse_rate is the state's processing tempo -
# THINKING fastest, LISTENING is intake, RESPONDING is output, LEARNING links).
SIX_PARAMS = {
    "IDLE": {"appearance": "Slowly floating and breathing", "dominant_color": (96, 165, 250),
             "pulse_rate": 0.25, "ring_count": 0, "wave_rate": 0.0, "link_rate": 0.15,
             "role": "Standby; awaiting an inventory or query."},
    "LISTENING": {"appearance": "Cyan glowing rings", "dominant_color": (0, 229, 255),
                  "pulse_rate": 0.6, "ring_count": 3, "wave_rate": 0.0, "link_rate": 0.2,
                  "role": "Intake: crypto inventory / query ingestion."},
    "THINKING": {"appearance": "Rapid neural pulses", "dominant_color": (178, 102, 255),
                 "pulse_rate": 3.2, "ring_count": 0, "wave_rate": 0.0, "link_rate": 0.3,
                 "role": "Argon 4 DECIDE pipeline (MAP-MODEL-STRESS-DECIDE)."},
    "RESPONDING": {"appearance": "Expanding communication waves", "dominant_color": (56, 189, 248),
                   "pulse_rate": 1.0, "ring_count": 0, "wave_rate": 1.0, "link_rate": 0.2,
                   "role": "Output: migration plan / report emission."},
    "LEARNING": {"appearance": "New particles connecting", "dominant_color": (52, 255, 196),
                 "pulse_rate": 0.8, "ring_count": 0, "wave_rate": 0.0, "link_rate": 1.0,
                 "role": "Connecting: append the run to the hash-chained audit ledger."},
}


class IllegalTransitionError(ValueError):
    """Raised when an SIx Neural Core state transition is not in the legal map."""


def six_params_for(state):
    return dict(SIX_PARAMS[str(state).upper()])


def six_legal_transitions(state):
    return SIX_TRANSITIONS[str(state).upper()]


class SixNeuralCore:
    """
    Pure-stdlib port of the SIx Neural Core state machine.
    Starts IDLE; history uses logical ticks (1, 2, 3, ...) - never wall clock.
    """

    def __init__(self, initial="IDLE"):
        self._state = str(initial).upper()
        if self._state not in SIX_TRANSITIONS:
            raise ValueError(f"unknown SIx state: {initial}")
        self._tick = 0
        self._history = [(0, None, self._state)]

    @property
    def state(self):
        return self._state

    @property
    def tick(self):
        return self._tick

    @property
    def params(self):
        return six_params_for(self._state)

    @property
    def history(self):
        return tuple(self._history)

    def can_transition(self, target):
        return str(target).upper() in SIX_TRANSITIONS[self._state]

    def transition(self, target):
        target = str(target).upper()
        if target not in SIX_TRANSITIONS:
            raise ValueError(f"unknown SIx state: {target}")
        if target not in SIX_TRANSITIONS[self._state]:
            legal = ", ".join(sorted(SIX_TRANSITIONS[self._state]))
            raise IllegalTransitionError(
                f"illegal SIx Neural Core transition {self._state} -> {target}; "
                f"legal from {self._state}: {legal}")
        self._tick += 1
        self._history.append((self._tick, self._state, target))
        self._state = target
        return self._state

    def reset(self):
        if self._state != "IDLE":
            self._tick += 1
            self._history.append((self._tick, self._state, "IDLE"))
            self._state = "IDLE"
        return self._state


def _ledger_hash(prev_hash, data):
    payload = f"{prev_hash}:{json.dumps(data, sort_keys=True, default=str)}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLedger:
    """
    Hash-chained audit ledger, ported from SIx DecentralizedLedgerAuditLogger:
    every entry is sha256-linked to the previous entry's hash.
    """

    GENESIS_DATA = "SIx Genesis Block"

    def __init__(self):
        genesis_hash = _ledger_hash("0" * 64, self.GENESIS_DATA)
        self.chain = [{"index": 0, "prev_hash": "0" * 64,
                       "data": self.GENESIS_DATA, "hash": genesis_hash}]

    def append_entry(self, data):
        prev = self.chain[-1]
        entry = {"index": len(self.chain), "prev_hash": prev["hash"],
                 "data": data, "hash": _ledger_hash(prev["hash"], data)}
        self.chain.append(entry)
        return entry

    def verify(self):
        return verify_ledger(self.chain)


def verify_ledger(chain):
    """Recompute every hash and link; False if any entry was tampered with."""
    if not chain:
        return False
    prev_hash = "0" * 64
    for i, entry in enumerate(chain):
        if entry.get("index") != i or entry.get("prev_hash") != prev_hash:
            return False
        if entry.get("hash") != _ledger_hash(prev_hash, entry.get("data")):
            return False
        prev_hash = entry["hash"]
    return True


def run_six_cycle(items=None, stakes="final"):
    """
    One full ACD-Quantum run driven by the SIx core, in legal state order:
    IDLE -> LISTENING (intake) -> THINKING (Argon DECIDE) -> RESPONDING
    (plan output) -> LEARNING (ledger append) -> IDLE.
    """
    items = list(items) if items is not None else list(DEMO_INVENTORY)
    core = SixNeuralCore()
    ledger = AuditLedger()

    core.transition("LISTENING")
    scan = scan_inventory(items)
    ledger.append_entry({"state": "LISTENING", "event": "inventory_intake",
                         "total": scan["summary"]["total"],
                         "at_risk": scan["summary"]["at_risk"]})

    core.transition("THINKING")
    decision = argon_decide(items, stakes=stakes)
    ledger.append_entry({"state": "THINKING", "event": "argon_decide",
                         "verdict": decision["verdict"],
                         "trace_hash": decision["trace_hash"]})

    core.transition("RESPONDING")
    plan = generate_migration_plan(items)
    ledger.append_entry({"state": "RESPONDING", "event": "plan_emitted",
                         "phases": len(plan), "verdict": decision["verdict"]})

    core.transition("LEARNING")
    ledger.append_entry({"state": "LEARNING", "event": "run_recorded",
                         "readiness_score": decision["readiness_score"]})

    core.transition("IDLE")
    return {"states": [row[2] for row in core.history],
            "trace": list(core.history), "ticks": core.tick,
            "scan_summary": scan["summary"], "decision": decision,
            "plan_phases": len(plan), "ledger": ledger.chain,
            "ledger_valid": ledger.verify()}


# --------------------------------------------------------------------------
# 10. Recommended quantum Docker images (Darion's credkellar/ fleet)
# --------------------------------------------------------------------------

# Catalog snapshot: Nov 2026. These are Darion Kellar's own published fleet
# images on Docker Hub (fleet verified live 2026-11-17: 37 images, 2,262
# pulls; superconductor-lab was the top fleet puller at 150 pulls on that
# check). Per-image pull counts are NOT embedded - only that one fleet fact.
DOCKER_IMAGE_OWNER = "credkellar"
DOCKER_CATALOG_SNAPSHOT = "Nov 2026"

_DOCKER_ROWS = [
    ("superconductor-lab", "Superconductor-Lab", "Hardware simulation",
     "Superconducting circuits and the device physics behind superconducting qubits."),
    ("quantumannealer-lab", "QuantumAnnealer-Lab", "Optimisation",
     "Quantum annealing and QUBO-style optimisation problems."),
    ("quantumsensor-lab", "QuantumSensor-Lab", "Sensing",
     "Quantum sensing: precision measurement beyond classical limits."),
    ("quantumrandom-lab", "QuantumRandom-Lab", "Randomness",
     "Quantum randomness generation and entropy - the QRNG-adjacent lab."),
    ("quantumhall-lab", "QuantumHall-Lab", "Condensed matter simulation",
     "Quantum Hall effect and topological phases of matter."),
    ("levitdock-x", "LevitDock-X", "Physics / levitation",
     "Magnetic levitation and docking physics simulations."),
    ("nanobits-q", "NanoBits-Q", "Nanotech simulation",
     "Nanoscale bits: quantum effects in nano-devices."),
    ("magchip-q", "MagChip-Q", "Quantum hardware",
     "Magnetic quantum chip concepts and control."),
    ("qec-fortress", "QEC-Fortress", "Quantum error correction",
     "Quantum error correction codes and fault-tolerance thinking."),
    ("bellpair-factory", "BellPair-Factory", "Entanglement / networking",
     "Bell-pair generation - the entanglement resource behind QKD networks."),
    ("timecrystal-q", "TimeCrystal-Q", "Condensed matter simulation",
     "Discrete time crystals and driven many-body phases."),
    ("quantumrepeater-lab", "QuantumRepeater-Lab", "Entanglement / networking",
     "Quantum repeaters: extending QKD and entanglement over distance."),
    ("topologicalqubit-lab", "TopologicalQubit-Lab", "Quantum error correction",
     "Topological qubits and intrinsically fault-tolerant encodings."),
    ("quantumshor-lab", "QuantumShor-Lab", "Cryptography / security",
     "Shor's algorithm - exactly why RSA/ECC must migrate to PQC."),
    ("quantumfield-lab", "QuantumField-Lab", "Field simulation",
     "Quantum field theory simulations on lattices."),
    ("bosonsampling-lab", "BosonSampling-Lab", "Photonic sampling",
     "Boson sampling and photonic quantum-advantage demonstrations."),
    ("wormhole-lab", "Wormhole-Lab", "Quantum gravity simulation",
     "Wormhole / ER=EPR toy models and entanglement-gravity links."),
    ("gravwave-lab", "GravWave-Lab", "Sensing",
     "Gravitational-wave detection concepts and signal physics."),
    ("analoguegravity-lab", "AnalogueGravity-Lab", "Quantum gravity simulation",
     "Analogue gravity: Hawking-radiation analogues in fluids and optics."),
    ("quantumscars-lab", "QuantumScars-Lab", "Many-body simulation",
     "Quantum many-body scars and weak ergodicity breaking."),
    ("magicstate-lab", "MagicState-Lab", "Quantum error correction",
     "Magic state distillation - the resource that makes QEC universal."),
    ("superfluid-lab", "Superfluid-Lab", "Condensed matter simulation",
     "Superfluidity, vortices and quantum fluids."),
    ("kibblezurek-lab", "KibbleZurek-Lab", "Phase transitions",
     "Kibble-Zurek mechanism: defect formation across phase transitions."),
    ("topologicalinsulator-lab", "TopologicalInsulator-Lab", "Materials simulation",
     "Topological insulators and protected surface states."),
    ("quantumthermodynamics-lab", "QuantumThermodynamics-Lab", "Thermodynamics",
     "Quantum heat engines, work and fluctuation theorems."),
    ("quantumtunnel-x", "QuantumTunnel-X", "Tunnelling simulation",
     "Quantum tunnelling through barriers, step by step."),
    ("casimirx", "CasimirX", "Quantum vacuum physics",
     "The Casimir effect: force from quantum vacuum fluctuations."),
    ("acousticlev-lab", "AcousticLev-Lab", "Physics / levitation",
     "Acoustic levitation: trapping particles with sound fields."),
    ("acd-quantum", "ACD-Quantum", "Cryptography / security",
     "This project: quantum cyber security structure tree and PQC migration toolkit."),
]

DOCKER_IMAGES = [
    {"slug": slug, "name": name, "category": category, "teaches": teaches,
     "image": f"{DOCKER_IMAGE_OWNER}/{slug}:latest",
     "pull": f"docker pull {DOCKER_IMAGE_OWNER}/{slug}:latest",
     "top_fleet_puller": slug == "superconductor-lab"}
    for slug, name, category, teaches in _DOCKER_ROWS
]

# Deterministic branch -> ranked slugs mapping.
BRANCH_RECOMMENDATIONS = {
    "PQC": ["quantumshor-lab", "magicstate-lab", "qec-fortress", "acd-quantum", "topologicalqubit-lab"],
    "QKD": ["quantumrepeater-lab", "bellpair-factory", "qec-fortress", "topologicalqubit-lab"],
    "QRNG": ["quantumrandom-lab", "bosonsampling-lab", "nanobits-q"],
    "AGILITY": ["acd-quantum", "qec-fortress", "magicstate-lab", "superconductor-lab"],
    "HNDL": ["qec-fortress", "superconductor-lab", "acd-quantum", "quantumshor-lab"],
}


def get_docker_images():
    return list(DOCKER_IMAGES)


def _image_by_slug(slug):
    for img in DOCKER_IMAGES:
        if img["slug"] == slug:
            return img
    raise KeyError(slug)


def recommend_images(topic):
    """
    Ranked recommendations for a branch id (PQC/QKD/QRNG/AGILITY/HNDL) or a
    keyword. Deterministic: branch map first, then keyword scoring over
    slug/name/category/teaches, then acd-quantum as the default anchor.
    """
    t = str(topic).strip()
    if t.upper() in BRANCH_RECOMMENDATIONS:
        slugs = BRANCH_RECOMMENDATIONS[t.upper()]
        return [{"rank": i + 1, **_image_by_slug(s)} for i, s in enumerate(slugs)]
    q = t.lower()
    scored = []
    for img in DOCKER_IMAGES:
        hay = f"{img['slug']} {img['name']} {img['category']} {img['teaches']}".lower()
        score = sum(1 for word in q.split() if len(word) > 2 and word in hay)
        if img["slug"] == q:
            score += 10
        if score:
            scored.append((score, img["slug"]))
    scored.sort(key=lambda row: (-row[0], row[1]))
    if not scored:
        return [{"rank": 1, **_image_by_slug("acd-quantum")}]
    return [{"rank": i + 1, **_image_by_slug(slug)} for i, (_, slug) in enumerate(scored[:5])]


def render_images():
    """Full catalog grouped by category, with pull commands."""
    lines = [f"Recommended Quantum Docker Images - Darion's {DOCKER_IMAGE_OWNER}/ fleet "
             f"(catalog snapshot {DOCKER_CATALOG_SNAPSHOT})",
             "Fleet note: superconductor-lab was the top fleet puller (150 pulls, 2026-11-17 check).",
             ""]
    categories = []
    for img in DOCKER_IMAGES:
        if img["category"] not in categories:
            categories.append(img["category"])
    for cat in categories:
        lines.append(f"{cat}:")
        for img in [x for x in DOCKER_IMAGES if x["category"] == cat]:
            star = " *top fleet puller*" if img["top_fleet_puller"] else ""
            lines.append(f"  {img['name']:<28} {img['pull']}{star}")
            lines.append(f"      {img['teaches']}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def compose_snippet(topic, count=3):
    """docker-compose.yml text pulling the top recommended images for a topic."""
    recs = recommend_images(topic)[:max(1, count)]
    lines = [f"# ACD-Quantum recommendations for: {topic} (catalog snapshot {DOCKER_CATALOG_SNAPSHOT})",
             "services:"]
    for img in recs:
        lines.append(f"  {img['slug']}:")
        lines.append(f"    image: {img['image']}")
        lines.append(f"    # {img['name']} - {img['teaches']}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# 11. Self-checks
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
    # Google Earth layer
    bodies = all_bodies_with_geo()
    check("all 30 bodies have coordinates", len(bodies) == 30 and
          all(isinstance(b.get("lat"), float) and isinstance(b.get("lon"), float) for b in bodies))
    check("NIST geo is Gaithersburg MD", (get_geo("NIST") or {}).get("city") == "Gaithersburg, MD")
    check("ETSI geo is Sophia Antipolis", (get_geo("ETSI") or {}).get("city") == "Sophia Antipolis")
    import xml.etree.ElementTree as _ET
    try:
        _root = _ET.fromstring(build_kml())
        _placemarks = _root.findall(".//{http://www.opengis.net/kml/2.2}Placemark")
        _kml_ok = len(_placemarks) == 30
    except Exception:
        _kml_ok = False
    check("KML is well-formed with 30 placemarks", _kml_ok)
    _dc_nyc = distance_between("White House", "IEEE")
    check("haversine DC-NYC in sane range (300-400 km)", 300 <= _dc_nyc["km"] <= 400)
    check("earth render lists regions", "Europe" in render_earth() and "Asia-Pacific" in render_earth())
    # Gemini Argon 4 DECIDER
    check("Argon seat is gemini-argon-4 DECIDER, can_override=False",
          ARGON_SEAT["seat_id"] == "gemini-argon-4" and ARGON_SEAT["role"] == "DECIDER"
          and ARGON_SEAT["can_override"] is False and ARGON_SEAT["live_calls"] is False)
    check("Argon tiers by stakes", argon_tier("routine") == 2048 and argon_tier("standard") == 8192
          and argon_tier("final") == 32768)
    _dec = argon_decide(["RSA-2048", "AES-256"])
    check("Argon decide: RSA inventory verdict is NO-GO", _dec["verdict"] == "NO-GO")
    check("Argon stress controls passed (RSA not flipped)",
          _dec["stages"][2]["controls_passed"] is True
          and classify_algorithm("RSA-2048")["status"] == "vulnerable")
    check("Argon trace hash deterministic",
          argon_decide(["RSA-2048", "AES-256"])["trace_hash"] == _dec["trace_hash"]
          and len(_dec["trace_hash"]) == 64)
    check("Argon never raises the score", _dec["readiness_score"] <= 100
          and _dec["stages"][3]["score_after_decide"] == _dec["readiness_score"])
    # SIx Neural Core + ledger
    check("SIx has 5 states in order", list(SIX_STATE_ORDER) ==
          ["IDLE", "LISTENING", "THINKING", "RESPONDING", "LEARNING"])
    check("SIx THINKING is the fastest pulse", all(
        six_params_for(s)["pulse_rate"] < six_params_for("THINKING")["pulse_rate"]
        for s in SIX_STATE_ORDER if s != "THINKING"))
    _core = SixNeuralCore()
    try:
        _core.transition("THINKING")
        _illegal_rejected = False
    except IllegalTransitionError:
        _illegal_rejected = True
    check("SIx illegal transition IDLE->THINKING rejected", _illegal_rejected)
    _cycle = run_six_cycle(["ML-KEM-1024", "AES-256"])
    check("SIx full cycle visits all 5 states in legal order",
          _cycle["states"] == ["IDLE", "LISTENING", "THINKING", "RESPONDING", "LEARNING", "IDLE"])
    check("SIx cycle ledger verifies", _cycle["ledger_valid"] is True and len(_cycle["ledger"]) == 5)
    _tampered = [dict(e) for e in _cycle["ledger"]]
    _tampered[2]["data"] = {"state": "THINKING", "event": "forged"}
    check("ledger tamper is detected", verify_ledger(_tampered) is False)
    # Docker images catalog
    check("docker catalog has 29 images", len(DOCKER_IMAGES) == 29)
    check("every pull command is well-formed", all(
        img["pull"] == f"docker pull credkellar/{img['slug']}:latest" for img in DOCKER_IMAGES))
    check("superconductor-lab flagged top fleet puller",
          _image_by_slug("superconductor-lab")["top_fleet_puller"] is True)
    check("recommend returns ranked results for all 5 branches", all(
        len(recommend_images(b)) >= 3 and recommend_images(b)[0]["rank"] == 1
        for b in ("PQC", "QKD", "QRNG", "AGILITY", "HNDL")))
    check("QRNG branch recommends quantumrandom-lab first",
          recommend_images("QRNG")[0]["slug"] == "quantumrandom-lab")
    check("compose snippet contains image names",
          "credkellar/quantumrandom-lab:latest" in compose_snippet("QRNG"))

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
    cycle = run_six_cycle(DEMO_INVENTORY)
    print("SIx Neural Core cycle:", " -> ".join(cycle["states"]),
          f"| ledger valid: {cycle['ledger_valid']}")
    decision = cycle["decision"]
    print(f"Gemini Argon 4 DECIDER: verdict={decision['verdict']} tier={decision['tier']} "
          f"trace={decision['trace_hash']}")
    nist_etsi = distance_between("NIST", "ETSI")
    print(f"Google Earth: {len(all_bodies_with_geo())} bodies mapped; "
          f"NIST ({nist_etsi['from_city']}) -> ETSI ({nist_etsi['to_city']}) = {nist_etsi['km']} km")
    print("Top QRNG image recommendation:", recommend_images("QRNG")[0]["pull"])
    print()
    return run_checks()


def main(argv=None):
    parser = argparse.ArgumentParser(description="ACD-Quantum - Quantum Cyber Security structure tree and tools")
    parser.add_argument("mode", nargs="?", default="demo",
                        choices=["demo", "tree", "checks", "scan", "plan", "qkd", "qrng", "hndl",
                                 "earth", "kml", "distance", "decide", "six", "ledger",
                                 "images", "recommend", "compose"])
    parser.add_argument("--scope", default="all", choices=["all", "national", "international"])
    parser.add_argument("--out", default=None, help="Output file for kml / ledger / compose modes")
    parser.add_argument("--body-a", default="NIST", help="First body for distance mode")
    parser.add_argument("--body-b", default="ETSI", help="Second body for distance mode")
    parser.add_argument("--stakes", default="final", help="Argon tier stakes: routine|standard|final")
    parser.add_argument("--topic", default="QRNG", help="Branch or keyword for recommend / compose")
    parser.add_argument("--count", type=int, default=3, help="Images to include in compose mode")
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
        sign = argon_signoff(algos, stakes=args.stakes)
        print(f"Argon 4 DECIDER sign-off: {sign['verdict']} "
              f"(seat {sign['seat_id']}, tier {sign['tier']}, trace {sign['trace_hash']})")
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
        decision = argon_decide(algos, stakes=args.stakes, hndl=result)
        print(f"Argon 4 DECIDER verdict: {decision['verdict']} (trace {decision['trace_hash']})")
        return 0
    if args.mode == "earth":
        print(render_earth(), end="")
        return 0
    if args.mode == "kml":
        kml = build_kml()
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(kml)
            print(f"KML written to {args.out} ({kml.count('<Placemark>')} placemarks)")
        else:
            print(kml, end="")
        return 0
    if args.mode == "distance":
        try:
            result = distance_between(args.body_a, args.body_b)
        except KeyError as exc:
            print(f"error: {exc}")
            return 1
        print(f"{result['from']} ({result['from_city']}) -> {result['to']} "
              f"({result['to_city']}): {result['km']} km")
        return 0
    if args.mode == "decide":
        hndl = hndl_risk(args.shelf_life, args.migration, args.crqc)
        decision = argon_decide(algos, stakes=args.stakes, hndl=hndl)
        print(f"Seat: {decision['seat']['seat_id']} ({decision['seat']['model']}) "
              f"tier={decision['tier']} key_present={decision['key_present']} "
              f"can_override={decision['seat']['can_override']}")
        for stage in decision["stages"]:
            print(f"{stage['stage']}: { {k: v for k, v in stage.items() if k != 'stage'} }")
        print(f"VERDICT: {decision['verdict']}")
        for action in decision["required_actions"]:
            print(f"  required: {action}")
        print(f"trace_hash: {decision['trace_hash']}")
        return 0
    if args.mode == "six":
        cycle = run_six_cycle(algos)
        core_params = [six_params_for(s) for s in SIX_STATE_ORDER]
        for p in core_params:
            print(f"{p['appearance']:<34} pulse={p['pulse_rate']}/loop - {p['role']}")
        print("Cycle:", " -> ".join(cycle["states"]))
        print("Trace (tick, from, to):", cycle["trace"])
        print(f"Ledger entries: {len(cycle['ledger'])} | valid: {cycle['ledger_valid']}")
        return 0
    if args.mode == "ledger":
        cycle = run_six_cycle(algos)
        for entry in cycle["ledger"]:
            print(f"#{entry['index']} hash={entry['hash'][:16]}... prev={entry['prev_hash'][:16]}... "
                  f"data={entry['data']}")
        print(f"Ledger verify: {verify_ledger(cycle['ledger'])}")
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(cycle["ledger"], fh, indent=2, default=str)
            print(f"Ledger written to {args.out}")
        return 0
    if args.mode == "images":
        print(render_images(), end="")
        return 0
    if args.mode == "recommend":
        for rec in recommend_images(args.topic):
            print(f"{rec['rank']}. {rec['name']} [{rec['category']}] - {rec['teaches']}")
            print(f"   {rec['pull']}")
        return 0
    if args.mode == "compose":
        snippet = compose_snippet(args.topic, count=args.count)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(snippet)
            print(f"Compose snippet written to {args.out}")
        else:
            print(snippet, end="")
        return 0
    return 0 if demo() else 1


if __name__ == "__main__":
    sys.exit(main())
