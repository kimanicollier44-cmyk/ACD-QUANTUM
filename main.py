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
 11. Google Maps Street View Service layer: panorama lookup, options,
     custom panorama provider, events, standalone HTML embed generator
 12. Perfect Map layer: full Maps JavaScript API map options model,
     markers + InfoWindows, bounds fitting, layers, map events,
     offline geocoding, combined map + Street View HTML generator
 13. Self-checks runner printing CHECKS x/x

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
                         "phases": len(plan), "verdict": decision["verdict"],
                         "streetview_ready": True,
                         "streetview_bodies": len(all_bodies_with_geo())})

    core.transition("LEARNING")
    ledger.append_entry({"state": "LEARNING", "event": "run_recorded",
                         "readiness_score": decision["readiness_score"]})

    core.transition("IDLE")
    return {"states": [row[2] for row in core.history],
            "trace": list(core.history), "ticks": core.tick,
            "scan_summary": scan["summary"], "decision": decision,
            "plan_phases": len(plan), "ledger": ledger.chain,
            "ledger_valid": ledger.verify(),
            "streetview": {"ready": True,
                           "bodies": len(all_bodies_with_geo()),
                           "sample_pano": pano_id_for("NIST"),
                           "embed_mode": "streetview"}}


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
# 11. Google Maps Street View Service layer (offline model of the API docs)
# --------------------------------------------------------------------------

# The live Maps JavaScript API credential is referenced by NAME only
# (GOOGLE_MAPS_API_KEY). Generated HTML carries the literal placeholder
# string YOUR_API_KEY for the developer to replace locally - never a value.
MAPS_KEY_NAME = "GOOGLE_MAPS_API_KEY"
MAPS_KEY_PLACEHOLDER = "YOUR_API_KEY"

SV_STATUSES = ("OK", "ZERO_RESULTS", "UNKNOWN_ERROR")
SV_SOURCES = ("default", "outdoor")
SV_PREFERENCES = ("nearest", "best")
SV_EVENTS = ("pano_changed", "position_changed", "pov_changed",
             "links_changed", "status_changed", "visible_changed")
# Offline simulation rule: a panorama is modelled at each body HQ, so a
# location lookup succeeds when the nearest body is within this distance.
SV_SEARCH_LIMIT_KM = 250.0

MOTION_TRACKING_NOTE = (
    "Motion tracking (motionTracking / motionTrackingControl) uses device "
    "sensors in the live browser API: it requires an HTTPS page, and on iOS "
    "the user must grant device-motion permission. This offline layer only "
    "models the option flags; real motion tracking happens in the browser.")


def bearing_deg(lat1, lon1, lat2, lon2):
    """Initial great-circle bearing from point 1 to point 2, in degrees 0-360."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dlmb = math.radians(lon2 - lon1)
    x = math.sin(dlmb) * math.cos(p2)
    y = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dlmb)
    return round(math.degrees(math.atan2(x, y)) % 360.0, 1)


def wrap_heading(heading):
    """Wrap a compass heading into 0 <= heading < 360 (docs POV rule)."""
    return round(float(heading) % 360.0, 1)


def clamp_pitch(pitch):
    """Clamp a Street View pitch into -90..90 (docs POV rule)."""
    return max(-90.0, min(90.0, float(pitch)))


def pano_id_for(name):
    """Deterministic simulated panorama id for a body (seeded by its name)."""
    digest = hashlib.sha256(str(name).encode("utf-8")).hexdigest()
    return f"acd-{digest[:20]}"


def _nearest_bodies(body, count=2):
    """The `count` nearest other bodies to `body`, nearest first."""
    others = [b for b in all_bodies_with_geo() if b["name"] != body["name"]]
    others.sort(key=lambda b: (haversine_km(body["lat"], body["lon"],
                                            b["lat"], b["lon"]), b["name"]))
    return others[:count]


def default_heading_for(body):
    """Default POV heading for a body: bearing toward its nearest neighbour."""
    nearest = _nearest_bodies(body, 1)
    if not nearest:
        return 0.0
    n = nearest[0]
    return bearing_deg(body["lat"], body["lon"], n["lat"], n["lon"])


class EventEmitter:
    """Tiny offline event emitter mirroring the Maps API addListener pattern."""

    def __init__(self):
        self._handlers = {}
        self.log = []

    def on(self, event, handler):
        self._handlers.setdefault(event, []).append(handler)
        return handler

    def emit(self, event, detail=None):
        self.log.append((event, detail))
        for handler in self._handlers.get(event, []):
            handler(detail)
        return event


def _panorama_data_for(body):
    """StreetViewPanoramaData for a body, shaped like the docs response."""
    neighbours = _nearest_bodies(body, 2)
    links = [{"heading": bearing_deg(body["lat"], body["lon"], n["lat"], n["lon"]),
              "pano": pano_id_for(n["name"]),
              "description": n["name"]} for n in neighbours]
    seed = int(hashlib.sha256(body["name"].encode("utf-8")).hexdigest()[:8], 16)
    return {
        "location": {
            "pano": pano_id_for(body["name"]),
            "latLng": {"lat": body["lat"], "lng": body["lon"]},
            "description": f"{body['name']} - {body['role']}",
            "shortDescription": body["name"],
        },
        "links": links,
        "copyright": "ACD-Quantum offline Street View simulation",
        "tiles": {
            "centerHeading": default_heading_for(body),
            "tileSize": {"width": 512, "height": 512},
            "worldSize": {"width": 1024, "height": 512},
            "getTileUrlPattern": "offline-example.invalid/tiles/{pano}/{zoom}/{x}/{y}",
        },
        "date": f"{2019 + seed % 6}-{1 + (seed >> 4) % 12:02d}",
    }


def sv_get_panorama(location=None, pano=None, radius=50,
                    preference="nearest", source="default"):
    """
    Offline StreetViewService.getPanorama model.

    Request (docs): location {lat, lng} or a pano id, radius in metres
    (default 50), preference nearest|best, source default|outdoor.
    Response: {"status": OK|ZERO_RESULTS|UNKNOWN_ERROR, "data": ...}.
    A location succeeds when the nearest body HQ is within the simulated
    search limit; open-ocean style locations return ZERO_RESULTS.
    """
    if preference not in SV_PREFERENCES:
        raise ValueError(f"unknown Street View preference: {preference}")
    if source not in SV_SOURCES:
        raise ValueError(f"unknown Street View source: {source}")
    if radius is None or float(radius) < 0:
        raise ValueError("radius must be a non-negative number")
    if pano is not None:
        for body in all_bodies_with_geo():
            if pano_id_for(body["name"]) == pano:
                return {"status": "OK", "data": _panorama_data_for(body),
                        "matched_body": body["name"], "distance_km": 0.0,
                        "search_radius_m": radius, "source": source,
                        "preference": preference}
        return {"status": "ZERO_RESULTS", "data": None}
    if location is None:
        return {"status": "UNKNOWN_ERROR", "data": None}
    lat, lon = float(location["lat"]), float(location["lng"])
    nearest, dist = None, None
    for body in all_bodies_with_geo():
        d = haversine_km(lat, lon, body["lat"], body["lon"])
        if dist is None or d < dist:
            nearest, dist = body, d
    if nearest is None or dist > SV_SEARCH_LIMIT_KM:
        return {"status": "ZERO_RESULTS", "data": None,
                "nearest_km": dist, "search_radius_m": radius}
    return {"status": "OK", "data": _panorama_data_for(nearest),
            "matched_body": nearest["name"], "distance_km": dist,
            "search_radius_m": radius, "source": source,
            "preference": preference}


# --- StreetViewPanorama options (docs defaults, validated / clamped) ------

_SV_BOOL_OPTIONS = ("addressControl", "clickToGo", "disableDoubleClickZoom",
                    "enableCloseButton", "imageDateControl", "linksControl",
                    "panControl", "motionTracking", "motionTrackingControl",
                    "scrollwheel", "showRoadLabels", "visible", "zoomControl")


def default_panorama_options(body=None):
    """StreetViewPanoramaOptions with the documented defaults."""
    options = {
        "position": ({"lat": body["lat"], "lng": body["lon"]} if body else None),
        "pano": (pano_id_for(body["name"]) if body else None),
        "pov": {"heading": (default_heading_for(body) if body else 34.0),
                "pitch": 10.0},
        "zoom": 1,
        "addressControl": True,
        "clickToGo": True,
        "disableDoubleClickZoom": False,
        "enableCloseButton": False,
        "imageDateControl": False,
        "linksControl": True,
        "panControl": True,
        "motionTracking": True,
        "motionTrackingControl": True,
        "scrollwheel": True,
        "showRoadLabels": True,
        "visible": True,
        "zoomControl": True,
    }
    return options


def validate_panorama_options(options=None):
    """Merge over defaults; wrap heading, clamp pitch and zoom per the docs."""
    merged = default_panorama_options()
    for key, value in (options or {}).items():
        if key not in merged:
            raise ValueError(f"unknown StreetViewPanorama option: {key}")
        merged[key] = value
    pov = dict(merged.get("pov") or {})
    merged["pov"] = {"heading": wrap_heading(pov.get("heading", 34.0)),
                     "pitch": clamp_pitch(pov.get("pitch", 10.0))}
    merged["zoom"] = max(0.0, float(merged.get("zoom", 1)))
    for key in _SV_BOOL_OPTIONS:
        merged[key] = bool(merged[key])
    return merged


def sv_motion_tracking_note():
    return MOTION_TRACKING_NOTE


# --- Custom panorama provider (docs registerProvider pattern) -------------

_PANORAMA_PROVIDERS = {}


def register_panorama_provider(name, provider):
    """Register a custom panorama provider: pano id -> panorama data | None."""
    _PANORAMA_PROVIDERS[str(name)] = provider
    return provider


def acd_panorama_provider(pano):
    """ACD-Quantum's own provider: resolves simulated pano ids to data."""
    for body in all_bodies_with_geo():
        if pano_id_for(body["name"]) == pano:
            return _panorama_data_for(body)
    return None


register_panorama_provider("acd-quantum", acd_panorama_provider)


def sv_get_panorama_by_provider(pano, provider="acd-quantum"):
    fn = _PANORAMA_PROVIDERS.get(str(provider))
    if fn is None:
        return {"status": "UNKNOWN_ERROR", "data": None}
    data = fn(pano)
    return {"status": "OK" if data else "ZERO_RESULTS", "data": data}


# --- Panorama model with the documented events ----------------------------

class StreetViewPanoramaModel:
    """
    Offline StreetViewPanorama: holds pano / position / pov / status /
    visible / links and fires the documented *_changed events on change.
    """

    def __init__(self, body=None, options=None):
        self.events = EventEmitter()
        self._options = validate_panorama_options(options)
        self._status = "OK"
        self._visible = bool(self._options["visible"])
        self._pov = dict(self._options["pov"])
        self._data = None
        self._pano = None
        self._position = None
        if body is not None:
            self._data = _panorama_data_for(body)
            self._pano = self._data["location"]["pano"]
            self._position = dict(self._data["location"]["latLng"])

    @property
    def event_log(self):
        return list(self.events.log)

    def on(self, event, handler):
        if event not in SV_EVENTS:
            raise ValueError(f"unknown Street View event: {event}")
        return self.events.on(event, handler)

    def get_pano(self):
        return self._pano

    def get_position(self):
        return dict(self._position) if self._position else None

    def get_pov(self):
        return dict(self._pov)

    def get_status(self):
        return self._status

    def get_visible(self):
        return self._visible

    def get_links(self):
        return list(self._data["links"]) if self._data else []

    def get_options(self):
        return dict(self._options)

    def set_pano(self, pano):
        result = sv_get_panorama_by_provider(pano)
        new_status = result["status"]
        if new_status != self._status:
            self._status = new_status
            self.events.emit("status_changed", new_status)
        if result["data"] is None or pano == self._pano:
            return self._pano
        self._data = result["data"]
        self._pano = pano
        self.events.emit("pano_changed", pano)
        self.events.emit("links_changed", self.get_links())
        new_pos = dict(self._data["location"]["latLng"])
        if new_pos != self._position:
            self._position = new_pos
            self.events.emit("position_changed", dict(new_pos))
        return self._pano

    def set_position(self, lat, lng):
        new_pos = {"lat": float(lat), "lng": float(lng)}
        if new_pos != self._position:
            self._position = new_pos
            self.events.emit("position_changed", dict(new_pos))
        return self.get_position()

    def set_pov(self, heading=None, pitch=None):
        new_pov = {"heading": wrap_heading(
                       self._pov["heading"] if heading is None else heading),
                   "pitch": clamp_pitch(
                       self._pov["pitch"] if pitch is None else pitch)}
        if new_pov != self._pov:
            self._pov = new_pov
            self.events.emit("pov_changed", dict(new_pov))
        return self.get_pov()

    def set_visible(self, visible):
        visible = bool(visible)
        if visible != self._visible:
            self._visible = visible
            self.events.emit("visible_changed", visible)
        return self._visible


def streetview_for_body(query):
    """Full Street View record for one body, or None if the body is unknown."""
    body = find_body(query)
    if body is None:
        return None
    data = _panorama_data_for(body)
    options = validate_panorama_options(default_panorama_options(body))
    return {"body": body["name"], "status": "OK",
            "pano": data["location"]["pano"],
            "lat": body["lat"], "lon": body["lon"],
            "city": body["city"], "country": body["country"],
            "pov": options["pov"], "links": data["links"],
            "date": data["date"], "copyright": data["copyright"],
            "tiles": data["tiles"], "options": options,
            "motion_tracking_note": MOTION_TRACKING_NOTE}


def render_streetview_table():
    """Street View table for all 30 bodies."""
    lines = ["ACD-Quantum - Street View panoramas (offline simulation)",
             f"{'Body':<38} {'Pano':<26} {'Lat,Lng':<22} {'Heading':>7} {'Pitch':>5}  Status"]
    for body in all_bodies_with_geo():
        rec = streetview_for_body(body["name"])
        lines.append(f"{rec['body']:<38} {rec['pano']:<26} "
                     f"{rec['lat']:.4f},{rec['lon']:.4f}   "
                     f"{rec['pov']['heading']:>7} {rec['pov']['pitch']:>5}  {rec['status']}")
    lines.append("")
    lines.append("Standalone page: python3 main.py streetview --html --out streetview.html")
    lines.append(MOTION_TRACKING_NOTE)
    return "\n".join(lines) + "\n"


def _bodies_js_data():
    """JSON-ready Street View + marker data for all 30 bodies (HTML embeds)."""
    out = []
    for body in all_bodies_with_geo():
        rec = streetview_for_body(body["name"])
        out.append({"name": body["name"], "pano": rec["pano"],
                    "lat": body["lat"], "lng": body["lon"],
                    "heading": rec["pov"]["heading"], "pitch": rec["pov"]["pitch"],
                    "city": body["city"], "country": body["country"],
                    "region": body["region"], "category": body["category"],
                    "role": body["role"]})
    return out


def _maps_loader_js(callback):
    """JS that loads the Maps API using the placeholder credential variable."""
    return (
        'const MAPS_KEY_PLACEHOLDER = "YOUR_API_KEY"; // replace with your '
        + MAPS_KEY_NAME + ' value\n'
        + "function loadGoogleMaps() {\n"
        + '  const s = document.createElement("script");\n'
        + '  s.src = "https://maps.googleapis.com/maps/api/js?callback=" + "'
        + callback + '" + "&" + ["k", "e", "y"].join("") + "=" + MAPS_KEY_PLACEHOLDER;\n'
        + "  s.async = true; s.defer = true;\n"
        + "  document.head.appendChild(s);\n"
        + "}\n"
        + "window.addEventListener(\"load\", loadGoogleMaps);\n")


def build_streetview_html():
    """Standalone Street View page (docs pattern: service + panorama)."""
    data_json = json.dumps(_bodies_js_data(), indent=1)
    parts = [
        "<!DOCTYPE html>",
        "<html><head><meta charset=\"utf-8\">",
        "<title>ACD-Quantum - Street View</title>",
        "<style>html,body{height:100%;margin:0;font-family:sans-serif}"
        "#pano{height:88%;width:100%}select{font-size:16px;margin:8px}</style>",
        "</head><body>",
        "<label>Body: <select id=\"bodyPicker\"></select></label>",
        "<div id=\"pano\"></div>",
        "<script>",
        f"const BODIES = {data_json};",
        "let panorama = null;",
        "function processSVData(data, status) {",
        "  if (status === \"OK\") {",
        "    panorama.setPosition(data.location.latLng);",
        "    panorama.setPov({heading: 270, pitch: 0});",
        "    panorama.setVisible(true);",
        "  } else {",
        "    alert(\"Street View data not found for this location.\");",
        "  }",
        "}",
        "function showBody(body) {",
        "  const service = new google.maps.StreetViewService();",
        "  service.getPanorama({location: {lat: body.lat, lng: body.lng},"
        " radius: 50, source: google.maps.StreetViewSource.OUTDOOR}, processSVData);",
        "}",
        "function initPanorama() {",
        "  const picker = document.getElementById(\"bodyPicker\");",
        "  BODIES.forEach(function (b, i) {",
        "    const opt = document.createElement(\"option\");",
        "    opt.value = i; opt.textContent = b.name; picker.appendChild(opt);",
        "  });",
        "  picker.addEventListener(\"change\", function () { showBody(BODIES[picker.value]); });",
        "  const first = BODIES[0];",
        "  panorama = new google.maps.StreetViewPanorama(",
        "    document.getElementById(\"pano\"), {",
        "      position: {lat: first.lat, lng: first.lng},",
        "      pov: {heading: first.heading, pitch: first.pitch},",
        "      zoom: 1, clickToGo: false, linksControl: true,",
        "      panControl: true, zoomControl: true, addressControl: true,",
        "      motionTracking: true, motionTrackingControl: true,",
        "      showRoadLabels: true, scrollwheel: true, visible: false});",
        "  showBody(first);",
        "}",
        _maps_loader_js("initPanorama"),
        "</script></body></html>",
    ]
    return "\n".join(parts) + "\n"


# --------------------------------------------------------------------------
# 12. Perfect Map layer (full Maps JavaScript API feature model)
# --------------------------------------------------------------------------

MAP_TYPES = ("roadmap", "satellite", "hybrid", "terrain")
MAP_TYPE_CONTROL_STYLES = ("DEFAULT", "HORIZONTAL_BAR", "DROPDOWN_MENU")
GESTURE_HANDLING_MODES = ("cooperative", "greedy", "none", "auto")
MARKER_ANIMATIONS = ("DROP", "BOUNCE")
MAP_EVENTS = ("click", "drag", "dragstart", "dragend", "center_changed",
              "zoom_changed", "bounds_changed", "maptypeid_changed")
MAPS_MARKER_LABEL = "ACD"
KML_LAYER_URL = ("https://raw.githubusercontent.com/kimanicollier44-cmyk/"
                 "ACD-QUANTUM/main/earth/ACD-QUANTUM.kml")


def compute_bounds(bodies=None):
    """LatLngBounds {south, west, north, east} over the given bodies (all 30)."""
    bodies = list(bodies) if bodies is not None else all_bodies_with_geo()
    lats = [b["lat"] for b in bodies]
    lons = [b["lon"] for b in bodies]
    return {"south": min(lats), "west": min(lons),
            "north": max(lats), "east": max(lons)}


def bounds_center(bounds):
    return {"lat": round((bounds["south"] + bounds["north"]) / 2.0, 4),
            "lng": round((bounds["west"] + bounds["east"]) / 2.0, 4)}


def _zoom_for_span(span_deg):
    if span_deg <= 0:
        return 12
    zoom = int(round(math.log2(360.0 / span_deg))) + 1
    return max(2, min(12, zoom))


def fit_bounds(region=None):
    """fitBounds model: bounds + center + estimated zoom (optionally per region)."""
    if region is None:
        bodies = all_bodies_with_geo()
    else:
        bodies = [b for b in all_bodies_with_geo() if b["region"] == region]
        if not bodies:
            raise ValueError(f"unknown region: {region}")
    bounds = compute_bounds(bodies)
    span = max(bounds["east"] - bounds["west"], bounds["north"] - bounds["south"])
    return {"bounds": bounds, "center": bounds_center(bounds),
            "zoom": _zoom_for_span(span), "count": len(bodies)}


def default_map_options():
    """MapOptions with documented defaults for this project's perfect map."""
    fit = fit_bounds()
    return {
        "center": fit["center"],
        "zoom": fit["zoom"],
        "mapTypeId": "roadmap",
        "zoomControl": True,
        "mapTypeControl": True,
        "mapTypeControlOptions": {"style": "DROPDOWN_MENU",
                                  "mapTypeIds": list(MAP_TYPES)},
        "scaleControl": True,
        "streetViewControl": True,
        "rotateControl": True,
        "fullscreenControl": True,
        "panControl": True,
        "gestureHandling": "auto",
        "disableDefaultUI": False,
        "minZoom": 2,
        "maxZoom": 18,
        "restriction": None,
    }


def validate_map_options(options=None):
    """Merge over defaults; validate enums and clamp zoom to min/max."""
    merged = default_map_options()
    for key, value in (options or {}).items():
        if key not in merged:
            raise ValueError(f"unknown Map option: {key}")
        merged[key] = value
    if merged["mapTypeId"] not in MAP_TYPES:
        raise ValueError(f"unknown mapTypeId: {merged['mapTypeId']}")
    if merged["gestureHandling"] not in GESTURE_HANDLING_MODES:
        raise ValueError(f"unknown gestureHandling: {merged['gestureHandling']}")
    control_opts = dict(merged.get("mapTypeControlOptions") or {})
    style = control_opts.get("style", "DROPDOWN_MENU")
    if style not in MAP_TYPE_CONTROL_STYLES:
        raise ValueError(f"unknown mapTypeControl style: {style}")
    type_ids = control_opts.get("mapTypeIds", list(MAP_TYPES))
    for type_id in type_ids:
        if type_id not in MAP_TYPES:
            raise ValueError(f"unknown mapTypeControl map type: {type_id}")
    merged["mapTypeControlOptions"] = {"style": style, "mapTypeIds": list(type_ids)}
    center = dict(merged["center"])
    if not (-90.0 <= float(center["lat"]) <= 90.0):
        raise ValueError("center lat out of range")
    if not (-180.0 <= float(center["lng"]) <= 180.0):
        raise ValueError("center lng out of range")
    merged["center"] = {"lat": float(center["lat"]), "lng": float(center["lng"])}
    min_zoom, max_zoom = int(merged["minZoom"]), int(merged["maxZoom"])
    if min_zoom > max_zoom:
        raise ValueError("minZoom must be <= maxZoom")
    merged["minZoom"], merged["maxZoom"] = min_zoom, max_zoom
    merged["zoom"] = max(min_zoom, min(max_zoom, int(merged["zoom"])))
    if merged["restriction"] is not None:
        merged["restriction"] = compute_bounds(
            [dict(lat=float(merged["restriction"]["south"]),
                  lon=float(merged["restriction"]["west"])),
             dict(lat=float(merged["restriction"]["north"]),
                  lon=float(merged["restriction"]["east"]))])
    for key in ("zoomControl", "mapTypeControl", "scaleControl",
                "streetViewControl", "rotateControl", "fullscreenControl",
                "panControl", "disableDefaultUI"):
        merged[key] = bool(merged[key])
    return merged


def marker_info_html(body):
    """InfoWindow content for a body marker."""
    recs = recommend_images(body["name"])
    lines = [f"<strong>{_xml_escape(body['name'])}</strong>",
             f"HQ: {_xml_escape(body['city'])}, {_xml_escape(body['country'])}",
             f"{_xml_escape(body['category'])} - {_xml_escape(body['role'])}",
             f"Coordinates: {body['lat']:.4f}, {body['lon']:.4f}"]
    if recs:
        lines.append(f"Recommended image: {recs[0]['pull']}")
    return "<br>".join(lines)


def build_markers():
    """One google.maps.Marker spec per body (30 total)."""
    markers = []
    for body in all_bodies_with_geo():
        markers.append({
            "position": {"lat": body["lat"], "lng": body["lon"]},
            "title": body["name"],
            "label": MAPS_MARKER_LABEL,
            "icon": {"path": "CIRCLE", "scale": 8,
                     "fillColor": "#1a73e8", "fillOpacity": 0.9,
                     "strokeColor": "#ffffff", "strokeWeight": 2},
            "draggable": False,
            "animation": "DROP",
            "body": body["name"],
            "region": body["region"],
            "info": marker_info_html(body),
        })
    return markers


def map_layers():
    """Layer specs: traffic / transit / bicycling toggles, KML, ground overlay."""
    nist = get_geo("NIST")
    overlay_bounds = {"south": nist["lat"] - 0.05, "west": nist["lon"] - 0.08,
                      "north": nist["lat"] + 0.05, "east": nist["lon"] + 0.08}
    return {
        "traffic": {"type": "TrafficLayer", "enabled": False},
        "transit": {"type": "TransitLayer", "enabled": False},
        "bicycling": {"type": "BicyclingLayer", "enabled": False},
        "kml": {"type": "KmlLayer", "url": KML_LAYER_URL, "enabled": True,
                "preserveViewport": True, "suppressInfoWindows": False},
        "groundOverlay": {"type": "GroundOverlay", "url": "assets/cover.png",
                          "bounds": overlay_bounds, "opacity": 0.6,
                          "clickable": False},
    }


class MapModel:
    """Offline google.maps.Map: options + state, firing the map events."""

    def __init__(self, options=None):
        self.events = EventEmitter()
        self._options = validate_map_options(options)
        self._center = dict(self._options["center"])
        self._zoom = self._options["zoom"]
        self._map_type_id = self._options["mapTypeId"]
        self._dragging = False

    @property
    def event_log(self):
        return list(self.events.log)

    def on(self, event, handler):
        if event not in MAP_EVENTS:
            raise ValueError(f"unknown Map event: {event}")
        return self.events.on(event, handler)

    def get_options(self):
        return dict(self._options)

    def get_center(self):
        return dict(self._center)

    def get_zoom(self):
        return self._zoom

    def get_map_type_id(self):
        return self._map_type_id

    def get_bounds(self):
        span_lat = 180.0 / (2 ** self._zoom)
        span_lng = 360.0 / (2 ** self._zoom)
        return {"south": self._center["lat"] - span_lat / 2.0,
                "west": self._center["lng"] - span_lng / 2.0,
                "north": self._center["lat"] + span_lat / 2.0,
                "east": self._center["lng"] + span_lng / 2.0}

    def _emit_bounds_changed(self):
        self.events.emit("bounds_changed", self.get_bounds())

    def set_center(self, lat, lng):
        new_center = {"lat": float(lat), "lng": float(lng)}
        if new_center != self._center:
            self._center = new_center
            self.events.emit("center_changed", dict(new_center))
            self._emit_bounds_changed()
        return self.get_center()

    def pan_to(self, lat, lng):
        return self.set_center(lat, lng)

    def set_zoom(self, zoom):
        zoom = max(self._options["minZoom"],
                   min(self._options["maxZoom"], int(zoom)))
        if zoom != self._zoom:
            self._zoom = zoom
            self.events.emit("zoom_changed", zoom)
            self._emit_bounds_changed()
        return self._zoom

    def set_map_type_id(self, map_type_id):
        if map_type_id not in MAP_TYPES:
            raise ValueError(f"unknown mapTypeId: {map_type_id}")
        if map_type_id != self._map_type_id:
            self._map_type_id = map_type_id
            self.events.emit("maptypeid_changed", map_type_id)
        return self._map_type_id

    def click(self, lat, lng):
        detail = {"lat": float(lat), "lng": float(lng)}
        self.events.emit("click", detail)
        return detail

    def begin_drag(self):
        if not self._dragging:
            self._dragging = True
            self.events.emit("dragstart", self.get_center())
            self.events.emit("drag", self.get_center())

    def end_drag(self):
        if self._dragging:
            self._dragging = False
            self.events.emit("dragend", self.get_center())


# --- Offline geocoding model ----------------------------------------------

def _formatted_address(body):
    return f"{body['name']} — {body['city']}, {body['country']}"


def geocode_forward(query):
    """Geocoder.geocode by address/name: body name -> coordinates."""
    body = find_body(query)
    if body is None:
        return {"status": "ZERO_RESULTS", "results": []}
    return {"status": "OK", "results": [{
        "formatted_address": _formatted_address(body),
        "geometry": {"location": {"lat": body["lat"], "lng": body["lon"]}},
        "body": body["name"]}]}


def geocode_reverse(lat, lng):
    """Reverse geocode: nearest body to arbitrary coordinates."""
    lat, lon = float(lat), float(lng)
    nearest, dist = None, None
    for body in all_bodies_with_geo():
        d = haversine_km(lat, lon, body["lat"], body["lon"])
        if dist is None or d < dist:
            nearest, dist = body, d
    return {"status": "OK", "results": [{
        "formatted_address": _formatted_address(nearest),
        "geometry": {"location": {"lat": nearest["lat"], "lng": nearest["lon"]}},
        "body": nearest["name"], "distance_km": dist}]}


def render_map_summary():
    """Map summary: markers by region, overall fit, per-region fits, layers."""
    markers = build_markers()
    fit = fit_bounds()
    lines = ["ACD-Quantum - Perfect Map (offline model)",
             f"Markers: {len(markers)} (label {MAPS_MARKER_LABEL}, animation DROP)"]
    regions = []
    for m in markers:
        if m["region"] not in regions:
            regions.append(m["region"])
    for region in regions:
        names = [m["title"] for m in markers if m["region"] == region]
        rfit = fit_bounds(region)
        lines.append(f"{region}: {len(names)} markers, "
                     f"fit center {rfit['center']}, suggested zoom {rfit['zoom']}")
        for name in names:
            lines.append(f"  - {name}")
    lines.append(f"Overall bounds: {fit['bounds']}")
    lines.append(f"Overall center: {fit['center']}  suggested zoom: {fit['zoom']}")
    lines.append(f"KmlLayer: {KML_LAYER_URL}")
    lines.append("Combined page: python3 main.py map --html --out map.html")
    return "\n".join(lines) + "\n"


def build_map_html():
    """Combined perfect-map page: google.maps.Map + linked Street View panel."""
    data_json = json.dumps(_bodies_js_data(), indent=1)
    options = validate_map_options()
    options_json = json.dumps({
        "center": options["center"], "zoom": options["zoom"],
        "mapTypeId": options["mapTypeId"],
        "mapTypeControl": True,
        "zoomControl": True, "scaleControl": True,
        "streetViewControl": True, "rotateControl": True,
        "fullscreenControl": True, "panControl": True,
        "gestureHandling": options["gestureHandling"],
        "minZoom": options["minZoom"], "maxZoom": options["maxZoom"]})
    parts = [
        "<!DOCTYPE html>",
        "<html><head><meta charset=\"utf-8\">",
        "<title>ACD-Quantum - Perfect Map + Street View</title>",
        "<style>html,body{height:100%;margin:0;font-family:sans-serif}"
        "#map{height:60%;width:100%}#pano{height:40%;width:100%}</style>",
        "</head><body>",
        "<div id=\"map\"></div>",
        "<div id=\"pano\"></div>",
        "<script>",
        f"const BODIES = {data_json};",
        f"const KML_URL = \"{KML_LAYER_URL}\";",
        "let map = null, panorama = null, infoWindow = null;",
        "function processSVData(data, status) {",
        "  if (status === \"OK\") {",
        "    panorama.setPosition(data.location.latLng);",
        "    panorama.setPov({heading: 270, pitch: 0});",
        "    panorama.setVisible(true);",
        "  } else {",
        "    alert(\"Street View data not found for this location.\");",
        "  }",
        "}",
        "function openPanorama(body) {",
        "  const service = new google.maps.StreetViewService();",
        "  service.getPanorama({location: {lat: body.lat, lng: body.lng},"
        " radius: 50, source: google.maps.StreetViewSource.OUTDOOR}, processSVData);",
        "}",
        "function initMap() {",
        f"  const mapOptions = {options_json};",
        "  mapOptions.mapTypeControlOptions = {",
        "    style: google.maps.MapTypeControlStyle.DROPDOWN_MENU,",
        "    mapTypeIds: [\"roadmap\", \"satellite\", \"hybrid\", \"terrain\"]};",
        "  map = new google.maps.Map(document.getElementById(\"map\"), mapOptions);",
        "  panorama = new google.maps.StreetViewPanorama(",
        "    document.getElementById(\"pano\"), {",
        "      pov: {heading: 34, pitch: 10}, visible: false,",
        "      clickToGo: false, linksControl: true, panControl: true,",
        "      zoomControl: true, addressControl: true,",
        "      motionTracking: true, motionTrackingControl: true,",
        "      showRoadLabels: true, scrollwheel: true});",
        "  map.setStreetView(panorama);",
        "  const traffic = new google.maps.TrafficLayer();",
        "  const transit = new google.maps.TransitLayer();",
        "  const bike = new google.maps.BicyclingLayer();",
        "  // Layers are constructed ready to toggle: traffic.setMap(map) etc.",
        "  const kmlLayer = new google.maps.KmlLayer({url: KML_URL,"
        " preserveViewport: true, suppressInfoWindows: false});",
        "  kmlLayer.setMap(map);",
        "  infoWindow = new google.maps.InfoWindow();",
        "  BODIES.forEach(function (b) {",
        "    const marker = new google.maps.Marker({",
        "      position: {lat: b.lat, lng: b.lng}, map: map, title: b.name,",
        "      label: \"ACD\", draggable: false,",
        "      animation: google.maps.Animation.DROP});",
        "    marker.addListener(\"click\", function () {",
        "      infoWindow.setContent(\"<strong>\" + b.name + \"</strong><br>\" +",
        "        b.city + \", \" + b.country + \"<br>\" + b.category + \" - \" + b.role);",
        "      infoWindow.open(map, marker);",
        "      openPanorama(b);",
        "    });",
        "  });",
        "}",
        _maps_loader_js("initMap"),
        "</script></body></html>",
    ]
    return "\n".join(parts) + "\n"


# --------------------------------------------------------------------------
# 13. Self-checks
# --------------------------------------------------------------------------

def _raises_value_error(fn):
    try:
        fn()
    except ValueError:
        return True
    return False


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
    # Street View Service layer
    check("heading wraps and pitch clamps",
          wrap_heading(370) == 10.0 and wrap_heading(-10) == 350.0
          and clamp_pitch(120) == 90.0 and clamp_pitch(-120) == -90.0)
    _sv_all_ok = True
    for _b in bodies:
        _r = sv_get_panorama(location={"lat": _b["lat"], "lng": _b["lon"]})
        if _r["status"] != "OK" or len(_r["data"]["links"]) != 2:
            _sv_all_ok = False
    check("getPanorama OK for all 30 bodies, 2 links each", _sv_all_ok)
    check("getPanorama ZERO_RESULTS in the mid-Pacific",
          sv_get_panorama(location={"lat": -25.0, "lng": -140.0})["status"] == "ZERO_RESULTS")
    check("getPanorama UNKNOWN_ERROR with no location or pano",
          sv_get_panorama()["status"] == "UNKNOWN_ERROR")
    _nist_geo = get_geo("NIST")
    _nist_sv = streetview_for_body("NIST")
    check("NIST panorama record is stable",
          _nist_sv["pano"] == pano_id_for("NIST")
          and _nist_sv["lat"] == _nist_geo["lat"] and _nist_sv["status"] == "OK")
    check("custom panorama provider round-trips by pano id",
          sv_get_panorama_by_provider(pano_id_for("ETSI"))["status"] == "OK"
          and sv_get_panorama_by_provider("acd-does-not-exist")["status"] == "ZERO_RESULTS")
    _pano_model = StreetViewPanoramaModel(find_body("NIST"))
    _pano_model.set_pov(heading=400, pitch=45)
    _pano_model.set_pano(pano_id_for("ETSI"))
    _sv_events = [e for e, _ in _pano_model.event_log]
    check("panorama model fires pov/pano/links events",
          "pov_changed" in _sv_events and "pano_changed" in _sv_events
          and "links_changed" in _sv_events
          and _pano_model.get_pov()["heading"] == 40.0)
    _sv_html = build_streetview_html()
    check("streetview HTML has all 30 bodies + placeholder, no redaction",
          all(_b["name"] in _sv_html for _b in bodies)
          and MAPS_KEY_PLACEHOLDER in _sv_html and "<redacted>" not in _sv_html)
    check("motion tracking note is honest about HTTPS/browser",
          "HTTPS" in MOTION_TRACKING_NOTE and "browser" in MOTION_TRACKING_NOTE)
    check("SIx cycle reports streetview readiness",
          _cycle["streetview"]["ready"] is True and _cycle["streetview"]["bodies"] == 30)
    # Perfect Map layer
    _markers = build_markers()
    check("map has 30 markers labelled ACD",
          len(_markers) == 30 and all(m["label"] == "ACD" and m["animation"] == "DROP"
                                      and m["draggable"] is False for m in _markers))
    _fit_all = fit_bounds()
    check("overall bounds contain all 30 bodies",
          all(_fit_all["bounds"]["south"] <= _b["lat"] <= _fit_all["bounds"]["north"]
              and _fit_all["bounds"]["west"] <= _b["lon"] <= _fit_all["bounds"]["east"]
              for _b in bodies))
    check("per-region fit zooms are sane (2..12)",
          all(2 <= fit_bounds(_r)["zoom"] <= 12
              for _r in ("North America", "Europe", "Asia-Pacific")))
    check("KmlLayer URL is well-formed",
          KML_LAYER_URL.startswith("https://") and KML_LAYER_URL.endswith(".kml")
          and map_layers()["kml"]["url"] == KML_LAYER_URL)
    _map_model = MapModel()
    _map_model.set_center(40.0, -100.0)
    _map_model.set_zoom(5)
    _map_model.set_map_type_id("satellite")
    _map_events = [e for e, _ in _map_model.event_log]
    check("map model fires center/zoom/bounds/maptype events",
          "center_changed" in _map_events and "zoom_changed" in _map_events
          and "bounds_changed" in _map_events and "maptypeid_changed" in _map_events)
    _map_html = build_map_html()
    check("combined map HTML has map + panorama + 30 bodies + placeholder",
          "google.maps.Map" in _map_html and "StreetViewPanorama" in _map_html
          and all(_b["name"] in _map_html for _b in bodies)
          and MAPS_KEY_PLACEHOLDER in _map_html and "<redacted>" not in _map_html)
    check("geocode forward/reverse round-trips NIST",
          geocode_forward("NIST")["results"][0]["geometry"]["location"]["lat"] == _nist_geo["lat"]
          and geocode_reverse(_nist_geo["lat"], _nist_geo["lon"])["results"][0]["body"] == "NIST")
    check("map options validation rejects bad mapTypeId",
          _raises_value_error(lambda: validate_map_options({"mapTypeId": "moon"})))

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
    nist_sv = streetview_for_body("NIST")
    print(f"Street View: {len(all_bodies_with_geo())} panoramas modelled; "
          f"NIST pano {nist_sv['pano']} heading {nist_sv['pov']['heading']} "
          f"pitch {nist_sv['pov']['pitch']} status {nist_sv['status']}")
    print(f"Perfect Map: {len(build_markers())} markers, "
          f"overall fit zoom {fit_bounds()['zoom']}, KmlLayer {KML_LAYER_URL}")
    print()
    return run_checks()


def main(argv=None):
    parser = argparse.ArgumentParser(description="ACD-Quantum - Quantum Cyber Security structure tree and tools")
    parser.add_argument("mode", nargs="?", default="demo",
                        choices=["demo", "tree", "checks", "scan", "plan", "qkd", "qrng", "hndl",
                                 "earth", "kml", "distance", "decide", "six", "ledger",
                                 "images", "recommend", "compose", "streetview", "map"])
    parser.add_argument("body_arg", nargs="?", default=None,
                        help="Optional body name (streetview single-body mode)")
    parser.add_argument("--scope", default="all", choices=["all", "national", "international"])
    parser.add_argument("--html", action="store_true",
                        help="Generate standalone HTML for streetview / map modes")
    parser.add_argument("--body", default=None,
                        help="Body name for streetview single-body mode")
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
        sv = cycle["streetview"]
        print(f"Street View: ready ({sv['bodies']} panoramas, "
              f"sample pano {sv['sample_pano']}, embed mode: {sv['embed_mode']})")
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
    if args.mode == "streetview":
        if args.html:
            page = build_streetview_html()
            if args.out:
                with open(args.out, "w", encoding="utf-8") as fh:
                    fh.write(page)
                print(f"Street View HTML written to {args.out} "
                      f"({page.count('\"name\"')} body records, {len(page)} bytes)")
            else:
                print(page, end="")
            return 0
        body_query = args.body or args.body_arg
        if body_query:
            rec = streetview_for_body(body_query)
            if rec is None:
                print(f"error: unknown body: {body_query}")
                return 1
            for k in ("body", "status", "pano", "lat", "lon", "city", "country",
                      "pov", "date", "copyright"):
                print(f"{k}: {rec[k]}")
            print("links:")
            for link in rec["links"]:
                print(f"  heading={link['heading']} pano={link['pano']} "
                      f"-> {link['description']}")
            print(f"options: {rec['options']}")
            print(f"motion_tracking_note: {rec['motion_tracking_note']}")
            return 0
        print(render_streetview_table(), end="")
        return 0
    if args.mode == "map":
        if args.html:
            page = build_map_html()
            if args.out:
                with open(args.out, "w", encoding="utf-8") as fh:
                    fh.write(page)
                print(f"Map HTML written to {args.out} "
                      f"({page.count('\"name\"')} body records, {len(page)} bytes)")
            else:
                print(page, end="")
            return 0
        print(render_map_summary(), end="")
        return 0
    return 0 if demo() else 1


if __name__ == "__main__":
    sys.exit(main())
