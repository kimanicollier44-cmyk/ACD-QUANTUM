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
 13. Media + sensing layer (models / specs / plans only): voice
     recognition (speech-to-intent over text), speech speaker (TTS
     presets + SSML-like speech plans), audio analysis on generated
     sample buffers / WAV files, a Bluetooth device / profile /
     pairing-security model over a labelled synthetic scan, and a
     3D 8K cinematic camera spec + capture-plan model
 14. Monad chain layer: chain profile (mainnet 143 / testnet 10143),
     10k TPS simulator at 300 ms blocks / 600 ms finality, optimistic
     parallel execution model, EIP-1559 tx + lifecycle model, EVM
     account quantum-risk audit (ECDSA flagged by the scanner),
     validator / bridge / MEV risk models, recommended-features
     catalog - offline models only, no live RPC, no keys, no real txs
 15. Self-checks runner printing CHECKS x/x

Honest limits: this is an educational / planning tool. The QKD and QRNG
modules are classical simulations of quantum protocols - they do not use
real quantum hardware, do not produce true quantum randomness, and do not
by themselves make any real system quantum-safe. Real migration must use
validated implementations of the NIST standards. The media layer is
likewise models, specs, plans and text / sample-data processing only:
no real microphone, speaker hardware, Bluetooth radio or camera is
accessed, the Bluetooth scan is synthetic, and the voiceprints are
synthetic demo vectors - never real biometric identification. The
Monad chain layer is likewise offline models and simulations only:
no live RPC calls, no keys, and no real transactions.
"""

import argparse
import hashlib
import json
import math
import os
import random
import re
import struct
import sys
import wave
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
                         "streetview_bodies": len(all_bodies_with_geo()),
                         "media": {"voice_ready": True,
                                   "speaker_ready": True,
                                   "audio_ready": True,
                                   "bluetooth_ready": True,
                                   "camera_ready": True,
                                   "hardware_accessed": False},
                         "chain": {"monad_ready": True,
                                   "chain_id": 143,
                                   "live_calls": False}})

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
                           "embed_mode": "streetview"},
            "media": {"voice_ready": True, "speaker_ready": True,
                      "audio_ready": True, "bluetooth_ready": True,
                      "camera_ready": True, "hardware_accessed": False,
                      "bluetooth_scan": "synthetic",
                      "voiceprints": "synthetic demo vectors"},
            "monad": {"ready": True, "chain_id": 143,
                      "throughput_tps": MONAD_TPS_CEILING,
                      "block_time_ms": MONAD_BLOCK_MS,
                      "finality_ms": MONAD_FINALITY_MS,
                      "live_calls": False}}


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
# 13. Media + sensing layer (models / specs / plans - NO hardware access)
# --------------------------------------------------------------------------

MEDIA_HONESTY_NOTE = (
    "Media layer = offline models, specs, plans and text/sample-data "
    "processing only. No real microphone, speaker hardware, Bluetooth "
    "radio or camera is accessed; the Bluetooth scan is synthetic and "
    "the voiceprints are synthetic demo vectors, never real biometrics.")

# --- 13a. Voice recognition: speech-to-intent over supplied text ----------

WAKE_PHRASES = ("hey acd quantum", "ok acd quantum", "hey acd", "ok acd",
                "acd quantum", "acd")

# Command grammar: (phrases, mode). Longer / more specific phrases first.
VOICE_GRAMMAR = [
    (("run checks", "run the checks", "self checks", "check yourself"), "checks"),
    (("ai tools", "security tools", "must have ai tools"), "aitools"),
    (("prompt codes", "prompt code", "secret codes", "claude codes", "gemini codes", "codes"), "codes"),
    (("glossary", "define", "what is rag", "ai glossary"), "glossary"),
    (("career stack", "career path", "career reality", "career"), "career"),
    (("cyber map", "cybermap", "cybersecurity domains", "what cybersecurity actually is"), "cybermap"),
    (("knowledge layer", "knowledge", "merge 9", "merge nine"), "knowledge"),
    (("monad tps", "monad throughput", "monad speed"), "monad-tps"),
    (("monad parallel", "parallel execution"), "monad-parallel"),
    (("monad quantum risk", "monad risk"), "monad-risk"),
    (("monad plan", "monad migration"), "monad-plan"),
    (("check monad", "monad"), "monad"),
    (("street view", "streetview", "show panorama", "open panorama"), "streetview"),
    (("distance from", "distance between", "distance"), "distance"),
    (("docker images", "recommended images", "show images", "images"), "images"),
    (("compose", "docker compose"), "compose"),
    (("recommend", "recommendations"), "recommend"),
    (("neural core", "six cycle", "run six", "six"), "six"),
    (("ledger", "audit ledger", "show the ledger"), "ledger"),
    (("google earth", "earth", "show earth"), "earth"),
    (("export kml", "kml"), "kml"),
    (("open map", "show map", "perfect map", "map"), "map"),
    (("structure tree", "show tree", "tree"), "tree"),
    (("migration plan", "make a plan", "plan"), "plan"),
    (("argon decide", "decide", "decision", "verdict"), "decide"),
    (("scan", "scanner", "check algorithms"), "scan"),
    (("quantum key distribution", "qkd", "bb84"), "qkd"),
    (("quantum random", "qrng"), "qrng"),
    (("hndl", "harvest now", "mosca"), "hndl"),
    (("voice demo", "voice"), "voice"),
    (("speaker presets", "speech presets", "speaker"), "speaker"),
    (("audio", "sound check", "tone"), "audio"),
    (("bluetooth", "pairing"), "bluetooth"),
    (("camera", "cinematic", "8k"), "camera"),
]

_ALGO_TOKEN_RE = re.compile(
    r"ML-KEM-\d+|ML-DSA-\d+|SLH-DSA|RSA-\d+|ECDSA|ECDH|X25519|P-256|"
    r"AES-\d+|SHA-\d+|HQC|MD5|DES|DH")


def normalize_transcript(text):
    """Lower-case, strip punctuation, collapse whitespace (deterministic)."""
    cleaned = re.sub(r"[^a-z0-9\-\s]", " ", str(text).lower())
    return re.sub(r"\s+", " ", cleaned).strip()


def _extract_algorithms(command_text):
    """Algorithm slots, in order of appearance, from a normalised command."""
    upper = command_text.upper()
    found = []
    for match in _ALGO_TOKEN_RE.finditer(upper):
        token = match.group(0)
        if token not in found:
            found.append(token)
    return found


def _extract_body(command_text):
    """Longest body name mentioned in the command, or None."""
    best = None
    for body in all_bodies_with_geo():
        if body["name"].lower() in command_text:
            if best is None or len(body["name"]) > len(best):
                best = body["name"]
    return best


def _extract_distance_bodies(command_text):
    """Parse 'distance NIST to ETSI' / 'distance from NIST to ETSI' slots."""
    text = command_text
    for prefix in ("distance from ", "distance between ", "distance "):
        if text.startswith(prefix):
            text = text[len(prefix):]
            break
    if " to " not in text:
        return None
    left, right = text.split(" to ", 1)
    a, b = find_body(left.strip()), find_body(right.strip())
    if a is None or b is None:
        return None
    return {"from_body": a["name"], "to_body": b["name"],
            "km": distance_between(a["name"], b["name"])["km"]}


def parse_voice_command(transcript):
    """
    Deterministic speech-to-intent over a supplied transcript string.
    Returns wake handling, matched mode, extracted slots and a confidence
    score (exact / fuzzy / unknown). No microphone is involved - the
    transcript is text the caller already has.
    """
    raw = str(transcript or "")
    text = normalize_transcript(raw)
    wake_detected, wake_phrase, command = False, None, text
    for wake in WAKE_PHRASES:
        if text == wake or text.startswith(wake + " "):
            wake_detected, wake_phrase = True, wake
            command = text[len(wake):].strip()
            break
    result = {"transcript": raw, "normalized": text,
              "wake_detected": wake_detected, "wake_phrase": wake_phrase,
              "command": command, "mode": None, "intent": None,
              "slots": {}, "confidence": 0.0, "confidence_level": "unknown",
              "status": "no_match", "hardware_accessed": False,
              "note": MEDIA_HONESTY_NOTE}
    if not command:
        result["intent"] = "wake_only"
        result["confidence_level"] = "fuzzy"
        result["confidence"] = 0.5
        return result
    # Slot-driven routes first (distance / scan carry their own payloads).
    if command.startswith("distance"):
        slots = _extract_distance_bodies(command)
        if slots:
            result.update({"mode": "distance", "intent": "distance",
                           "slots": slots, "confidence": 0.97,
                           "confidence_level": "exact", "status": "matched"})
            return result
    for phrases, mode in VOICE_GRAMMAR:
        for phrase in phrases:
            if command == phrase or command.startswith(phrase + " "):
                slots = {}
                if mode == "scan":
                    slots["algorithms"] = _extract_algorithms(command)
                body = _extract_body(command)
                if body and mode in ("streetview", "map", "earth", "camera"):
                    slots["body"] = body
                result.update({"mode": mode, "intent": mode, "slots": slots,
                               "confidence": 0.98 if command == phrase else 0.94,
                               "confidence_level": "exact",
                               "status": "matched"})
                return result
    # Fuzzy path: any grammar keyword appearing anywhere in the command.
    for phrases, mode in VOICE_GRAMMAR:
        if any(p in command for p in phrases):
            slots = {}
            if mode == "scan":
                slots["algorithms"] = _extract_algorithms(command)
            body = _extract_body(command)
            if body and mode in ("streetview", "map", "earth", "camera"):
                slots["body"] = body
            result.update({"mode": mode, "intent": mode, "slots": slots,
                           "confidence": 0.78, "confidence_level": "fuzzy",
                           "status": "matched"})
            return result
    return result


def route_voice_command(transcript):
    """
    Route a transcript through the SIx state machine: LISTENING parses,
    THINKING resolves the intent, RESPONDING builds the speech plan.
    """
    core = SixNeuralCore()
    core.transition("LISTENING")
    parsed = parse_voice_command(transcript)
    core.transition("THINKING")
    core.transition("RESPONDING")
    if parsed["status"] == "matched":
        reply = (f"Understood. Running {parsed['mode']} mode"
                 + (f" for {parsed['slots']['body']}"
                    if parsed["slots"].get("body") else "")
                 + (f" on {', '.join(parsed['slots']['algorithms'])}"
                    if parsed["slots"].get("algorithms") else "")
                 + ".")
    else:
        reply = ("I did not recognise that command. Try: scan, plan, "
                 "decide, earth, street view, map, bluetooth or camera.")
    speech = build_speech_plan(reply)
    core.transition("IDLE")
    return {"parsed": parsed, "states": [row[2] for row in core.history],
            "reply_text": reply, "speech_plan": speech}


def diarize_transcript(transcript):
    """
    Split a supplied multi-speaker transcript into turns. Speaker tags are
    'NAME:' or 'SPEAKER n:' at the start of a segment (line or inline).
    Returns turns plus per-speaker word counts. Text processing only.
    """
    text = str(transcript or "")
    tag_re = re.compile(r"(?m)^\s*([A-Za-z][A-Za-z0-9 ._-]{0,40}?)\s*:\s*")
    matches = list(tag_re.finditer(text))
    turns = []
    if not matches:
        words = len(text.split())
        if words:
            turns.append({"speaker": "UNKNOWN", "text": text.strip(),
                          "word_count": words})
    else:
        for i, match in enumerate(matches):
            start = match.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            segment = text[start:end].strip()
            turns.append({"speaker": match.group(1).strip().upper(),
                          "text": segment,
                          "word_count": len(segment.split())})
    speakers = {}
    for turn in turns:
        entry = speakers.setdefault(turn["speaker"],
                                    {"turns": 0, "words": 0})
        entry["turns"] += 1
        entry["words"] += turn["word_count"]
    return {"turns": turns, "speakers": speakers,
            "total_words": sum(t["word_count"] for t in turns),
            "note": "Diarization model over supplied tagged text only."}


def _synthetic_voiceprint(seed_text, dimensions=8):
    """Deterministic synthetic voiceprint vector (demo data, NOT biometric)."""
    digest = hashlib.sha256(f"acd-voiceprint:{seed_text}".encode()).digest()
    vector = [round(b / 255.0, 4) for b in digest[:dimensions]]
    norm = math.sqrt(sum(v * v for v in vector)) or 1.0
    return [round(v / norm, 4) for v in vector]


# Enrolled demo speakers: synthetic vectors only, labelled as such.
ENROLLED_VOICEPRINTS = {
    "Darion (demo)": _synthetic_voiceprint("darion-demo"),
    "Analyst (demo)": _synthetic_voiceprint("analyst-demo"),
    "Operator (demo)": _synthetic_voiceprint("operator-demo"),
}
VOICEPRINT_THRESHOLD = 0.82


def cosine_similarity(a, b):
    """Cosine similarity of two equal-length numeric vectors."""
    if len(a) != len(b) or not a:
        raise ValueError("vectors must be non-empty and equal length")
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return round(dot / (na * nb), 4)


def match_voiceprint(vector, threshold=VOICEPRINT_THRESHOLD):
    """
    Match a synthetic voiceprint vector against the enrolled demo set.
    Below threshold the speaker is UNKNOWN. SYNTHETIC DEMO DATA ONLY -
    this is a similarity model, never real biometric identification.
    """
    scored = sorted(((cosine_similarity(vector, enrolled), name)
                     for name, enrolled in ENROLLED_VOICEPRINTS.items()),
                    reverse=True)
    best_score, best_name = scored[0]
    matched = best_score >= threshold
    return {"speaker": best_name if matched else "UNKNOWN",
            "similarity": best_score, "threshold": threshold,
            "matched": matched, "synthetic_demo_data": True,
            "biometric_identification": False,
            "note": "Synthetic demo vectors only - not a real voiceprint."}


# --- 13b. Speech speaker: TTS presets + SSML-like speech plans ------------

VOICE_PRESETS = [
    {"id": "acd-narrator", "name": "ACD Narrator", "language": "en-US",
     "gender_style": "neutral", "rate": 1.0, "pitch": 0, "volume": 80},
    {"id": "acd-analyst", "name": "ACD Analyst", "language": "en-US",
     "gender_style": "feminine", "rate": 1.05, "pitch": 2, "volume": 75},
    {"id": "acd-commander", "name": "ACD Commander", "language": "en-GB",
     "gender_style": "masculine", "rate": 0.92, "pitch": -3, "volume": 85},
    {"id": "acd-alert", "name": "ACD Alert", "language": "en-US",
     "gender_style": "neutral", "rate": 1.15, "pitch": 4, "volume": 95},
]
SPEECH_RANGES = {"rate": (0.5, 2.0), "pitch": (-12, 12), "volume": (0, 100)}


def _clamp(value, low, high):
    return max(low, min(high, value))


def get_voice_preset(preset_id="acd-narrator"):
    for preset in VOICE_PRESETS:
        if preset["id"] == preset_id:
            return dict(preset)
    raise ValueError(f"unknown voice preset: {preset_id}")


def build_speech_plan(text, preset_id="acd-narrator", rate=None, pitch=None,
                      volume=None, break_ms=250):
    """
    Build an SSML-like speech plan for text. Rate / pitch / volume are
    validated and clamped to SPEECH_RANGES; the text is XML-escaped in
    the markup. This is a plan/spec - no speaker hardware is driven.
    """
    preset = get_voice_preset(preset_id)
    rate = _clamp(float(rate if rate is not None else preset["rate"]),
                  *SPEECH_RANGES["rate"])
    pitch = _clamp(float(pitch if pitch is not None else preset["pitch"]),
                   *SPEECH_RANGES["pitch"])
    volume = _clamp(float(volume if volume is not None else preset["volume"]),
                    *SPEECH_RANGES["volume"])
    break_ms = int(_clamp(int(break_ms), 0, 5000))
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", str(text))
                 if s.strip()]
    body = f' <break time="{break_ms}ms"/> '.join(
        _xml_escape(s) for s in sentences)
    ssml = (f'<speak version="1.0" xml:lang="{preset["language"]}">'
            f'<prosody rate="{rate}" pitch="{pitch:+.0f}st" '
            f'volume="{volume:.0f}">{body}</prosody></speak>')
    return {"preset": preset["id"], "preset_name": preset["name"],
            "language": preset["language"],
            "gender_style": preset["gender_style"],
            "rate": rate, "pitch": pitch, "volume": volume,
            "break_ms": break_ms, "text": str(text), "ssml": ssml,
            "sentences": len(sentences), "hardware_accessed": False,
            "note": "Speech plan only - no speaker hardware is driven."}


class SpeechQueue:
    """Utterance queue model: enqueue speech plans, speak in FIFO order."""

    def __init__(self):
        self._items = []

    def enqueue(self, plan):
        self._items.append(plan)
        return len(self._items)

    def peek(self):
        return self._items[0] if self._items else None

    def next(self):
        return self._items.pop(0) if self._items else None

    def clear(self):
        self._items.clear()

    def __len__(self):
        return len(self._items)


def speak_verdict(items=None, stakes="final"):
    """Render the Argon 4 verdict + readiness summary as a speech plan."""
    items = list(items) if items is not None else list(DEMO_INVENTORY)
    decision = argon_decide(items, stakes=stakes)
    ready = migration_readiness(items, has_inventory=True)
    text = (f"ACD Quantum decision: {decision['verdict']}. "
            f"Migration readiness is {ready['score']} out of 100, "
            f"grade {ready['grade']}. "
            f"{len(decision['required_actions'])} required actions remain.")
    return build_speech_plan(text, preset_id="acd-narrator")


# --- 13c. Audio: stdlib analysis on generated buffers / WAV files ---------

AUDIO_FORMATS = [
    {"format": "WAV", "codec": "PCM 16-bit", "lossless": True,
     "typical_bitrate_kbps": 1411, "use": "mastering / analysis"},
    {"format": "FLAC", "codec": "FLAC", "lossless": True,
     "typical_bitrate_kbps": 700, "use": "lossless archive"},
    {"format": "MP3", "codec": "MP3", "lossless": False,
     "typical_bitrate_kbps": 192, "use": "legacy distribution"},
    {"format": "AAC", "codec": "AAC-LC", "lossless": False,
     "typical_bitrate_kbps": 160, "use": "streaming / mobile"},
    {"format": "Opus", "codec": "Opus", "lossless": False,
     "typical_bitrate_kbps": 96, "use": "voice / low-bitrate streaming"},
]
LOUDNESS_TARGETS = {"podcast": -16.0, "streaming": -14.0, "broadcast": -23.0}


def generate_tone_samples(frequency=440.0, seconds=1.0, sample_rate=16000,
                          amplitude=0.5):
    """Deterministic 16-bit sine test tone as a list of int samples."""
    count = int(seconds * sample_rate)
    amp = _clamp(float(amplitude), 0.0, 1.0) * 32767
    return [int(round(amp * math.sin(2 * math.pi * frequency * i / sample_rate)))
            for i in range(count)]


def write_wav(path, samples, sample_rate=16000, channels=1):
    """Write 16-bit PCM samples to a WAV file with the stdlib wave module."""
    frames = b"".join(struct.pack("<h", int(_clamp(s, -32768, 32767)))
                      for s in samples)
    with wave.open(str(path), "wb") as wf:
        wf.setnchannels(channels)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(frames)
    return str(path)


def analyse_audio_samples(samples, sample_rate=16000, channels=1,
                          bit_depth=16):
    """Level analysis of a 16-bit sample buffer (RMS / peak / dBFS / silence)."""
    samples = list(samples)
    if not samples or sample_rate <= 0 or channels <= 0:
        raise ValueError("need samples, a positive sample rate and channels")
    full_scale = float(2 ** (bit_depth - 1))
    norm = [s / full_scale for s in samples]
    rms = math.sqrt(sum(v * v for v in norm) / len(norm))
    peak = max(abs(v) for v in norm)
    dbfs = round(20 * math.log10(rms), 2) if rms > 0 else -120.0
    silence = sum(1 for v in norm if abs(v) < 0.01) / len(norm)
    return {"sample_rate": sample_rate, "channels": channels,
            "bit_depth": bit_depth, "samples": len(samples),
            "duration_seconds": round(len(samples) / (sample_rate * channels), 4),
            "rms": round(rms, 4), "peak": round(peak, 4),
            "peak_dbfs": round(20 * math.log10(peak), 2) if peak > 0 else -120.0,
            "rms_dbfs": dbfs, "silence_ratio": round(silence, 4),
            "estimated_lufs": round(dbfs - 3.01, 2),
            "loudness_basis": "estimate from RMS dBFS, not a BS.1770 meter"}


def analyse_wav(path):
    """Analyse a 16-bit WAV file: format params + level analysis."""
    with wave.open(str(path), "rb") as wf:
        params = {"sample_rate": wf.getframerate(),
                  "channels": wf.getnchannels(),
                  "bit_depth": wf.getsampwidth() * 8,
                  "frames": wf.getnframes()}
        raw = wf.readframes(params["frames"])
    if params["bit_depth"] != 16:
        raise ValueError("only 16-bit WAV analysis is modelled")
    samples = list(struct.unpack(f"<{len(raw) // 2}h", raw))
    result = analyse_audio_samples(samples, params["sample_rate"],
                                   params["channels"], params["bit_depth"])
    result["format"] = "WAV"
    result["path"] = str(path)
    return result


def loudness_check(measured_lufs, target="podcast", tolerance=1.0):
    """Compare a loudness estimate against a labelled delivery target."""
    if target not in LOUDNESS_TARGETS:
        raise ValueError(f"unknown loudness target: {target}")
    goal = LOUDNESS_TARGETS[target]
    delta = round(float(measured_lufs) - goal, 2)
    return {"target": target, "target_lufs": goal,
            "measured_lufs": float(measured_lufs), "delta_lu": delta,
            "within_tolerance": abs(delta) <= tolerance,
            "note": "Labelled estimate targets (-16 podcast / -14 streaming "
                    "/ -23 broadcast LUFS)."}


def audio_pipeline_spec():
    """Mic-in -> recognition -> speaker-out pipeline spec (model only)."""
    return {"input_profile": {"device": "modelled USB/BLE microphone",
                              "sample_rate": 48000, "channels": 1,
                              "bit_depth": 16, "hardware_accessed": False},
            "recognition": {"engine": "ACD speech-to-intent (text model)",
                            "wake_phrases": list(WAKE_PHRASES),
                            "grammar_modes": sorted({m for _, m in VOICE_GRAMMAR})},
            "output_profile": {"device": "modelled speaker output",
                               "presets": [p["id"] for p in VOICE_PRESETS],
                               "plan_format": "SSML-like markup",
                               "hardware_accessed": False},
            "note": MEDIA_HONESTY_NOTE}


# --- 13d. Bluetooth: device / profile / pairing-security model ------------

BLUETOOTH_SERVICES = [
    {"name": "Heart Rate", "uuid": "0x180D", "kind": "GATT service",
     "transport": "BLE"},
    {"name": "Battery Service", "uuid": "0x180F", "kind": "GATT service",
     "transport": "BLE"},
    {"name": "Device Information", "uuid": "0x180A", "kind": "GATT service",
     "transport": "BLE"},
    {"name": "Generic Access", "uuid": "0x1800", "kind": "GATT service",
     "transport": "BLE + Classic"},
    {"name": "A2DP", "uuid": "0x110D", "kind": "profile",
     "transport": "Classic", "use": "stereo audio streaming"},
    {"name": "HFP", "uuid": "0x111E", "kind": "profile",
     "transport": "Classic", "use": "hands-free calls"},
    {"name": "AVRCP", "uuid": "0x110E", "kind": "profile",
     "transport": "Classic", "use": "media remote control"},
    {"name": "LE Audio (ASCS)", "uuid": "0x184E", "kind": "profile",
     "transport": "BLE", "use": "LC3 audio over BLE"},
    {"name": "Auracast (PACS)", "uuid": "0x1850", "kind": "profile",
     "transport": "BLE", "use": "broadcast audio"},
]
_PAIRING_METHODS = {
    "numeric_comparison": {"label": "Numeric Comparison",
                           "stack": "LE Secure Connections",
                           "mitm_protection": True, "authenticated": True,
                           "verdict": "STRONG"},
    "passkey_entry": {"label": "Passkey Entry",
                      "stack": "LE Secure Connections",
                      "mitm_protection": True, "authenticated": True,
                      "verdict": "STRONG"},
    "out_of_band": {"label": "Out of Band (OOB)",
                    "stack": "LE Secure Connections",
                    "mitm_protection": True, "authenticated": True,
                    "verdict": "STRONG"},
    "just_works": {"label": "Just Works", "stack": "LE (legacy or SC)",
                   "mitm_protection": False, "authenticated": False,
                   "verdict": "WEAK"},
    "legacy_pin": {"label": "Legacy PIN", "stack": "Bluetooth Classic legacy",
                   "mitm_protection": False, "authenticated": False,
                   "verdict": "WEAK"},
}


def bluetooth_synthetic_scan(tx_power=-59):
    """
    SYNTHETIC scan results (labelled): no radio is scanned. Distances are
    estimated from RSSI with the log-distance path-loss model.
    """
    raw = [
        ("ACD Field Headset", "7C:2F:80:11:AC:01", "BLE", -48, True,
         "numeric_comparison", ["0x180F", "0x184E", "0x1850"]),
        ("Quantum Lab Sensor", "7C:2F:80:11:AC:02", "BLE", -62, True,
         "just_works", ["0x180D", "0x180F", "0x180A"]),
        ("ACD Lab Speaker", "7C:2F:80:11:AC:03", "Classic", -71, True,
         "passkey_entry", ["0x110D", "0x110E", "0x111E"]),
        ("Legacy Keyboard", "7C:2F:80:11:AC:04", "Classic", -83, True,
         "legacy_pin", ["0x180A"]),
        ("Unknown Beacon", "7C:2F:80:11:AC:05", "BLE", -90, False,
         "just_works", ["0x180F"]),
    ]
    devices = []
    for name, address, transport, rssi, connectable, pairing, uuids in raw:
        devices.append({
            "name": name, "address": address, "transport": transport,
            "rssi_dbm": rssi, "connectable": connectable,
            "pairing_method": pairing, "service_uuids": uuids,
            "services": [s["name"] for s in BLUETOOTH_SERVICES
                         if s["uuid"] in uuids],
            "distance_m": estimate_distance_m(rssi, tx_power=tx_power),
            "synthetic": True})
    return devices


def estimate_distance_m(rssi_dbm, tx_power=-59, path_loss_exponent=2.0):
    """Log-distance path-loss estimate: d = 10 ** ((Tx - RSSI) / (10 * n))."""
    return round(10 ** ((tx_power - float(rssi_dbm)) /
                        (10 * path_loss_exponent)), 2)


def assess_pairing(method):
    """Security assessment of a pairing method (MITM / authentication)."""
    key = str(method).strip().lower().replace(" ", "_").replace("-", "_")
    if key not in _PAIRING_METHODS:
        raise ValueError(f"unknown pairing method: {method}")
    result = dict(_PAIRING_METHODS[key])
    result["method"] = key
    result["flag"] = ("WEAK - no MITM protection, do not trust for "
                      "sensitive data" if result["verdict"] == "WEAK"
                      else "OK - authenticated, MITM-protected pairing")
    return result


class BondingStore:
    """Bonding store model: remembered pairings keyed by device address."""

    def __init__(self):
        self._bonds = {}

    def bond(self, device, method=None):
        method = method or device.get("pairing_method", "just_works")
        record = {"name": device["name"], "address": device["address"],
                  "transport": device.get("transport"),
                  "assessment": assess_pairing(method), "bonded": True}
        self._bonds[device["address"]] = record
        return record

    def get(self, address):
        return self._bonds.get(address)

    def list(self):
        return [self._bonds[k] for k in sorted(self._bonds)]

    def remove(self, address):
        return self._bonds.pop(address, None) is not None

    def __len__(self):
        return len(self._bonds)


def bluetooth_security_assessment(devices=None):
    """Assess every scanned device's pairing; weakest link first."""
    devices = list(devices) if devices is not None else bluetooth_synthetic_scan()
    rows = []
    for device in devices:
        assessment = assess_pairing(device["pairing_method"])
        rows.append({"name": device["name"], "address": device["address"],
                     "method": device["pairing_method"],
                     "verdict": assessment["verdict"],
                     "mitm_protection": assessment["mitm_protection"],
                     "flag": assessment["flag"]})
    order = {"WEAK": 0, "STRONG": 1}
    rows.sort(key=lambda r: (order[r["verdict"]], r["name"]))
    weak = [r for r in rows if r["verdict"] == "WEAK"]
    return {"devices": rows, "weak_count": len(weak),
            "weakest": rows[0] if rows else None,
            "strongest": rows[-1] if rows else None,
            "synthetic_scan": True, "hardware_accessed": False,
            "note": "Synthetic scan + pairing model - no radio accessed."}


# --- 13e. 3D 8K cinematic camera: spec + capture-plan model ---------------

CAMERA_RESOLUTIONS = {
    "8K DCI": {"width": 8192, "height": 4320, "label": "8K DCI (8192x4320)"},
    "8K UHD": {"width": 7680, "height": 4320, "label": "8K UHD (7680x4320)"},
    "4K DCI": {"width": 4096, "height": 2160, "label": "4K DCI (4096x2160)"},
    "4K UHD": {"width": 3840, "height": 2160, "label": "4K UHD (3840x2160)"},
}
CAMERA_FRAME_RATES = {24: "cinematic", 30: "broadcast", 60: "smooth",
                      120: "slow motion"}
CAMERA_CODECS = {
    "RAW": {"bits_per_pixel": 48.0, "bit_depth": 16, "kind": "uncompressed raw"},
    "ProRes 422 HQ": {"bits_per_pixel": 12.0, "bit_depth": 10,
                      "kind": "intra-frame mezzanine"},
    "H.265": {"bits_per_pixel": 1.2, "bit_depth": 10,
              "kind": "long-GOP distribution"},
    "H.264": {"bits_per_pixel": 2.0, "bit_depth": 8,
              "kind": "long-GOP legacy"},
}
CAMERA_COLOR_PIPELINES = [
    {"name": "RAW", "bit_depth": 16, "note": "sensor data, grade in post"},
    {"name": "LOG", "bit_depth": 10, "note": "flat profile for grading"},
    {"name": "HDR10", "bit_depth": 10, "note": "PQ transfer, static metadata"},
    {"name": "HLG", "bit_depth": 10, "note": "hybrid log-gamma broadcast HDR"},
]
CAMERA_STABILIZATION = ["locked-off tripod", "3-axis gimbal",
                        "IBIS (in-body)", "electronic (EIS)", "handheld"]


def camera_spec_summary():
    """The full 3D 8K cinematic camera spec model (no camera accessed)."""
    return {"resolutions": CAMERA_RESOLUTIONS,
            "frame_rates": CAMERA_FRAME_RATES,
            "codecs": CAMERA_CODECS,
            "color_pipelines": CAMERA_COLOR_PIPELINES,
            "sensor": {"width_mm": 36.0, "height_mm": 24.0,
                       "format": "full frame (modelled)"},
            "stereo_3d": {"default_interaxial_mm": 65,
                          "note": "twin-lens / rig model, depth budget checked"},
            "photo_mode": {"burst_fps": 20, "formats": ["RAW", "RAW+JPEG"]},
            "stabilization": CAMERA_STABILIZATION,
            "hardware_accessed": False, "note": MEDIA_HONESTY_NOTE}


def estimate_storage(resolution="8K DCI", fps=24, codec="RAW",
                     card_capacity_gb=512):
    """Bitrate + storage estimate from resolution x fps x codec model."""
    if resolution not in CAMERA_RESOLUTIONS:
        raise ValueError(f"unknown resolution: {resolution}")
    if codec not in CAMERA_CODECS:
        raise ValueError(f"unknown codec: {codec}")
    res = CAMERA_RESOLUTIONS[resolution]
    bpp = CAMERA_CODECS[codec]["bits_per_pixel"]
    bits_per_s = res["width"] * res["height"] * float(fps) * bpp
    mb_s = round(bits_per_s / 8 / 1_000_000, 2)
    gb_hour = round(mb_s * 3600 / 1000, 2)
    return {"resolution": resolution, "width": res["width"],
            "height": res["height"], "fps": fps, "codec": codec,
            "frame_rate_class": CAMERA_FRAME_RATES.get(fps, "custom"),
            "mb_per_s": mb_s, "gb_per_min": round(mb_s * 60 / 1000, 2),
            "gb_per_hour": gb_hour,
            "card_capacity_minutes": round(card_capacity_gb / gb_hour * 60, 1)
            if gb_hour else 0.0,
            "card_capacity_gb": card_capacity_gb}


def camera_fov(focal_mm, sensor_width_mm=36.0, sensor_height_mm=24.0):
    """Horizontal / vertical / diagonal FOV from focal length + sensor."""
    if focal_mm <= 0:
        raise ValueError("focal length must be positive")
    h = math.degrees(2 * math.atan(sensor_width_mm / (2 * focal_mm)))
    v = math.degrees(2 * math.atan(sensor_height_mm / (2 * focal_mm)))
    diag = math.hypot(sensor_width_mm, sensor_height_mm)
    d = math.degrees(2 * math.atan(diag / (2 * focal_mm)))
    return {"focal_mm": focal_mm, "hfov_deg": round(h, 2),
            "vfov_deg": round(v, 2), "dfov_deg": round(d, 2)}


def framing_at_distance(focal_mm, distance_m, sensor_width_mm=36.0,
                        sensor_height_mm=24.0):
    """Subject-plane width/height framed at a distance, + distance solver."""
    fov = camera_fov(focal_mm, sensor_width_mm, sensor_height_mm)
    width_m = 2 * distance_m * math.tan(math.radians(fov["hfov_deg"]) / 2)
    height_m = 2 * distance_m * math.tan(math.radians(fov["vfov_deg"]) / 2)
    return {"focal_mm": focal_mm, "distance_m": distance_m,
            "frame_width_m": round(width_m, 2),
            "frame_height_m": round(height_m, 2), "fov": fov}


def stereo_depth_budget(interaxial_mm=65, convergence_m=3.0, nearest_m=1.0,
                        farthest_m=10.0, max_parallax_deg=3.0):
    """Stereo 3D depth-budget check (model): parallax at the nearest plane."""
    if not (0 < nearest_m < convergence_m < farthest_m):
        raise ValueError("need 0 < nearest < convergence < farthest")
    baseline_m = interaxial_mm / 1000.0
    parallax = math.degrees(baseline_m * (1 / nearest_m - 1 / convergence_m))
    return {"interaxial_mm": interaxial_mm, "convergence_m": convergence_m,
            "nearest_m": nearest_m, "farthest_m": farthest_m,
            "max_parallax_deg": round(parallax, 2),
            "budget_deg": max_parallax_deg,
            "within_budget": parallax <= max_parallax_deg,
            "note": "Model estimate - check on a 3D monitor before capture."}


def camera_capture_plan(body_query, resolution="8K DCI", fps=24,
                        codec="ProRes 422 HQ"):
    """
    Capture plan for filming a body's HQ: ties the Earth coordinates and
    the Street View pano id (merges 5/6) to a 3D 8K camera plan. Spec /
    plan only - no camera is accessed and nothing is recorded.
    """
    body = find_body(body_query)
    if body is None:
        return None
    sv = streetview_for_body(body["name"])
    storage = estimate_storage(resolution, fps, codec)
    return {"body": body["name"], "city": body["city"],
            "country": body["country"], "lat": body["lat"],
            "lon": body["lon"], "streetview_pano": sv["pano"],
            "streetview_heading": sv["pov"]["heading"],
            "resolution": resolution, "fps": fps, "codec": codec,
            "storage": storage,
            "stereo": stereo_depth_budget(),
            "fov_35mm": camera_fov(35),
            "color_pipeline": "LOG (grade to HDR10)",
            "stabilization": "3-axis gimbal",
            "shot_list": ["establishing wide of HQ approach (Street View "
                          "heading)", "orbit move at convergence distance",
                          "detail pass: signage / entrance",
                          "photo burst RAW+JPEG for the record"],
            "hardware_accessed": False, "note": MEDIA_HONESTY_NOTE}


# --------------------------------------------------------------------------
# 14. Monad chain layer (offline models / simulations - NO live RPC)
# --------------------------------------------------------------------------

MONAD_HONESTY_NOTE = (
    "Monad layer = offline deterministic models and simulations only. "
    "No live RPC calls are made, no keys are used, and no real "
    "transactions are created, signed or broadcast. Throughput, latency "
    "and timing figures are simulated estimates against the published "
    "Monad catalog parameters, not measurements of the live network.")

# Published Monad catalog parameters (Monad docs, page updated 2026-07-23):
# 10,000 TPS, 300 ms block frequency, 600 ms finality, MonadBFT consensus,
# RaptorCast block propagation, asynchronous / deferred execution,
# optimistic parallel execution, MonadDB, 100% EVM compatible.
MONAD_TPS_CEILING = 10000
MONAD_BLOCK_MS = 300
MONAD_FINALITY_MS = 600

MONAD_NETWORKS = [
    {"name": "Monad Mainnet", "network": "mainnet", "chain_id": 143,
     "rpc_url": "https://rpc.monad.xyz",
     "explorer_url": "https://monadexplorer.com",
     "currency": "MON", "label": "catalog data (public endpoint)"},
    {"name": "Monad Testnet", "network": "testnet", "chain_id": 10143,
     "rpc_url": "https://testnet-rpc.monad.xyz",
     "explorer_url": "https://testnet.monadexplorer.com",
     "currency": "MON", "label": "catalog data (public endpoint)"},
]

MONAD_TOKEN_PROFILE = {
    "name": "Monad", "symbol": "MON", "decimals": 18,
    "total_supply": 100_000_000_000, "fixed_supply": True,
    "label": "catalog data - labelled model entry, not a live balance",
}

MONAD_TX_MIX = {"transfers": 0.45, "swaps": 0.25, "mints": 0.10,
                "contract_calls": 0.20}

# Gas figures are labelled estimates in the EVM model; a plain transfer is
# the canonical 21,000 gas.
MONAD_GAS_ESTIMATES = {"transfer": 21000, "erc20_transfer": 45000,
                       "swap": 150000, "mint": 90000,
                       "contract_call": 100000}

MONAD_RPC_METHODS = ["eth_blockNumber", "eth_call", "eth_chainId",
                     "eth_estimateGas", "eth_getBalance",
                     "eth_getTransactionByHash",
                     "eth_getTransactionReceipt", "eth_sendRawTransaction"]

MONAD_SAMPLE_EOA = "0x1234567890AbcdEF1234567890aBcdef12345678"


def monad_network(network="mainnet"):
    """One Monad network catalog entry by name ('mainnet' / 'testnet')."""
    for entry in MONAD_NETWORKS:
        if entry["network"] == str(network).strip().lower():
            return dict(entry)
    return None


def monad_recommended_features():
    """The recommended Monad feature set - every entry merged in ACD."""
    rows = [
        ("10,000 TPS throughput",
         "Catalog ceiling of 10,000 transactions per second; the TPS "
         "simulator flags anything above it EXCEEDS_CATALOG_CEILING."),
        ("300 ms block frequency",
         "Blocks every 300 ms (~3.33 blocks/sec, ~3,000 tx per block at "
         "the 10k TPS ceiling)."),
        ("600 ms finality",
         "Transactions reach finality in ~600 ms in the lifecycle timing "
         "model (mempool -> proposed -> voted -> finalized)."),
        ("MonadBFT consensus",
         "Byzantine fault tolerant consensus; quorum math is n - f with "
         "f = (n - 1) // 3 (n=100 -> quorum 67, f=33)."),
        ("RaptorCast block propagation",
         "Erasure-coded block propagation stage in the tx lifecycle "
         "model (the 'proposed' step)."),
        ("Optimistic parallel execution",
         "Transactions execute in parallel across lanes; conflicts are "
         "detected and re-executed (simulated with read/write sets)."),
        ("Asynchronous / deferred execution",
         "Execution is deferred relative to consensus ordering in the "
         "catalog model - ordering first, execution after."),
        ("MonadDB",
         "The chain's purpose-built state database (catalog entry)."),
        ("100% EVM equivalence",
         "Full EVM compatibility: EVM addresses, gas model and tooling "
         "carry over unchanged."),
        ("EIP-1559 fee market",
         "Transactions carry maxFeePerGas / maxPriorityFeePerGas fields "
         "in the transaction model."),
        ("JSON-RPC method catalog",
         "Standard eth_* method names catalogued (eth_call, "
         "eth_estimateGas, eth_sendRawTransaction, ...); monad-specific "
         "extensions are labelled catalog names only - nothing is called."),
        ("Quantum-risk account audit (ACD tie-in)",
         "EVM accounts use ECDSA / secp256k1, classified "
         "QUANTUM-VULNERABLE by the ACD scanner; per-account exposure "
         "reports + a PQC migration path are built in."),
    ]
    return [{"feature": name, "status": "merged", "description": desc}
            for name, desc in rows]


def monad_profile():
    """Full Monad chain profile: networks, token, performance catalog."""
    return {"networks": [dict(n) for n in MONAD_NETWORKS],
            "token": dict(MONAD_TOKEN_PROFILE),
            "throughput_tps": MONAD_TPS_CEILING,
            "block_time_ms": MONAD_BLOCK_MS,
            "finality_ms": MONAD_FINALITY_MS,
            "blocks_per_second": round(1000.0 / MONAD_BLOCK_MS, 3),
            "consensus": "MonadBFT",
            "propagation": "RaptorCast",
            "execution": ["asynchronous / deferred execution",
                          "optimistic parallel execution"],
            "database": "MonadDB",
            "evm_compatible": True,
            "rpc_methods": list(MONAD_RPC_METHODS),
            "features": monad_recommended_features(),
            "live_calls": False, "note": MONAD_HONESTY_NOTE}


def simulate_tps(target_tps=10000, seconds=3.0, seed=42):
    """
    Deterministic throughput simulation at the 300 ms block frequency.
    Per-block transaction counts jitter +-3% around the target share;
    latency percentiles are labelled simulated estimates.
    """
    target = int(target_tps)
    blocks_per_second = 1000.0 / MONAD_BLOCK_MS
    num_blocks = max(1, int(round(float(seconds) * blocks_per_second)))
    tx_per_block_target = target / blocks_per_second
    rng = random.Random(seed)
    per_block = [int(round(tx_per_block_target * (0.97 + 0.06 * rng.random())))
                 for _ in range(num_blocks)]
    total = sum(per_block)
    duration_s = num_blocks * MONAD_BLOCK_MS / 1000.0
    achieved = round(total / duration_s, 1) if duration_s else 0.0
    mix = {}
    assigned = 0
    kinds = list(MONAD_TX_MIX)
    for i, kind in enumerate(kinds):
        if i == len(kinds) - 1:
            mix[kind] = total - assigned
        else:
            mix[kind] = int(round(total * MONAD_TX_MIX[kind]))
            assigned += mix[kind]
    conflicts = int(round(total * 0.018))
    failed = int(round(total * 0.001))
    succeeded = total - failed
    exceeds = target > MONAD_TPS_CEILING
    return {"target_tps": target, "seconds": float(seconds),
            "blocks": num_blocks,
            "blocks_per_second": round(blocks_per_second, 3),
            "block_time_ms": MONAD_BLOCK_MS,
            "tx_per_block_target": round(tx_per_block_target, 1),
            "total_transactions": total,
            "achieved_tps": achieved,
            "tx_mix": mix,
            "conflicts": conflicts, "reexecuted": conflicts,
            "succeeded": succeeded, "failed": failed,
            "success_rate_pct": round(100.0 * succeeded / total, 2) if total else 0.0,
            "latency_ms_estimates": {"p50": 180, "p95": 420, "p99": 580,
                                     "label": "simulated estimate"},
            "finality_ms": MONAD_FINALITY_MS,
            "ceiling_flag": ("EXCEEDS_CATALOG_CEILING" if exceeds
                             else "WITHIN_CATALOG_CEILING"),
            "note": MONAD_HONESTY_NOTE}


def synthetic_parallel_batch(conflicting=True, count=12):
    """Synthetic transactions with read/write account sets (labelled)."""
    txs = []
    for i in range(int(count)):
        if conflicting:
            hot = "acct-hot" if i % 3 else "acct-hot-2"
            writes = [hot, f"acct-{i}"]
            reads = [f"acct-{(i + 1) % count}"]
        else:
            writes = [f"acct-{i}-w"]
            reads = [f"acct-{i}-r"]
        txs.append({"id": f"tx-{i + 1:02d}", "reads": reads,
                    "writes": writes, "synthetic": True})
    return txs


def parallel_execute(transactions=None, lanes=4, seed=42):
    """
    Optimistic parallel execution simulation: every transaction runs in
    parallel waves across lanes; a transaction whose write set touches an
    earlier transaction's accessed set (or whose reads touch an earlier
    write) conflicts and is re-executed in a follow-up wave.
    """
    txs = (list(transactions) if transactions is not None
           else synthetic_parallel_batch(conflicting=True))
    lanes = max(1, int(lanes))
    seen_writes, seen_access = set(), set()
    reexecuted_ids = []
    for tx in txs:
        reads = set(tx.get("reads", []))
        writes = set(tx.get("writes", []))
        if (writes & seen_access) or (reads & seen_writes):
            reexecuted_ids.append(tx["id"])
        seen_writes |= writes
        seen_access |= reads | writes
    n = len(txs)
    conflicts = len(reexecuted_ids)
    waves = math.ceil(n / lanes) if n else 0
    reexec_waves = math.ceil(conflicts / lanes) if conflicts else 0
    serial_units = n
    parallel_units = waves + reexec_waves
    speedup = round(serial_units / parallel_units, 2) if parallel_units else 0.0
    return {"transactions": n, "lanes": lanes, "conflicts": conflicts,
            "reexecutions": conflicts, "reexecuted_ids": reexecuted_ids,
            "serial_time_units": serial_units,
            "parallel_time_units": parallel_units, "speedup": speedup,
            "model": "optimistic parallel execution (labelled simulation)",
            "note": MONAD_HONESTY_NOTE}


def estimate_gas(tx_type="transfer"):
    """Labelled EVM gas estimate per transaction type (transfer = 21,000)."""
    key = str(tx_type).strip().lower()
    if key not in MONAD_GAS_ESTIMATES:
        raise ValueError(f"unknown transaction type: {tx_type}")
    return {"tx_type": key, "gas": MONAD_GAS_ESTIMATES[key],
            "label": "estimate (EVM model)"}


def validate_address(address):
    """EVM address format check: '0x' followed by exactly 40 hex chars."""
    return bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", str(address or "")))


def build_transaction(from_address, to_address, value_mon=0.0,
                      tx_type="transfer", nonce=0,
                      max_fee_per_gas=100, max_priority_fee_per_gas=2):
    """Validated EVM transaction model (EIP-1559 fields). Never broadcast."""
    if not validate_address(from_address):
        raise ValueError(f"invalid from address: {from_address}")
    if not validate_address(to_address):
        raise ValueError(f"invalid to address: {to_address}")
    if float(value_mon) < 0:
        raise ValueError("value must be >= 0")
    if int(nonce) < 0:
        raise ValueError("nonce must be >= 0")
    return {"from": from_address, "to": to_address,
            "value_mon": float(value_mon), "tx_type": tx_type,
            "gas": estimate_gas(tx_type)["gas"], "nonce": int(nonce),
            "maxFeePerGas": max_fee_per_gas,
            "maxPriorityFeePerGas": max_priority_fee_per_gas,
            "chain_id": monad_network("mainnet")["chain_id"],
            "status": "modelled - not signed, not broadcast",
            "note": MONAD_HONESTY_NOTE}


def tx_lifecycle(tx=None):
    """Lifecycle timing model: mempool -> proposed -> voted -> finalized."""
    stages = [{"state": "mempool", "at_ms": 0},
              {"state": "proposed (RaptorCast)", "at_ms": MONAD_BLOCK_MS},
              {"state": "voted (MonadBFT)", "at_ms": 450},
              {"state": "finalized", "at_ms": MONAD_FINALITY_MS}]
    return {"tx": tx, "states": stages, "final_state": "finalized",
            "block_time_ms": MONAD_BLOCK_MS,
            "finality_ms": MONAD_FINALITY_MS, "note": MONAD_HONESTY_NOTE}


def monad_migration_path():
    """PQC migration path for chain users, in the 5-phase plan language."""
    return [
        {"phase": 0, "name": "Discover",
         "action": "Inventory every EVM account, contract, admin key and "
                   "bridge position (CBOM for the chain estate)."},
        {"phase": 1, "name": "Prioritise (HNDL first)",
         "action": "Rank exposed public keys by value and shelf-life; "
                   "long-lived, high-value EOAs migrate first."},
        {"phase": 2, "name": "Replace vulnerable public-key",
         "action": "Move value off exposed ECDSA keys to fresh, "
                   "hash-based / ML-DSA-ready custody as PQC account "
                   "options land; rotate contract admin keys."},
        {"phase": 3, "name": "Strengthen symmetric + hybrid",
         "action": "AES-256 / SHA-384 everywhere off-chain; hybrid "
                   "(classical + PQC) signatures during transition."},
        {"phase": 4, "name": "Agility + verify",
         "action": "Keep signature schemes configurable (crypto-agility), "
                   "re-run the ACD quantum-risk audit yearly and on every "
                   "contract upgrade."},
    ]


def monad_account_risk(address, account_type="eoa", public_key_exposed=True):
    """
    Per-account quantum exposure report. EVM accounts sign with ECDSA on
    secp256k1 - classified by the existing ACD scanner (reuse, not a copy).
    An exposed EVM public key is a Shor target once a CRQC arrives.
    """
    valid = validate_address(address)
    cls = classify_algorithm("ECDSA")
    acct = str(account_type or "eoa").strip().lower()
    if not valid:
        rating, exposure = "UNKNOWN", "invalid address format"
    elif acct == "eoa" and public_key_exposed:
        rating = "HIGH"
        exposure = ("EOA with exposed public key - direct Shor target "
                    "once a CRQC arrives")
    elif acct == "eoa":
        rating = "MEDIUM"
        exposure = ("EOA, key not yet exposed on-chain; the public key "
                    "is revealed by the first outgoing transaction")
    elif acct == "contract":
        rating = "MEDIUM"
        exposure = ("contract account - risk concentrates in its "
                    "ECDSA admin / owner keys")
    else:
        rating, exposure = "MEDIUM", f"{acct} account - ECDSA-signed"
    return {"address": address, "valid": valid, "account_type": acct,
            "signature_scheme": "ECDSA (secp256k1)",
            "signature_status": cls["status"],
            "signature_detail": cls["detail"],
            "public_key_exposed": bool(public_key_exposed),
            "quantum_exposure": exposure, "risk_rating": rating,
            "chain_verdict": ("NO-GO" if rating == "HIGH"
                              else "CONDITIONAL GO"),
            "migration_path": monad_migration_path(),
            "note": MONAD_HONESTY_NOTE}


def monad_argon_chain_decision():
    """Argon 4 DECIDER over the chain exposure (ECDSA in the inventory)."""
    decision = argon_decide(["ECDSA", "AES-256"], stakes="final")
    return {"verdict": decision["verdict"],
            "trace_hash": decision["trace_hash"],
            "can_override": decision["seat"]["can_override"],
            "seat_id": decision["seat"]["seat_id"],
            "reason": "ECDSA (secp256k1) is quantum-vulnerable; the "
                      "tighten-only DECIDER keeps the chain verdict at "
                      "NO-GO until exposed keys are migrated."}


def smart_contract_audit(address=None, upgradeable=True, is_bridge=False):
    """Smart-contract quantum-risk audit checklist (model)."""
    entries = [
        {"item": "Signature scheme", "finding": "ECDSA (secp256k1)",
         "quantum_risk": "HIGH",
         "note": "Shor-vulnerable; plan ML-DSA / hash-based migration."},
        {"item": "Admin keys", "finding": "ECDSA admin / owner keys",
         "quantum_risk": "HIGH",
         "note": "Rotate to PQC-ready custody; prefer multisig with "
                 "distributed keys."},
        {"item": "Upgradeability",
         "finding": "upgradeable (proxy admin)" if upgradeable
                    else "immutable (no proxy)",
         "quantum_risk": "MEDIUM" if upgradeable else "LOW",
         "note": "An upgrade path is also a migration path - keep it, "
                 "guard the admin key." if upgradeable else
                 "No upgrade path: a quantum break cannot be patched."},
        {"item": "Bridge exposure",
         "finding": "bridge contract surface" if is_bridge
                    else "no bridge surface",
         "quantum_risk": "HIGH" if is_bridge else "LOW",
         "note": "Bridges concentrate value behind validator signatures."
                 if is_bridge else "No cross-chain signature surface."},
    ]
    overall = ("HIGH" if any(e["quantum_risk"] == "HIGH" for e in entries)
               else "MEDIUM")
    return {"address": address, "checklist": entries,
            "overall_quantum_risk": overall, "note": MONAD_HONESTY_NOTE}


def validator_quorum(n_validators):
    """MonadBFT quorum math: f = (n - 1) // 3, quorum = n - f (2/3+)."""
    n = int(n_validators)
    if n < 1:
        raise ValueError("validator count must be >= 1")
    f = (n - 1) // 3
    return {"validators": n, "quorum": n - f, "fault_tolerance": f,
            "rule": "quorum = n - f, f = (n - 1) // 3 (MonadBFT 2/3+)"}


def validator_set_model(n_validators=100):
    """Validator / staking model (stake-weighted, labelled model data)."""
    model = validator_quorum(n_validators)
    model.update({
        "consensus": "MonadBFT", "stake_weighted": True,
        "staking": {
            "delegated_stake": "supported (labelled model entry)",
            "unbonding": "labelled model entry - not a live parameter",
            "slashing_risks": ["double-signing (modelled entry)",
                               "extended downtime (modelled entry)"]},
        "note": MONAD_HONESTY_NOTE})
    return model


def bridge_risk(model="lock_mint", validator_count=8,
                signature_scheme="ECDSA"):
    """Bridge risk assessment (model): design x signatures x quorum size."""
    cls = classify_algorithm(signature_scheme)
    vulnerable = cls["status"] in ("vulnerable", "broken")
    if vulnerable and model == "lock_mint":
        rating = "HIGH"
    elif vulnerable:
        rating = "MEDIUM"
    else:
        rating = "LOW"
    return {"model": model, "validator_count": int(validator_count),
            "signature_scheme": signature_scheme,
            "signature_status": cls["status"], "quantum_risk": rating,
            "mitigations": ["raise validator-set size / quorum",
                            "migrate bridge signatures to ML-DSA / "
                            "hash-based schemes",
                            "cap locked value per bridge (HNDL exposure)"],
            "note": MONAD_HONESTY_NOTE}


def mev_protection_catalog():
    """MEV mitigation catalog entries (model)."""
    return [
        {"mitigation": "Private orderflow",
         "description": "Route transactions through private channels so "
                        "they are not visible in the public mempool."},
        {"mitigation": "Batch auctions",
         "description": "Uniform clearing price per batch removes "
                        "ordering advantage inside the batch."},
        {"mitigation": "Encrypted mempool (catalog entry)",
         "description": "Threshold-encrypted transaction pool; contents "
                        "revealed only after ordering."},
        {"mitigation": "Commit-reveal ordering (catalog entry)",
         "description": "Hide intent until the order is fixed."},
    ]


def render_monad():
    """Printable Monad profile + recommended-features catalog."""
    profile = monad_profile()
    lines = ["MONAD CHAIN LAYER (offline model - no live RPC, no keys, "
             "no real transactions)"]
    for net in profile["networks"]:
        lines.append(f"{net['name']:<14} chain_id={net['chain_id']:<6} "
                     f"rpc={net['rpc_url']} explorer={net['explorer_url']}")
    tok = profile["token"]
    lines.append(f"Token: {tok['symbol']} ({tok['name']}), "
                 f"{tok['decimals']} decimals, "
                 f"{tok['total_supply']:,} fixed supply")
    lines.append(f"Performance: {profile['throughput_tps']:,} TPS, "
                 f"{profile['block_time_ms']} ms blocks, "
                 f"{profile['finality_ms']} ms finality, "
                 f"{profile['consensus']} + {profile['propagation']}, "
                 f"{profile['database']}, 100% EVM compatible")
    lines.append("Recommended features (all merged):")
    for i, feat in enumerate(profile["features"], 1):
        lines.append(f"  {i:>2}. [{feat['status']}] {feat['feature']} - "
                     f"{feat['description']}")
    lines.append(f"note: {MONAD_HONESTY_NOTE}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# 15. Knowledge layer - Merge 9 (catalog / reference models transcribed
#     from Darion's six infographics - NOT live vendor integrations)
# --------------------------------------------------------------------------

KNOWLEDGE_HONESTY_NOTE = (
    "Knowledge layer = offline catalog / reference data transcribed from "
    "Darion's infographics. ACD-Quantum does NOT call CrowdStrike, "
    "SentinelOne, Claude, Gemini or any other vendor API live; the prompt "
    "codes are a reference registry, not commands sent to any model.")

KNOWLEDGE_SOURCES = [
    "13 Must-Have AI Tools for Cybersecurity (Endpoint, Cloud, SOC, and Pentesting)",
    "Claude Secret Codes (Simple prompts. Clearer thinking. Bigger results with Claude.)",
    "80 Secret Codes of Google Gemini",
    "The Ultimate AI Glossary",
    "Cybersecurity Career Reality - stack by @hacktanic",
    "What Cybersecurity Actually Is - pie by @hacktanic",
]

# --- 15a. 13 must-have AI tools for cybersecurity ---------------------------

AI_TOOLS = [
    {"number": 1, "name": "CrowdStrike Charlotte AI", "category": "ENDPOINT SECURITY",
     "description": "AI analyst that triages alerts and executes response actions."},
    {"number": 2, "name": "SentinelOne Purple AI", "category": "ENDPOINT SECURITY",
     "description": "Natural-language threat investigation and autonomous EDR/XDR response."},
    {"number": 3, "name": "Darktrace", "category": "NETWORK SECURITY",
     "description": "Self-learning anomaly detection across network, email, cloud, and OT."},
    {"number": 4, "name": "Wiz", "category": "CLOUD SECURITY",
     "description": "Cloud security posture management with AI workload discovery and risk mapping."},
    {"number": 5, "name": "Microsoft Security Copilot", "category": "SECURITY OPERATIONS",
     "description": "AI assistant for incident response and security operations."},
    {"number": 6, "name": "Palo Alto Cortex", "category": "SECURITY OPERATIONS",
     "description": "AI-driven XDR and SOC automation across endpoints and cloud."},
    {"number": 7, "name": "IBM QRadar Advisor", "category": "SIEM / THREAT INTELLIGENCE",
     "description": "AI-assisted threat prioritization and investigation inside QRadar."},
    {"number": 8, "name": "Cisco AI Security", "category": "NETWORK & IDENTITY SECURITY",
     "description": "Identity, network, and endpoint protection with AI-driven detection."},
    {"number": 9, "name": "Vectra AI", "category": "NETWORK & IDENTITY SECURITY",
     "description": "AI-powered network detection and response for hybrid environments."},
    {"number": 10, "name": "Acronis Cyber Protect AI", "category": "DATA PROTECTION",
     "description": "Integrated backup, disaster recovery, and endpoint security."},
    {"number": 11, "name": "Cybereason", "category": "ENDPOINT SECURITY",
     "description": "AI-powered extended detection and response across large-scale data."},
    {"number": 12, "name": "Pentera", "category": "PENTESTING",
     "description": "Agentic AI pentesting for continuous security validation."},
    {"number": 13, "name": "Guardz", "category": "SMALL BUSINESS SECURITY",
     "description": "AI-powered cybersecurity for small businesses and managed service providers."},
]

AI_TOOL_TAGLINE = "Endpoint, Cloud, SOC, and Pentesting"

_NEED_TO_TOOLS = {
    "endpoint": ["CrowdStrike Charlotte AI", "SentinelOne Purple AI", "Cybereason"],
    "network": ["Darktrace", "Vectra AI", "Cisco AI Security"],
    "cloud": ["Wiz", "Palo Alto Cortex"],
    "soc": ["Microsoft Security Copilot", "Palo Alto Cortex"],
    "pentesting": ["Pentera"],
    "pentest": ["Pentera"],
    "siem": ["IBM QRadar Advisor"],
    "threat intelligence": ["IBM QRadar Advisor"],
    "data-protection": ["Acronis Cyber Protect AI"],
    "data protection": ["Acronis Cyber Protect AI"],
    "backup": ["Acronis Cyber Protect AI"],
    "small-business": ["Guardz"],
    "small business": ["Guardz"],
    "identity": ["Cisco AI Security", "Vectra AI"],
}


def get_ai_tools():
    """The 13 must-have AI cybersecurity tools (catalog data, no live calls)."""
    return [dict(t) for t in AI_TOOLS]


def _tool_by_name(name):
    for tool in AI_TOOLS:
        if tool["name"].lower() == str(name).strip().lower():
            return tool
    return None


def tools_by_category(category):
    """Tools whose infographic category matches (case-insensitive)."""
    wanted = str(category).strip().lower()
    return [dict(t) for t in AI_TOOLS if t["category"].lower() == wanted]


def recommend_ai_tool(need):
    """Map a plain need (endpoint/network/cloud/soc/...) to catalog tools."""
    key = str(need).strip().lower()
    names = _NEED_TO_TOOLS.get(key)
    if names is None:
        names = _NEED_TO_TOOLS.get(_normalise(key), [])
    return [dict(_tool_by_name(n)) for n in names if _tool_by_name(n)]


def ai_tool_categories():
    """The distinct categories covered by the 13-tool catalog."""
    return sorted({t["category"] for t in AI_TOOLS})


def coverage_gap_check(categories_present):
    """Compare categories an org already covers against the catalog's."""
    present = {str(c).strip().lower() for c in categories_present}
    covered = [c for c in ai_tool_categories() if c.lower() in present]
    missing = [c for c in ai_tool_categories() if c.lower() not in present]
    total = len(ai_tool_categories())
    return {"covered": covered, "missing": missing,
            "covered_count": len(covered), "total_categories": total,
            "coverage_pct": round(100.0 * len(covered) / total, 1) if total else 0.0,
            "note": KNOWLEDGE_HONESTY_NOTE}


def render_aitools():
    lines = ["13 MUST-HAVE AI TOOLS FOR CYBERSECURITY",
             f"Tagline: {AI_TOOL_TAGLINE}",
             "Catalog / reference data only - no vendor API is called live.", ""]
    for tool in AI_TOOLS:
        lines.append(f"{tool['number']:>2}. {tool['name']} [{tool['category']}]")
        lines.append(f"    {tool['description']}")
        lines.append(f"    Closest cyber domain(s): "
                     f"{', '.join(domain_for_tool(tool['name']))}")
    lines.append("")
    lines.append(f"note: {KNOWLEDGE_HONESTY_NOTE}")
    return "\n".join(lines) + "\n"


# --- 15b. Claude secret codes (14) ------------------------------------------

CLAUDE_CODES_TAGLINE = ("Simple prompts. Clearer thinking. "
                        "Bigger results with Claude.")

CLAUDE_CODES = [
    {"number": 1, "code": "/godmode", "key": "godmode",
     "title": "Get Claude's most powerful mode",
     "description": "Use this to get deeper reasoning, more detailed and high-quality answers.",
     "example": "/godmode: Create a complete strategy with pros, cons and next steps."},
    {"number": 2, "code": "/devil", "key": "devil",
     "title": "Challenge your ideas",
     "description": "Ask Claude to act as a critical thinker and find weaknesses in your plan.",
     "example": "/devil: Analyse this idea and point out the flaws."},
    {"number": 3, "code": "/10x", "key": "10x",
     "title": "Make it 10x better",
     "description": "Use this to get a much stronger, clearer and more actionable version of your content.",
     "example": "/10x: Rewrite this pitch to make it 10x more compelling."},
    {"number": 4, "code": "/pitch", "key": "pitch",
     "title": "Create a 30-second pitch",
     "description": "Get a concise and impactful investor or client pitch.",
     "example": "/pitch: Create a 30-second investor pitch for my startup."},
    {"number": 5, "code": "/ghost", "key": "ghost",
     "title": "Write in a human-like way",
     "description": "Make the response sound natural, conversational and less AI-like.",
     "example": "/ghost: Rewrite this in a natural, human and conversational tone."},
    {"number": 6, "code": "/compare", "key": "compare",
     "title": "Do a side-by-side analysis",
     "description": "Compare options, tools or ideas with clear pros and cons.",
     "example": "/compare: Compare these two tools for content creation in a table."},
    {"number": 7, "code": "/scout", "key": "scout",
     "title": "Find risks and blind spots",
     "description": "Identify potential risks, challenges and things you might be missing.",
     "example": "/scout: What are the risks and blind spots in this plan?"},
    {"number": 8, "code": "/artifacts", "key": "artifacts-build",
     "title": "Build useful apps and tools",
     "description": "Ask Claude to create interactive tools, templates, dashboards or small apps in chat.",
     "example": "/artifacts: Create a habit tracker app with a clean UI."},
    {"number": 9, "code": "/ooda", "key": "ooda",
     "title": "Solve complex problems",
     "description": "Use the OODA loop (Observe, Orient, Decide, Act) for better and faster decision-making.",
     "example": "/ooda: Help me solve this problem using the OODA loop."},
    {"number": 10, "code": "/artifacts", "key": "artifacts-review",
     "title": "Improve and find faults",
     "description": "Analyse your work, find errors and suggest improvements.",
     "example": "/artifacts: Review this content and find what can be improved."},
    {"number": 11, "code": "/critique", "key": "critique",
     "title": "Get detailed feedback",
     "description": "Ask Claude to review and critique your content, ideas or plans with actionable advice.",
     "example": "/critique: Review this blog post and suggest improvements."},
    {"number": 12, "code": "/explainlikeim5", "key": "explainlikeim5",
     "title": "Get simple explanations",
     "description": "Use this to explain complex topics in a very simple and easy-to-understand way.",
     "example": "/explainlikeim5: Explain how blockchain works."},
    {"number": 13, "code": "/brief", "key": "brief",
     "title": "Get a short and clear answer",
     "description": "Get the key points without extra details or fluff.",
     "example": "/brief: Summarise this article in 5 key points."},
    {"number": 14, "code": "/teacher", "key": "teacher",
     "title": "Learn and debate with a mentor",
     "description": "Ask Claude to act as a teacher, mentor or debate partner to deepen your understanding.",
     "example": "/teacher: Explain this topic step by step and then ask me questions."},
]

CLAUDE_CODES_DUPLICATION_NOTE = (
    "Honest note: the source infographic lists /artifacts twice - #8 "
    "'Build useful apps and tools' and #10 'Improve and find faults'. "
    "Both entries are stored, keyed distinctly as artifacts-build and "
    "artifacts-review.")


def get_claude_codes():
    """The 14 Claude prompt codes, exactly as printed (incl. the dupe)."""
    return [dict(c) for c in CLAUDE_CODES]


def claude_code(name):
    """One Claude code by key, code text or number; first match or None."""
    query = str(name).strip().lower().lstrip("/")
    for entry in CLAUDE_CODES:
        if query in (entry["key"], entry["code"].lstrip("/"),
                     str(entry["number"])):
            return dict(entry)
    return None


def claude_code_all(name):
    """All Claude entries matching a code text (exposes the /artifacts dupe)."""
    query = str(name).strip().lower()
    if not query.startswith("/"):
        query = "/" + query
    return [dict(c) for c in CLAUDE_CODES if c["code"] == query]


# --- 15c. 80 secret codes of Google Gemini ----------------------------------
# (number, group, name, code, source_partially_visible)

_GEMINI_RAW = [
    (1, "SYSTEM OPERATORS", "Set Persona", "GEMINI::SYS::PERSONA:DEVELOPER", False),
    (2, "SYSTEM OPERATORS", "Set Persona", "GEMINI::SYS::PERSONA:ANALYST", False),
    (3, "SYSTEM OPERATORS", "Set Persona", "GEMINI::SYS::PERSONA:WRITER", False),
    (4, "SYSTEM OPERATORS", "Set Persona", "GEMINI::SYS::PERSONA:TEACHER", False),
    (5, "SYSTEM OPERATORS", "Set Persona", "GEMINI::SYS::PERSONA:DESIGNER", False),
    (6, "SYSTEM OPERATORS", "Code Interpreter ON", "GEMINI::MODE::CODE_INT/ON", False),
    (7, "SYSTEM OPERATORS", "Code Interpreter OFF", "GEMINI::MODE::CODE_INT/OFF", False),
    (8, "FUNCTIONAL TRIGGERS", "Code Interpreter ON", "GEMINI::MODE::CODE_INT/ON", False),
    (9, "FUNCTIONAL TRIGGERS", "Code Interpreter OFF", "GEMINI::MODE::CODE_INT/OFF", False),
    (10, "FUNCTIONAL TRIGGERS", "Deep Research", "GEMINI::MODE::RESEARCH/ON", False),
    (11, "FUNCTIONAL TRIGGERS", "Data Export (CSV)", "GEMINI::MODE::DATA_EXPORT/ON", False),
    (12, "FUNCTIONAL TRIGGERS", "Web Search", "GEMINI::MODE::SEARCH/ON", False),
    (13, "FUNCTIONAL TRIGGERS", "Canvas Mode", "GEMINI::MODE::CANVAS/ON", False),
    (14, "FUNCTIONAL TRIGGERS", "Voice Mode", "GEMINI::MODE::VOICE/ON", False),
    (15, "DATA HANDLING", "Data Export (CSV)", "GEMINI::DATA::EXPORT.CSV", False),
    (16, "DATA HANDLING", "Data Export (JSON)", "GEMINI::DATA::EXPORT.JSON", False),
    (17, "DATA HANDLING", "Data Export (XLSX)", "GEMINI::DATA::EXPORT.XLSX", False),
    (18, "DATA HANDLING", "Import Table", "GEMINI::DATA::IMPORT.TABLE", False),
    (19, "DATA HANDLING", "Clean Data", "GEMINI::DATA::CLEAN/AUTO", False),
    (20, "DATA HANDLING", "Merge Sheets", "GEMINI::DATA::MERGE/SHEETS", False),
    (21, "DATA HANDLING", "Chart Builder", "GEMINI::DATA::CHART/BUILD", False),
    (22, "DATA HANDLING", "Data Summary", "GEMINI::DATA::SUMMARY/AUTO", False),
    (23, "CREATIVE MODIFIERS", "Summarize", "GEMINI::CONTENT::SUMMARIZE/SHORT", False),
    (24, "CREATIVE MODIFIERS", "Summarize (Long)", "GEMINI::CONTENT::SUMMARIZE/LONG", False),
    (25, "CREATIVE MODIFIERS", "Rewrite", "GEMINI::CONTENT::REWRITE/CLEAR", False),
    (26, "CREATIVE MODIFIERS", "Expand", "GEMINI::CONTENT::EXPAND/DETAIL", False),
    (27, "CREATIVE MODIFIERS", "Shorten", "GEMINI::CONTENT::SHORTEN/50", False),
    (28, "CREATIVE MODIFIERS", "Change Tone", "GEMINI::CONTENT::TONE/FORMAL", False),
    (29, "CREATIVE MODIFIERS", "Casual Tone", "GEMINI::CONTENT::TONE/CASUAL", False),
    (30, "CREATIVE MODIFIERS", "Translate", "GEMINI::CONTENT::TRANSLATE/AUTO", False),
    (31, "CREATIVE MODIFIERS", "Bullet Points", "GEMINI::CONTENT::FORMAT/BULLETS", False),
    (32, "CREATIVE MODIFIERS", "Table Format", "GEMINI::CONTENT::FORMAT/TABLE", False),
    (33, "CREATIVE MODIFIERS", "Headline Ideas", "GEMINI::CONTENT::HEADLINES/10", False),
    (34, "CREATIVE MODIFIERS", "Hook Writer", "GEMINI::CONTENT::HOOKS/5", False),
    (35, "CREATIVE MODIFIERS", "Story Mode", "GEMINI::CONTENT::STORY/ON", False),
    (36, "CREATIVE MODIFIERS", "Script Writer", "GEMINI::CONTENT::SCRIPT/VIDEO", False),
    (37, "CREATIVE MODIFIERS", "Image Prompt", "GEMINI::GEN::IMG::PROMPT/CREATE", False),
    (38, "DEBUGGING COMMANDS", "Scan Errors", "GEMINI::DEBUG::SCAN/DEEP", False),
    (39, "DEBUGGING COMMANDS", "Scan Errors (Quick)", "GEMINI::DEBUG::SCAN/QUICK", False),
    (40, "DEBUGGING COMMANDS", "Find Bugs", "GEMINI::DEBUG::BUGS/FIND", False),
    (41, "DEBUGGING COMMANDS", "Fix Bugs", "GEMINI::DEBUG::BUGS/FIX", False),
    (42, "DEBUGGING COMMANDS", "Trace Stack", "GEMINI::DEBUG::TRACE/STACK", False),
    (43, "DEBUGGING COMMANDS", "Lint Code", "GEMINI::DEBUG::LINT/AUTO", False),
    (44, "DEBUGGING COMMANDS", "Test Cases", "GEMINI::DEBUG::TEST/GEN", False),
    (45, "DEBUGGING COMMANDS", "Explain Error", "GEMINI::DEBUG::EXPLAIN/ERROR", False),
    (46, "DEBUGGING COMMANDS", "Profile Speed", "GEMINI::DEBUG::PROFILE/SPEED", False),
    (47, "DEBUGGING COMMANDS", "Memory Check", "GEMINI::DEBUG::MEMORY/CHECK", False),
    (48, "DEBUGGING COMMANDS", "Log Review", "GEMINI::DEBUG::LOGS/REVIEW", False),
    (49, "DEBUGGING COMMANDS", "Dependency Scan", "GEMINI::DEBUG::DEPS/SCAN", False),
    (50, "DEBUGGING COMMANDS", "Security Scan", "GEMINI::DEBUG::SECURITY/SCAN", False),
    (51, "DEBUGGING COMMANDS", "Refactor", "GEMINI::DEBUG::REFACTOR/CLEAN", False),
    (52, "DEBUGGING COMMANDS", "Summarize Issue", "GEMINI::DEBUG::SUMMARIZE/SHORT", False),
    (53, "DEBUGGING COMMANDS", "Rollback Hint", "GEMINI::DEBUG::ROLLBACK/HINT", False),
    (54, "INTEGRATION & API", "Call Web API", "GEMINI::INT::API/CALL(ENDPOINT)", False),
    (55, "INTEGRATION & API", "Call Web API (POST)", "GEMINI::INT::API/POST(ENDPOINT)", False),
    (56, "INTEGRATION & API", "Fetch JSON", "GEMINI::INT::API/FETCH(JSON)", False),
    (57, "INTEGRATION & API", "Auth Token", "GEMINI::INT::API/AUTH(TOKEN)", False),
    (58, "INTEGRATION & API", "Webhook Send", "GEMINI::INT::API/WEBHOOK(SEND)", False),
    (59, "INTEGRATION & API", "Rate Limit Check", "GEMINI::INT::API/LIMIT(CHECK)", False),
    (60, "INTEGRATION & API", "Generate Image", "GEMINI::INT::API/IMG(CALL)", False),
    (61, "API CALLS", "Call Web API", "GEMINI::INT::API/CALL/API", True),
    (62, "API CALLS", "Call Web API", "GEMINI::INT::API/CALL(ENDPOINT)", True),
    (63, "API CALLS", "Generate API", "GEMINI::INT::API/GEN(SPEC)", True),
    (64, "API CALLS", "Call Web API (GET)", "GEMINI::INT::API/GET(ENDPOINT)", True),
    (65, "API CALLS", "Call Web API (PUT)", "GEMINI::INT::API/PUT(ENDPOINT)", True),
    (66, "API CALLS", "Generate Image", "GEMINI::GEN::IMG(ENDPOINT)", True),
    (67, "API CALLS", "Generate Image", "GEMINI::GEN::IMG::PROMPT=...", True),
    (68, "API CALLS", "Generate Image (Style)", "GEMINI::GEN::IMG::STYLE=...", True),
    (69, "API CALLS", "Generate Image (Size)", "GEMINI::GEN::IMG::SIZE=...", True),
    (70, "API CALLS", "Generate Image (Seed)", "GEMINI::GEN::IMG::SEED=...", True),
    (71, "API CALLS", "Generate Image (Batch)", "GEMINI::GEN::IMG::BATCH=...", True),
    (72, "QUICK ACTIONS", "Quick Reset", "GEMINI::SYS::RESET.ALL", False),
    (73, "QUICK ACTIONS", "Quick Reset (Chat)", "GEMINI::SYS::RESET.CHAT", False),
    (74, "QUICK ACTIONS", "Quick Reset (Memory)", "GEMINI::SYS::RESET.MEMORY", False),
    (75, "QUICK ACTIONS", "Quick Reset (Persona)", "GEMINI::SYS::RESET.PERSONA", False),
    (76, "QUICK ACTIONS", "Quick Reset (Mode)", "GEMINI::SYS::RESET.MODE", False),
    (77, "QUICK ACTIONS", "Quick Undo", "GEMINI::SYS::UNDO/LAST", False),
    (78, "QUICK ACTIONS", "Quick Redo", "GEMINI::SYS::REDO/LAST", False),
    (79, "QUICK ACTIONS", "Quick Save", "GEMINI::SYS::SAVE/CHAT", False),
    (80, "QUICK ACTIONS", "Quick Reset (Settings)", "GEMINI::SYS::RESET.SETTINGS", False),
]

GEMINI_CODES = [{"number": n, "group": g, "name": name, "code": code,
                 "source_partially_visible": partial}
                for n, g, name, code, partial in _GEMINI_RAW]

GEMINI_GROUPS = ["SYSTEM OPERATORS", "FUNCTIONAL TRIGGERS", "DATA HANDLING",
                 "CREATIVE MODIFIERS", "DEBUGGING COMMANDS",
                 "INTEGRATION & API", "API CALLS", "QUICK ACTIONS"]

GEMINI_DUPLICATION_NOTE = (
    "Honest note: the source prints Code Interpreter ON/OFF twice - as "
    "SYSTEM OPERATORS #6/#7 and again as FUNCTIONAL TRIGGERS #8/#9 - and "
    "several API / image codes repeat across groups. All 80 numbered "
    "entries are kept exactly as printed. Entries #61-#71 are partially "
    "cut off in the source photo and are flagged "
    "source_partially_visible=True (best-effort transcription).")


def get_gemini_codes():
    """All 80 Gemini codes, numbered as printed (duplicates kept)."""
    return [dict(c) for c in GEMINI_CODES]


def gemini_codes_by_group(group):
    """Gemini codes in one group (case-insensitive group name)."""
    wanted = str(group).strip().lower()
    return [dict(c) for c in GEMINI_CODES if c["group"].lower() == wanted]


def gemini_code(number):
    """One Gemini entry by its printed number (1-80), or None."""
    try:
        wanted = int(number)
    except (TypeError, ValueError):
        return None
    for entry in GEMINI_CODES:
        if entry["number"] == wanted:
            return dict(entry)
    return None


def gemini_duplicate_codes():
    """Code strings that appear more than once in the 80 (honesty check)."""
    counts = {}
    for entry in GEMINI_CODES:
        counts[entry["code"]] = counts.get(entry["code"], 0) + 1
    return {code: n for code, n in counts.items() if n > 1}


# --- Combined prompt-code registry: Claude 14 + Gemini 80 = 94 --------------

def get_prompt_codes():
    """Unified registry: every Claude code and every Gemini code."""
    registry = []
    for entry in CLAUDE_CODES:
        registry.append({"source": "claude", "number": entry["number"],
                         "code": entry["code"], "key": entry["key"],
                         "name": entry["title"],
                         "description": entry["description"],
                         "example": entry["example"]})
    for entry in GEMINI_CODES:
        registry.append({"source": "gemini", "number": entry["number"],
                         "code": entry["code"], "key": None,
                         "name": entry["name"], "group": entry["group"],
                         "description": f"Gemini {entry['group'].title()} code.",
                         "source_partially_visible":
                             entry["source_partially_visible"]})
    return registry


def lookup_prompt_code(query):
    """Search both registries by code text, name or keyword substring."""
    needle = str(query).strip().lower()
    if not needle:
        return []
    hits = []
    for entry in get_prompt_codes():
        haystack = " ".join(str(entry.get(k, "")) for k in
                            ("code", "name", "description", "group",
                             "key")).lower()
        if needle in haystack:
            hits.append(entry)
    return hits


def render_codes():
    lines = ["PROMPT SECRET CODES - CLAUDE 14 + GEMINI 80 = 94",
             f"Claude tagline: {CLAUDE_CODES_TAGLINE}",
             "Reference registry only - no code is sent to any live model.",
             "", "CLAUDE SECRET CODES (14):"]
    for entry in CLAUDE_CODES:
        lines.append(f"{entry['number']:>2}. {entry['code']} "
                     f"[{entry['key']}] - {entry['title']}")
        lines.append(f"    {entry['description']}")
        lines.append(f"    Example: {entry['example']}")
    lines.append(CLAUDE_CODES_DUPLICATION_NOTE)
    lines.append("")
    lines.append("80 SECRET CODES OF GOOGLE GEMINI (syntax GEMINI::<SECTION>::<CODE>):")
    for group in GEMINI_GROUPS:
        lines.append(f"  {group}:")
        for entry in gemini_codes_by_group(group):
            flag = " (source partially visible)" \
                if entry["source_partially_visible"] else ""
            lines.append(f"  {entry['number']:>2}. {entry['name']}: "
                         f"{entry['code']}{flag}")
    lines.append(GEMINI_DUPLICATION_NOTE)
    lines.append("")
    lines.append(f"note: {KNOWLEDGE_HONESTY_NOTE}")
    return "\n".join(lines) + "\n"


# --- 15d. The Ultimate AI Glossary (18 terms) -------------------------------

AI_GLOSSARY = [
    {"term": "Artificial Intelligence",
     "definition": "Software that performs tasks that normally require human intelligence, such as understanding language, recognising patterns and making decisions."},
    {"term": "Machine Learning",
     "definition": "A branch of AI where systems learn patterns from data instead of being explicitly programmed for every rule."},
    {"term": "Deep Learning",
     "definition": "Machine learning using large multi-layered neural networks that learn increasingly abstract features from data."},
    {"term": "Generative AI",
     "definition": "AI that creates new content - text, images, audio or code - by modelling the patterns in its training data."},
    {"term": "Foundation Model",
     "definition": "A large model trained on broad data that can be adapted to many different downstream tasks."},
    {"term": "LLM Model",
     "definition": "A deployed large language model - the trained network itself, as distinct from the application wrapped around it (listed separately from 'LLM' in the source)."},
    {"term": "Training vs Inference",
     "definition": "Training is the learning phase that fits a model's parameters to data; inference is using the trained model to produce outputs."},
    {"term": "LLM",
     "definition": "Large Language Model - a neural network with billions of parameters trained on huge text corpora to understand and generate language."},
    {"term": "Prompt Engineering",
     "definition": "Designing the input text given to a model to reliably get the desired output."},
    {"term": "Context Engineering",
     "definition": "Designing everything the model sees - instructions, retrieved facts, conversation history and tools - not just the single prompt."},
    {"term": "Transformer",
     "definition": "The neural-network architecture behind modern LLMs, built on attention, which weighs how each token relates to the others."},
    {"term": "Parameters",
     "definition": "The learned numeric weights of a model; their count is a rough measure of model size and capacity."},
    {"term": "Reasoning Model",
     "definition": "A model trained to work through problems step by step before answering, trading more compute for better answers on hard tasks."},
    {"term": "Chain of Thought",
     "definition": "Prompting or training a model to spell out intermediate reasoning steps before giving its final answer."},
    {"term": "Hallucination",
     "definition": "When a model generates confident-sounding content that is false or unsupported by its inputs."},
    {"term": "Grounding",
     "definition": "Anchoring a model's output in verified sources or retrieved facts so its answers can be checked."},
    {"term": "RAG",
     "definition": "Retrieval-Augmented Generation - the model retrieves relevant documents first, then generates an answer using them as context."},
    {"term": "Embeddings",
     "definition": "Numeric vector representations of text or other data that place similar meanings close together, enabling search and matching."},
]


def get_glossary():
    """The 18-term Ultimate AI Glossary."""
    return [dict(g) for g in AI_GLOSSARY]


def define(term):
    """Look up one glossary term (normalised / fuzzy); dict or None."""
    key = _normalise(term)
    for entry in AI_GLOSSARY:
        if _normalise(entry["term"]) == key:
            return dict(entry)
    for entry in AI_GLOSSARY:
        norm = _normalise(entry["term"])
        if key and (key in norm or norm in key):
            return dict(entry)
    return None


def glossary_quiz(seed=42, count=5):
    """Deterministic offline quiz: seeded sample of Q/A pairs."""
    rng = random.Random(seed)
    pool = list(AI_GLOSSARY)
    rng.shuffle(pool)
    picked = pool[:max(1, min(count, len(pool)))]
    return {"seed": seed,
            "questions": [{"term": e["term"],
                           "question": f"What is {e['term']}?",
                           "answer": e["definition"]} for e in picked],
            "note": "Deterministic offline quiz - same seed, same questions."}


def render_glossary():
    lines = ["THE ULTIMATE AI GLOSSARY (18 terms)", ""]
    for entry in AI_GLOSSARY:
        lines.append(f"{entry['term']}: {entry['definition']}")
    lines.append("")
    lines.append(f"note: {KNOWLEDGE_HONESTY_NOTE}")
    return "\n".join(lines) + "\n"


# --- 15e. Cybersecurity Career Reality stack (@hacktanic) -------------------

CAREER_STACK_CREDIT = "@hacktanic"

CAREER_STACK = [
    "Security Fundamentals",
    "Networking & Protocols",
    "Linux & System Security",
    "Programming & Scripting",
    "Cryptography",
    "Web Application Security",
    "Vulnerability Assessment",
    "Penetration Testing",
    "Incident Response",
    "SOC & Threat Monitoring",
    "Cloud Security",
    "Threat Intelligence",
    "Governance, Risk & Compliance",
    "Security Awareness",
    "Continuous Learning",
]


def get_career_stack():
    """The 15-layer career stack, top (layer 1) to bottom (layer 15)."""
    return [{"layer": i + 1, "name": name, "credit": CAREER_STACK_CREDIT}
            for i, name in enumerate(CAREER_STACK)]


def career_path_check(completed_layers):
    """Progress through the stack: % complete + the next layer to learn."""
    done = {str(x).strip().lower() for x in completed_layers}
    completed = [name for name in CAREER_STACK if name.lower() in done]
    remaining = [name for name in CAREER_STACK if name.lower() not in done]
    total = len(CAREER_STACK)
    return {"completed": completed, "completed_count": len(completed),
            "total_layers": total,
            "percent_complete": round(100.0 * len(completed) / total, 1),
            "next_layer": ({"layer": CAREER_STACK.index(remaining[0]) + 1,
                            "name": remaining[0]} if remaining else None),
            "remaining": remaining, "credit": CAREER_STACK_CREDIT}


def render_career():
    lines = ["CYBERSECURITY CAREER REALITY - the stack, top to bottom",
             f"Credit: {CAREER_STACK_CREDIT}", ""]
    for entry in get_career_stack():
        lines.append(f"{entry['layer']:>2}. {entry['name']}")
    lines.append("")
    lines.append(f"note: {KNOWLEDGE_HONESTY_NOTE}")
    return "\n".join(lines) + "\n"


# --- 15f. What cybersecurity actually is (@hacktanic) ------------------------

CYBER_MAP_CREDIT = "@hacktanic"
CYBER_MISCONCEPTION_LABEL = "Hacking"

CYBER_DOMAINS = [
    "Threat Intelligence",
    "Malware Analysis",
    "Incident Response",
    "Network Security",
    "Cloud Security",
    "Application Security",
    "Vulnerability Management",
    "Identity & Access Management",
    "Governance, Risk & Compliance",
    "Security Awareness",
    "SOC Operations",
    "Digital Forensics",
    "Penetration Testing",
    "Security Architecture",
]

_TOOL_TO_DOMAINS = {
    "CrowdStrike Charlotte AI": ["SOC Operations", "Incident Response"],
    "SentinelOne Purple AI": ["SOC Operations", "Digital Forensics"],
    "Darktrace": ["Network Security", "Threat Intelligence"],
    "Wiz": ["Cloud Security", "Vulnerability Management"],
    "Microsoft Security Copilot": ["SOC Operations", "Incident Response"],
    "Palo Alto Cortex": ["SOC Operations", "Network Security"],
    "IBM QRadar Advisor": ["Threat Intelligence", "SOC Operations"],
    "Cisco AI Security": ["Identity & Access Management", "Network Security"],
    "Vectra AI": ["Network Security", "Threat Intelligence"],
    "Acronis Cyber Protect AI": ["Incident Response", "Digital Forensics"],
    "Cybereason": ["SOC Operations", "Malware Analysis"],
    "Pentera": ["Penetration Testing", "Vulnerability Management"],
    "Guardz": ["Security Awareness", "Governance, Risk & Compliance"],
}

_LAYER_TO_DOMAINS = {
    "Security Fundamentals": ["Security Architecture"],
    "Networking & Protocols": ["Network Security"],
    "Linux & System Security": ["Security Architecture"],
    "Programming & Scripting": ["Application Security"],
    "Cryptography": ["Identity & Access Management"],
    "Web Application Security": ["Application Security"],
    "Vulnerability Assessment": ["Vulnerability Management"],
    "Penetration Testing": ["Penetration Testing"],
    "Incident Response": ["Incident Response"],
    "SOC & Threat Monitoring": ["SOC Operations"],
    "Cloud Security": ["Cloud Security"],
    "Threat Intelligence": ["Threat Intelligence"],
    "Governance, Risk & Compliance": ["Governance, Risk & Compliance"],
    "Security Awareness": ["Security Awareness"],
    "Continuous Learning": ["Malware Analysis", "Digital Forensics"],
}


def get_cyber_domains():
    """The 14 real domains of cybersecurity (pie by @hacktanic)."""
    return [{"domain": name, "credit": CYBER_MAP_CREDIT}
            for name in CYBER_DOMAINS]


def domain_for_tool(tool_name):
    """Closest cyber domain(s) for one of the 13 catalog AI tools."""
    tool = _tool_by_name(tool_name)
    if tool is None:
        return []
    return list(_TOOL_TO_DOMAINS.get(tool["name"], []))


def tools_for_domain(domain):
    """Catalog AI tools mapped to one cyber domain."""
    wanted = str(domain).strip().lower()
    return [name for name, domains in _TOOL_TO_DOMAINS.items()
            if any(d.lower() == wanted for d in domains)]


def domains_for_career_layer(layer_name):
    """Cyber domain(s) a career-stack layer feeds into, where natural."""
    for name, domains in _LAYER_TO_DOMAINS.items():
        if name.lower() == str(layer_name).strip().lower():
            return list(domains)
    return []


def render_cybermap():
    lines = ["WHAT CYBERSECURITY ACTUALLY IS",
             f"Credit: {CYBER_MAP_CREDIT}",
             f"Popular misconception (the umbrella label): "
             f"{CYBER_MISCONCEPTION_LABEL} - the field is really these "
             f"{len(CYBER_DOMAINS)} domains:", ""]
    for name in CYBER_DOMAINS:
        tools = tools_for_domain(name)
        suffix = f" - tools: {', '.join(tools)}" if tools else ""
        lines.append(f"  - {name}{suffix}")
    lines.append("")
    lines.append("AI tool -> domain cross-reference:")
    for tool in AI_TOOLS:
        lines.append(f"  {tool['name']}: "
                     f"{', '.join(domain_for_tool(tool['name']))}")
    lines.append("")
    lines.append(f"note: {KNOWLEDGE_HONESTY_NOTE}")
    return "\n".join(lines) + "\n"


# --- 15g. Unified Merge 9 surface --------------------------------------------

def knowledge_counts():
    """Entry counts for the whole Merge 9 knowledge layer."""
    counts = {"ai_tools": len(AI_TOOLS),
              "claude_codes": len(CLAUDE_CODES),
              "gemini_codes": len(GEMINI_CODES),
              "prompt_codes_total": len(get_prompt_codes()),
              "glossary_terms": len(AI_GLOSSARY),
              "career_layers": len(CAREER_STACK),
              "cyber_domains": len(CYBER_DOMAINS)}
    counts["total_entries"] = (counts["ai_tools"] + counts["claude_codes"]
                               + counts["gemini_codes"]
                               + counts["glossary_terms"]
                               + counts["career_layers"]
                               + counts["cyber_domains"])
    return counts


def render_knowledge():
    counts = knowledge_counts()
    lines = ["MERGE 9 - KNOWLEDGE LAYER (six infographics, one catalog)",
             f"note: {KNOWLEDGE_HONESTY_NOTE}", "", "Sources:"]
    for source in KNOWLEDGE_SOURCES:
        lines.append(f"  - {source}")
    lines += ["", "Counts:",
              f"  AI security tools: {counts['ai_tools']}",
              f"  Claude prompt codes: {counts['claude_codes']}",
              f"  Gemini prompt codes: {counts['gemini_codes']}",
              f"  Total prompt codes: {counts['prompt_codes_total']}",
              f"  Glossary terms: {counts['glossary_terms']}",
              f"  Career layers: {counts['career_layers']} "
              f"(credit {CAREER_STACK_CREDIT})",
              f"  Cyber domains: {counts['cyber_domains']} "
              f"(credit {CYBER_MAP_CREDIT})",
              f"  TOTAL ENTRIES: {counts['total_entries']}",
              "", "Cross-reference - AI tool -> cyber domain(s):"]
    for tool in AI_TOOLS:
        lines.append(f"  {tool['name']}: "
                     f"{', '.join(domain_for_tool(tool['name']))}")
    lines.append("")
    lines.append("Cross-reference - cyber domain -> AI tool(s):")
    for name in CYBER_DOMAINS:
        tools = tools_for_domain(name)
        lines.append(f"  {name}: {', '.join(tools) if tools else '(none)'}")
    lines.append("")
    lines.append(CLAUDE_CODES_DUPLICATION_NOTE)
    lines.append(GEMINI_DUPLICATION_NOTE)
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# 16. Self-checks
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
    # Media + sensing layer (merge 7: models / specs / plans, no hardware)
    _voice = parse_voice_command("ACD scan RSA-2048 and AES-256")
    check("voice wake phrase + scan intent + algorithm slots",
          _voice["wake_detected"] is True and _voice["mode"] == "scan"
          and _voice["slots"]["algorithms"] == ["RSA-2048", "AES-256"]
          and _voice["confidence_level"] == "exact")
    _voice_dist = parse_voice_command("hey ACD distance NIST to ETSI")
    check("voice distance slots resolve both bodies",
          _voice_dist["mode"] == "distance"
          and _voice_dist["slots"]["from_body"] == "NIST"
          and _voice_dist["slots"]["to_body"] == "ETSI"
          and _voice_dist["slots"]["km"] > 5000)
    check("voice unknown command is a labelled no-match",
          parse_voice_command("blorp the frobnicate")["status"] == "no_match"
          and parse_voice_command("blorp the frobnicate")["confidence"] == 0.0)
    _diar = diarize_transcript("DARION: scan the inventory now\n"
                               "ANALYST: readiness looks low today")
    check("diarization splits turns and counts words per speaker",
          _diar["speakers"]["DARION"]["words"] == 4
          and _diar["speakers"]["ANALYST"]["words"] == 4
          and _diar["total_words"] == 8)
    _vp_hit = match_voiceprint(ENROLLED_VOICEPRINTS["Darion (demo)"])
    _vp_miss = match_voiceprint([1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
    check("voiceprint synthetic match + UNKNOWN below threshold",
          _vp_hit["matched"] is True and _vp_hit["synthetic_demo_data"] is True
          and _vp_miss["speaker"] == "UNKNOWN")
    _speech = build_speech_plan("Hello <world> & friends.", rate=9, pitch=-99,
                                volume=500)
    check("speech plan clamps rate/pitch/volume and escapes markup",
          _speech["rate"] == 2.0 and _speech["pitch"] == -12
          and _speech["volume"] == 100 and "&lt;world&gt;" in _speech["ssml"]
          and "<world>" not in _speech["ssml"])
    _queue = SpeechQueue()
    _queue.enqueue(_speech)
    check("speech queue is FIFO and verdict plan renders",
          len(_queue) == 1 and _queue.next()["text"].startswith("Hello")
          and "decision:" in speak_verdict(["ML-KEM-1024", "AES-256"])["text"])
    import tempfile as _tempfile
    _wav_path = os.path.join(_tempfile.mkdtemp(), "acd-tone.wav")
    write_wav(_wav_path, generate_tone_samples(440, 1.0, 16000))
    _wav_info = analyse_wav(_wav_path)
    check("WAV round-trip: 1s 16kHz mono, RMS/peak in sane ranges",
          _wav_info["duration_seconds"] == 1.0
          and _wav_info["sample_rate"] == 16000 and _wav_info["channels"] == 1
          and 0.3 < _wav_info["rms"] < 0.4 and 0.49 < _wav_info["peak"] < 0.51)
    check("audio codec catalog + loudness targets are labelled estimates",
          len(AUDIO_FORMATS) == 5
          and loudness_check(-16.0, "podcast")["within_tolerance"] is True
          and loudness_check(-30.0, "streaming")["within_tolerance"] is False)
    check("RSSI distance estimate is monotonic in signal strength",
          estimate_distance_m(-40) < estimate_distance_m(-60)
          < estimate_distance_m(-80))
    check("pairing security: Just Works WEAK, Numeric Comparison STRONG",
          assess_pairing("just_works")["verdict"] == "WEAK"
          and assess_pairing("just_works")["mitm_protection"] is False
          and assess_pairing("numeric_comparison")["verdict"] == "STRONG")
    _bt = bluetooth_security_assessment()
    check("bluetooth synthetic scan assessed, weakest flagged WEAK",
          _bt["synthetic_scan"] is True and _bt["weak_count"] >= 1
          and _bt["weakest"]["verdict"] == "WEAK"
          and all(re.fullmatch(r"[0-9A-F]{2}(:[0-9A-F]{2}){5}", d["address"])
                  for d in bluetooth_synthetic_scan()))
    _raw_store = estimate_storage("8K DCI", 24, "RAW")
    _h265_store = estimate_storage("8K DCI", 24, "H.265")
    check("camera storage: 8K DCI 24fps RAW exceeds compressed",
          _raw_store["gb_per_hour"] > _h265_store["gb_per_hour"] > 0
          and _raw_store["width"] == 8192 and _raw_store["height"] == 4320)
    _fov35 = camera_fov(35)
    check("camera FOV math sane at 35mm full frame",
          50 < _fov35["hfov_deg"] < 60 and 35 < _fov35["vfov_deg"] < 42
          and stereo_depth_budget()["within_budget"] is True)
    _capture = camera_capture_plan("NIST")
    check("camera capture plan ties NIST geo + Street View pano",
          _capture["body"] == "NIST"
          and _capture["streetview_pano"] == pano_id_for("NIST")
          and _capture["lat"] == _nist_geo["lat"])
    check("SIx cycle reports media readiness, no hardware accessed",
          _cycle["media"]["voice_ready"] is True
          and _cycle["media"]["bluetooth_ready"] is True
          and _cycle["media"]["camera_ready"] is True
          and _cycle["media"]["hardware_accessed"] is False
          and next(e for e in _cycle["ledger"]
                   if isinstance(e["data"], dict)
                   and e["data"].get("state") == "RESPONDING")
          ["data"]["media"]["voice_ready"] is True)
    # Monad chain layer (merge 8: offline models, no live RPC)
    _mainnet = monad_network("mainnet")
    _testnet = monad_network("testnet")
    check("Monad chain ids: mainnet 143, testnet 10143",
          _mainnet["chain_id"] == 143 and _testnet["chain_id"] == 10143
          and _mainnet["rpc_url"] == "https://rpc.monad.xyz"
          and _testnet["rpc_url"] == "https://testnet-rpc.monad.xyz")
    check("MON token profile: 100B fixed supply, 18 decimals",
          MONAD_TOKEN_PROFILE["symbol"] == "MON"
          and MONAD_TOKEN_PROFILE["total_supply"] == 100_000_000_000
          and MONAD_TOKEN_PROFILE["decimals"] == 18
          and MONAD_TOKEN_PROFILE["fixed_supply"] is True)
    _tps = simulate_tps(10000, seconds=3.0)
    check("Monad block math: 300ms -> 3.333 blocks/s, ~3000 tx/block @10k TPS",
          _tps["blocks_per_second"] == 3.333
          and _tps["tx_per_block_target"] == 3000.0
          and _tps["blocks"] == 10)
    check("TPS simulator achieves within 5% of the 10k target",
          abs(_tps["achieved_tps"] - 10000) / 10000 < 0.05
          and _tps["ceiling_flag"] == "WITHIN_CATALOG_CEILING"
          and _tps["tx_mix"]["transfers"] > _tps["tx_mix"]["mints"] > 0)
    check("TPS above 10,000 flagged EXCEEDS_CATALOG_CEILING",
          simulate_tps(20000, seconds=1.0)["ceiling_flag"]
          == "EXCEEDS_CATALOG_CEILING")
    _par_hot = parallel_execute(synthetic_parallel_batch(conflicting=True),
                                lanes=4)
    _par_dis = parallel_execute(synthetic_parallel_batch(conflicting=False),
                                lanes=4)
    check("parallel execution: conflicts re-executed, disjoint batch clean",
          _par_hot["reexecutions"] > 0 and _par_dis["reexecutions"] == 0
          and _par_dis["conflicts"] == 0)
    check("parallel execution speedup > 1 on both batches",
          _par_hot["speedup"] > 1 and _par_dis["speedup"] > 1)
    check("EVM address validation accepts 0x+40hex, rejects bad formats",
          validate_address(MONAD_SAMPLE_EOA) is True
          and validate_address("0x123") is False
          and validate_address("1234567890abcdef1234567890abcdef12345678")
          is False)
    _risk = monad_account_risk(MONAD_SAMPLE_EOA)
    check("EOA quantum risk: ECDSA flagged vulnerable via scanner reuse",
          _risk["signature_status"] == "vulnerable"
          and _risk["signature_status"]
          == classify_algorithm("ECDSA")["status"]
          and _risk["risk_rating"] == "HIGH"
          and len(_risk["migration_path"]) == 5)
    check("MonadBFT quorum math: n=100 -> quorum 67, fault tolerance 33",
          validator_quorum(100)["quorum"] == 67
          and validator_quorum(100)["fault_tolerance"] == 33
          and validator_quorum(4)["quorum"] == 3)
    check("gas estimate: plain transfer = 21,000",
          estimate_gas("transfer")["gas"] == 21000
          and estimate_gas("swap")["gas"] > estimate_gas("transfer")["gas"])
    _life = tx_lifecycle(build_transaction(MONAD_SAMPLE_EOA,
                                           MONAD_SAMPLE_EOA, 1.5))
    check("tx lifecycle reaches finalized with 600 ms finality",
          _life["final_state"] == "finalized"
          and _life["finality_ms"] == 600
          and _life["states"][-1]["at_ms"] == 600)
    check("voice grammar routes Monad phrases to the monad modes",
          parse_voice_command("ACD monad tps")["mode"] == "monad-tps"
          and parse_voice_command("check monad")["mode"] == "monad"
          and parse_voice_command("ACD monad quantum risk")["mode"]
          == "monad-risk")
    _feats = monad_recommended_features()
    check("recommended Monad features catalog: all merged, key pieces in",
          len(_feats) >= 12
          and all(f["status"] == "merged" for f in _feats)
          and any("MonadBFT" in f["feature"] for f in _feats)
          and any("RaptorCast" in f["feature"] for f in _feats)
          and any("MonadDB" in f["feature"] for f in _feats))
    _chain_decision = monad_argon_chain_decision()
    check("Argon chain decision: ECDSA exposure stays NO-GO, no override",
          _chain_decision["verdict"] == "NO-GO"
          and _chain_decision["can_override"] is False)
    check("bridge + contract audit: ECDSA surfaces rated HIGH",
          bridge_risk()["quantum_risk"] == "HIGH"
          and smart_contract_audit()["overall_quantum_risk"] == "HIGH"
          and len(mev_protection_catalog()) >= 3)
    check("SIx cycle reports Monad readiness, no live calls",
          _cycle["monad"]["ready"] is True
          and _cycle["monad"]["chain_id"] == 143
          and _cycle["monad"]["live_calls"] is False
          and next(e for e in _cycle["ledger"]
                   if isinstance(e["data"], dict)
                   and e["data"].get("state") == "RESPONDING")
          ["data"]["chain"]["monad_ready"] is True)

    # Merge 9 - knowledge layer (six infographics, 154 entries)
    _counts = knowledge_counts()
    check("knowledge counts: 13/14/80/94/18/15/14/154",
          _counts["ai_tools"] == 13 and _counts["claude_codes"] == 14
          and _counts["gemini_codes"] == 80
          and _counts["prompt_codes_total"] == 94
          and _counts["glossary_terms"] == 18
          and _counts["career_layers"] == 15
          and _counts["cyber_domains"] == 14
          and _counts["total_entries"] == 154)
    check("AI tools numbered 1..13 as printed",
          [t["number"] for t in get_ai_tools()] == list(range(1, 14)))
    check("AI tool category coverage: endpoint x3, pentesting = Pentera",
          len(tools_by_category("ENDPOINT SECURITY")) == 3
          and tools_by_category("pentesting")[0]["name"] == "Pentera")
    check("recommend_ai_tool: pentesting -> Pentera, cloud -> Wiz first",
          recommend_ai_tool("pentesting")[0]["name"] == "Pentera"
          and recommend_ai_tool("cloud")[0]["name"] == "Wiz")
    _gap = coverage_gap_check(["ENDPOINT SECURITY", "CLOUD SECURITY"])
    check("coverage gap check math (2 of 9 categories)",
          _gap["covered_count"] == 2 and _gap["total_categories"] == 9
          and "PENTESTING" in _gap["missing"])
    check("Claude /artifacts duplicated honestly (build + review keys)",
          len(claude_code_all("/artifacts")) == 2
          and claude_code("artifacts-build")["number"] == 8
          and claude_code("artifacts-review")["number"] == 10
          and "twice" in CLAUDE_CODES_DUPLICATION_NOTE)
    check("Gemini dupes flagged: CODE_INT/ON appears at #6 and #8",
          gemini_duplicate_codes().get("GEMINI::MODE::CODE_INT/ON") == 2
          and gemini_code(6)["code"] == gemini_code(8)["code"])
    check("gemini_code(80) is Quick Reset (Settings)",
          gemini_code(80)["name"] == "Quick Reset (Settings)"
          and gemini_code(80)["code"] == "GEMINI::SYS::RESET.SETTINGS")
    check("Gemini groups: 8 groups, partially-visible flags on 61-71 only",
          len(GEMINI_GROUPS) == 8
          and all(gemini_code(n)["source_partially_visible"]
                  for n in range(61, 72))
          and not gemini_code(60)["source_partially_visible"]
          and not gemini_code(72)["source_partially_visible"])
    check("prompt registry merges Claude 14 + Gemini 80 = 94, lookup works",
          len(get_prompt_codes()) == 94
          and any(h["source"] == "claude" and h["code"] == "/godmode"
                  for h in lookup_prompt_code("godmode"))
          and any(h["source"] == "gemini"
                  for h in lookup_prompt_code("RESET.SETTINGS")))
    check("define('rag') and define('Chain of Thought') resolve",
          define("rag")["term"] == "RAG"
          and "Retrieval-Augmented" in define("rag")["definition"]
          and define("Chain of Thought")["term"] == "Chain of Thought"
          and define("not a real term") is None)
    check("glossary quiz is deterministic for a seed",
          glossary_quiz(seed=7) == glossary_quiz(seed=7)
          and glossary_quiz(seed=7) != glossary_quiz(seed=8)
          and len(glossary_quiz(seed=7)["questions"]) == 5)
    _path = career_path_check(CAREER_STACK[:5])
    check("career_path_check math: 5/15 done -> 33.3%, next layer 6",
          _path["completed_count"] == 5 and _path["percent_complete"] == 33.3
          and _path["next_layer"]["layer"] == 6
          and _path["next_layer"]["name"] == "Web Application Security")
    check("career stack credits @hacktanic, 15 layers in printed order",
          get_career_stack()[0]["name"] == "Security Fundamentals"
          and get_career_stack()[-1]["name"] == "Continuous Learning"
          and all(e["credit"] == "@hacktanic" for e in get_career_stack()))
    check("domain_for_tool: Darktrace -> Network Security, Pentera -> Pen Testing",
          "Network Security" in domain_for_tool("Darktrace")
          and domain_for_tool("Pentera") == ["Penetration Testing",
                                             "Vulnerability Management"]
          and domain_for_tool("No Such Tool") == [])
    check("cyber domains: 14 real domains, 'Hacking' is only the misconception",
          len(get_cyber_domains()) == 14
          and CYBER_MISCONCEPTION_LABEL == "Hacking"
          and "Hacking" not in CYBER_DOMAINS
          and set(tools_for_domain("Network Security"))
          == {"Darktrace", "Palo Alto Cortex", "Vectra AI",
              "Cisco AI Security"})
    check("knowledge renders carry counts, credits and honesty note",
          "TOTAL ENTRIES: 154" in render_knowledge()
          and "@hacktanic" in render_career()
          and "@hacktanic" in render_cybermap()
          and "no vendor API is called live" in render_aitools()
          and "94" in render_codes())
    check("voice grammar routes knowledge phrases to the new modes",
          parse_voice_command("ACD ai tools")["mode"] == "aitools"
          and parse_voice_command("ACD glossary")["mode"] == "glossary"
          and parse_voice_command("ACD career")["mode"] == "career"
          and parse_voice_command("ACD prompt codes")["mode"] == "codes"
          and parse_voice_command("ACD knowledge")["mode"] == "knowledge")


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
    _voice_demo = parse_voice_command("ACD scan RSA-2048 and AES-256")
    _bt_demo = bluetooth_security_assessment()
    _cam_demo = estimate_storage("8K DCI", 24, "RAW")
    print(f"Media layer: voice intent '{_voice_demo['mode']}' "
          f"(confidence {_voice_demo['confidence']}), "
          f"{len(VOICE_PRESETS)} speaker presets, "
          f"Bluetooth weakest pairing {_bt_demo['weakest']['verdict']} "
          f"({_bt_demo['weakest']['name']}), "
          f"8K DCI 24fps RAW storage {_cam_demo['gb_per_hour']} GB/hour "
          f"(models only - no hardware accessed)")
    _mon = simulate_tps(10000, seconds=3.0)
    _mon_par = parallel_execute(synthetic_parallel_batch(conflicting=True))
    print(f"Monad: 10,000 TPS catalog (300 ms blocks, 600 ms finality) - "
          f"simulated {_mon['achieved_tps']} TPS over {_mon['blocks']} blocks, "
          f"parallel speedup x{_mon_par['speedup']}, "
          f"EOA quantum risk {monad_account_risk(MONAD_SAMPLE_EOA)['risk_rating']} "
          f"(offline model - no live RPC)")
    _know = knowledge_counts()
    print(f"Knowledge layer (Merge 9): {_know['ai_tools']} AI security tools, "
          f"{_know['prompt_codes_total']} prompt codes "
          f"({_know['claude_codes']} Claude + {_know['gemini_codes']} Gemini), "
          f"{_know['glossary_terms']} glossary terms, "
          f"{_know['career_layers']} career layers, "
          f"{_know['cyber_domains']} cyber domains = "
          f"{_know['total_entries']} entries "
          f"(catalog only - no live vendor calls)")
    print()
    return run_checks()


def main(argv=None):
    parser = argparse.ArgumentParser(description="ACD-Quantum - Quantum Cyber Security structure tree and tools")
    parser.add_argument("mode", nargs="?", default="demo",
                        choices=["demo", "tree", "checks", "scan", "plan", "qkd", "qrng", "hndl",
                                 "earth", "kml", "distance", "decide", "six", "ledger",
                                 "images", "recommend", "compose", "streetview", "map",
                                 "voice", "speaker", "audio", "bluetooth", "camera",
                                 "monad", "monad-tps", "monad-parallel",
                                 "monad-risk", "monad-plan",
                                 "aitools", "codes", "glossary", "career",
                                 "cybermap", "knowledge"])
    parser.add_argument("body_arg", nargs="?", default=None,
                        help="Optional body name (streetview) or transcript (voice)")
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
    parser.add_argument("--demo", action="store_true",
                        help="Run the built-in demo transcript for voice mode")
    parser.add_argument("--say", default=None,
                        help="Text for speaker mode to turn into a speech plan")
    parser.add_argument("--preset", default="acd-narrator",
                        help="Voice preset id for speaker mode")
    parser.add_argument("--plan", dest="plan_body", default=None,
                        help="Body name for camera capture-plan mode")
    parser.add_argument("--tps", dest="tps_flag", action="store_true",
                        help="With monad mode: also print the TPS simulation")
    parser.add_argument("--seconds", type=float, default=3.0,
                        help="Duration for the monad-tps simulation")
    parser.add_argument("--target-tps", type=int, default=10000,
                        help="Target TPS for the monad-tps simulation")
    parser.add_argument("--lanes", type=int, default=4,
                        help="Parallel lanes for monad-parallel")
    parser.add_argument("--validators", type=int, default=100,
                        help="Validator count for the monad quorum model")
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
        media = cycle["media"]
        print(f"Media: voice ready={media['voice_ready']}, "
              f"speaker ready={media['speaker_ready']}, "
              f"audio ready={media['audio_ready']}, "
              f"Bluetooth ready={media['bluetooth_ready']} "
              f"(synthetic scan), 3D 8K camera ready={media['camera_ready']} "
              f"(spec/plans only), hardware accessed="
              f"{media['hardware_accessed']}")
        mon = cycle["monad"]
        print(f"Monad: ready={mon['ready']}, chain_id={mon['chain_id']}, "
              f"{mon['throughput_tps']:,} TPS catalog, "
              f"{mon['block_time_ms']} ms blocks, "
              f"{mon['finality_ms']} ms finality, "
              f"live calls={mon['live_calls']}")
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
    if args.mode == "voice":
        transcript = args.body_arg
        if args.demo or not transcript:
            transcript = "ACD scan RSA-2048 and AES-256"
            print(f"Demo transcript: {transcript}")
        route = route_voice_command(transcript)
        parsed = route["parsed"]
        print(f"wake_detected: {parsed['wake_detected']} "
              f"(phrase: {parsed['wake_phrase']})")
        print(f"mode: {parsed['mode']} | status: {parsed['status']} | "
              f"confidence: {parsed['confidence']} "
              f"({parsed['confidence_level']})")
        print(f"slots: {parsed['slots']}")
        print(f"SIx route: {' -> '.join(route['states'])}")
        print(f"reply: {route['reply_text']}")
        print(f"note: {MEDIA_HONESTY_NOTE}")
        return 0
    if args.mode == "speaker":
        if args.say:
            plan_out = build_speech_plan(args.say, preset_id=args.preset)
            for k in ("preset", "language", "rate", "pitch", "volume",
                      "sentences"):
                print(f"{k}: {plan_out[k]}")
            print(f"ssml: {plan_out['ssml']}")
            print(f"note: {plan_out['note']}")
            return 0
        for preset in VOICE_PRESETS:
            print(f"{preset['id']:<14} {preset['name']:<14} "
                  f"{preset['language']} {preset['gender_style']:<9} "
                  f"rate={preset['rate']} pitch={preset['pitch']} "
                  f"volume={preset['volume']}")
        verdict = speak_verdict(algos)
        print(f"verdict speech plan: {verdict['text']}")
        print(f"note: {verdict['note']}")
        return 0
    if args.mode == "audio":
        out_path = args.out or "acd-tone.wav"
        samples = generate_tone_samples(440, 1.0, 16000)
        write_wav(out_path, samples, sample_rate=16000)
        info = analyse_wav(out_path)
        for k in ("format", "path", "sample_rate", "channels", "bit_depth",
                  "duration_seconds", "rms", "peak", "rms_dbfs",
                  "silence_ratio", "estimated_lufs"):
            print(f"{k}: {info[k]}")
        print("formats: " + ", ".join(
            f"{f['format']} ~{f['typical_bitrate_kbps']} kbps"
            for f in AUDIO_FORMATS))
        loud = loudness_check(info["estimated_lufs"], "podcast")
        print(f"loudness vs podcast target: {loud}")
        print(f"pipeline: {audio_pipeline_spec()['input_profile']} -> "
              f"recognition -> {audio_pipeline_spec()['output_profile']}")
        return 0
    if args.mode == "bluetooth":
        print("SYNTHETIC scan (no radio accessed):")
        for device in bluetooth_synthetic_scan():
            print(f"{device['name']:<20} {device['address']} "
                  f"{device['transport']:<7} RSSI {device['rssi_dbm']} dBm "
                  f"~{device['distance_m']} m connectable="
                  f"{device['connectable']} services={device['services']}")
        assessment = bluetooth_security_assessment()
        for row in assessment["devices"]:
            print(f"{row['name']:<20} pairing={row['method']:<18} "
                  f"verdict={row['verdict']} mitm={row['mitm_protection']}")
        print(f"weakest: {assessment['weakest']['name']} "
              f"({assessment['weakest']['verdict']})")
        print(f"strongest: {assessment['strongest']['name']} "
              f"({assessment['strongest']['verdict']})")
        print(f"note: {assessment['note']}")
        return 0
    if args.mode == "camera":
        if args.plan_body:
            capture = camera_capture_plan(args.plan_body)
            if capture is None:
                print(f"error: unknown body: {args.plan_body}")
                return 1
            for k in ("body", "city", "country", "lat", "lon",
                      "streetview_pano", "streetview_heading", "resolution",
                      "fps", "codec", "color_pipeline", "stabilization"):
                print(f"{k}: {capture[k]}")
            print(f"storage: {capture['storage']}")
            print(f"stereo: {capture['stereo']}")
            print(f"fov_35mm: {capture['fov_35mm']}")
            print(f"shot_list: {capture['shot_list']}")
            print(f"note: {capture['note']}")
            return 0
        spec = camera_spec_summary()
        for name, res in spec["resolutions"].items():
            print(f"{name:<8} {res['width']}x{res['height']}")
        print("frame rates: " + ", ".join(
            f"{fps} ({label})" for fps, label in
            spec["frame_rates"].items()))
        print("color pipelines: " + ", ".join(
            f"{c['name']} {c['bit_depth']}-bit"
            for c in spec["color_pipelines"]))
        for codec in ("RAW", "ProRes 422 HQ", "H.265"):
            est = estimate_storage("8K DCI", 24, codec)
            print(f"8K DCI 24fps {codec:<13} {est['mb_per_s']} MB/s, "
                  f"{est['gb_per_hour']} GB/hour, "
                  f"{est['card_capacity_minutes']} min per "
                  f"{est['card_capacity_gb']} GB card")
        print(f"stereo depth budget (65mm baseline): {stereo_depth_budget()}")
        print(f"note: {MEDIA_HONESTY_NOTE}")
        return 0
    if args.mode == "monad":
        print(render_monad(), end="")
        prof = monad_profile()
        print(f"RPC methods (catalog names, never called): "
              f"{', '.join(prof['rpc_methods'])}")
        quorum = validator_quorum(args.validators)
        print(f"Validator model: n={quorum['validators']} -> "
              f"quorum={quorum['quorum']}, fault tolerance="
              f"{quorum['fault_tolerance']} (MonadBFT)")
        if args.tps_flag:
            sim = simulate_tps(args.target_tps, seconds=args.seconds)
            print(f"TPS simulation: target {sim['target_tps']:,}, achieved "
                  f"{sim['achieved_tps']} over {sim['blocks']} blocks "
                  f"({sim['ceiling_flag']})")
        return 0
    if args.mode == "monad-tps":
        sim = simulate_tps(args.target_tps, seconds=args.seconds)
        for k in ("target_tps", "achieved_tps", "blocks",
                  "blocks_per_second", "tx_per_block_target",
                  "total_transactions", "succeeded", "failed",
                  "success_rate_pct", "conflicts", "reexecuted",
                  "ceiling_flag"):
            print(f"{k}: {sim[k]}")
        print(f"tx_mix: {sim['tx_mix']}")
        print(f"latency_ms_estimates: {sim['latency_ms_estimates']}")
        print(f"finality_ms: {sim['finality_ms']}")
        print(f"note: {sim['note']}")
        return 0
    if args.mode == "monad-parallel":
        hot = parallel_execute(synthetic_parallel_batch(conflicting=True),
                               lanes=args.lanes)
        dis = parallel_execute(synthetic_parallel_batch(conflicting=False),
                               lanes=args.lanes)
        for label, res in (("conflicting batch", hot),
                           ("disjoint batch", dis)):
            print(f"{label}: txs={res['transactions']} lanes={res['lanes']} "
                  f"conflicts={res['conflicts']} "
                  f"reexecutions={res['reexecutions']} "
                  f"serial={res['serial_time_units']} units, "
                  f"parallel={res['parallel_time_units']} units, "
                  f"speedup=x{res['speedup']}")
        print(f"note: {hot['note']}")
        return 0
    if args.mode == "monad-risk":
        address = args.body_arg or MONAD_SAMPLE_EOA
        risk = monad_account_risk(address)
        for k in ("address", "valid", "account_type", "signature_scheme",
                  "signature_status", "public_key_exposed",
                  "quantum_exposure", "risk_rating", "chain_verdict"):
            print(f"{k}: {risk[k]}")
        audit = smart_contract_audit(address)
        print(f"contract audit overall quantum risk: "
              f"{audit['overall_quantum_risk']}")
        for entry in audit["checklist"]:
            print(f"  - {entry['item']:<18} {entry['quantum_risk']:<6} "
                  f"{entry['finding']}")
        decision = monad_argon_chain_decision()
        print(f"Argon 4 chain decision: {decision['verdict']} "
              f"(can_override={decision['can_override']}, "
              f"trace {decision['trace_hash']})")
        print(f"note: {risk['note']}")
        return 0 if risk["valid"] else 1
    if args.mode == "monad-plan":
        for step in monad_migration_path():
            print(f"Phase {step['phase']} - {step['name']}")
            print(f"  - {step['action']}")
        print(f"note: {MONAD_HONESTY_NOTE}")
        return 0
    if args.mode == "aitools":
        print(render_aitools(), end="")
        return 0
    if args.mode == "codes":
        print(render_codes(), end="")
        return 0
    if args.mode == "glossary":
        if args.body_arg:
            entry = define(args.body_arg)
            if entry is None:
                print(f"error: unknown glossary term: {args.body_arg}")
                return 1
            print(f"{entry['term']}: {entry['definition']}")
            return 0
        print(render_glossary(), end="")
        return 0
    if args.mode == "career":
        print(render_career(), end="")
        return 0
    if args.mode == "cybermap":
        print(render_cybermap(), end="")
        return 0
    if args.mode == "knowledge":
        print(render_knowledge(), end="")
        return 0
    return 0 if demo() else 1


if __name__ == "__main__":
    sys.exit(main())
