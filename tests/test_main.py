import main


def test_national_top15():
    data = main.get_national()
    assert len(data) == 15
    assert [x["rank"] for x in data] == list(range(1, 16))


def test_international_top15():
    data = main.get_international()
    assert len(data) == 15
    assert [x["rank"] for x in data] == list(range(1, 16))


def test_five_branches():
    ids = {b["id"] for b in main.get_branches()}
    assert ids == {"PQC", "QKD", "QRNG", "AGILITY", "HNDL"}


def test_nist_standards_present():
    nist = [x for x in main.get_national() if x["name"] == "NIST"][0]
    assert "FIPS 203" in nist["role"]
    assert "ML-KEM" in nist["role"] and "ML-DSA" in nist["role"] and "SLH-DSA" in nist["role"]


def test_nsa_cnsa2_present():
    nsa = [x for x in main.get_national() if x["name"] == "NSA"][0]
    assert "CNSA 2.0" in nsa["role"]


def test_tree_renders_both_scopes():
    tree = main.render_tree()
    assert "TOP 15 NATIONAL (USA)" in tree
    assert "TOP 15 INTERNATIONAL" in tree
    assert "TOP 15 NATIONAL" not in main.render_tree("international")


def test_classify_rsa_vulnerable():
    assert main.classify_algorithm("RSA-2048")["status"] == "vulnerable"
    assert main.classify_algorithm("rsa")["status"] == "vulnerable"


def test_classify_ecc_family_vulnerable():
    for name in ("ECDSA", "ECDH", "P-256", "X25519", "DH"):
        assert main.classify_algorithm(name)["status"] == "vulnerable", name


def test_classify_symmetric_cnsa_ok():
    assert main.classify_algorithm("AES-256")["status"] == "cnsa_ok"
    assert main.classify_algorithm("SHA-384")["status"] == "cnsa_ok"
    assert main.classify_algorithm("SHA-512")["status"] == "cnsa_ok"


def test_classify_pqc_safe():
    for name in ("ML-KEM-1024", "ML-DSA-87", "SLH-DSA", "HQC", "Kyber"):
        assert main.classify_algorithm(name)["status"] == "pqc_safe", name


def test_classify_weakened_and_broken_and_unknown():
    assert main.classify_algorithm("AES-128")["status"] == "weakened"
    assert main.classify_algorithm("MD5")["status"] == "broken"
    assert main.classify_algorithm("ROT13")["status"] == "unknown"


def test_scan_inventory_counts():
    scan = main.scan_inventory(["RSA-2048", "ECDSA", "AES-256", "ML-KEM-768", "AES-128"])
    s = scan["summary"]
    assert s["total"] == 5 and s["at_risk"] == 2 and s["safe"] == 2 and s["weakened"] == 1


def test_readiness_high_for_pqc_inventory():
    r = main.migration_readiness(["ML-KEM-1024", "AES-256"], has_inventory=True, has_agility=True)
    assert r["score"] >= 85 and r["grade"] == "READY"


def test_readiness_low_for_legacy_inventory():
    r = main.migration_readiness(["RSA-2048", "ECDSA"], has_inventory=False, has_agility=False)
    assert r["score"] < 20


def test_migration_plan_five_phases():
    plan = main.generate_migration_plan(["RSA-2048", "AES-128"])
    assert len(plan) == 5
    assert [p["phase"] for p in plan] == [0, 1, 2, 3, 4]
    assert "RSA-2048" in " ".join(plan[2]["actions"])


def test_bb84_clean_channel():
    r = main.simulate_bb84(512, eve=False, seed=7)
    assert r["qber"] == 0.0
    assert r["key_aborted"] is False
    assert r["sifted_length"] > 100


def test_bb84_eve_detected_by_qber():
    r = main.simulate_bb84(512, eve=True, seed=7)
    assert r["qber"] > r["qber_threshold"]
    assert r["eavesdropper_detected"] is True
    assert r["key_aborted"] is True
    assert r["sifted_key"] == ""


def test_bb84_deterministic():
    assert main.simulate_bb84(128, seed=3) == main.simulate_bb84(128, seed=3)


def test_qrng_length_and_determinism():
    assert len(main.qrng_bytes(64, seed="t")) == 64
    assert main.qrng_bytes(32, seed="a") == main.qrng_bytes(32, seed="a")
    assert main.qrng_bytes(32, seed="a") != main.qrng_bytes(32, seed="b")
    assert len(main.qrng_hex(16, seed="a")) == 32


def test_qrng_labelled_simulation():
    assert "simulation" in main.qrng_label().lower()
    assert "not true quantum" in main.qrng_label().lower()


def test_hndl_mosca_at_risk():
    r = main.hndl_risk(10, 5, 10)
    assert r["at_risk"] is True and r["margin_years"] == -5.0


def test_hndl_mosca_safe():
    r = main.hndl_risk(2, 2, 15)
    assert r["at_risk"] is False and r["risk_level"] == "LOW" and r["margin_years"] == 11.0


def test_run_checks_passes(capsys):
    assert main.run_checks() is True
    out = capsys.readouterr().out
    assert "CHECKS 54/54" in out


# --- Merge 1: Google Earth layer ---

def test_all_bodies_have_geo():
    bodies = main.all_bodies_with_geo()
    assert len(bodies) == 30
    for b in bodies:
        assert isinstance(b["lat"], float) and isinstance(b["lon"], float)
        assert b["city"] and b["country"] and b["region"]


def test_geo_known_headquarters():
    assert main.get_geo("NIST")["city"] == "Gaithersburg, MD"
    assert main.get_geo("NSA")["city"] == "Fort Meade, MD"
    assert main.get_geo("ETSI")["city"] == "Sophia Antipolis"
    assert main.get_geo("Germany BSI")["city"] == "Bonn"
    assert main.get_geo("IETF")["anchor"] is True  # virtual body, labelled anchor


def test_kml_wellformed_30_placemarks():
    import xml.etree.ElementTree as ET
    root = ET.fromstring(main.build_kml())
    ns = "{http://www.opengis.net/kml/2.2}"
    placemarks = root.findall(f".//{ns}Placemark")
    assert len(placemarks) == 30
    coords = [p.find(f"{ns}Point/{ns}coordinates").text for p in placemarks]
    assert all(c.count(",") == 2 for c in coords)


def test_haversine_known_pair():
    km = main.haversine_km(38.8977, -77.0365, 40.7128, -74.0060)  # DC -> NYC
    assert 300 <= km <= 400
    assert main.haversine_km(0, 0, 0, 0) == 0.0


def test_distance_between_bodies():
    d = main.distance_between("NIST", "ETSI")
    assert d["from"] == "NIST" and d["to"] == "ETSI" and d["km"] > 5000


# --- Merge 2: Gemini Argon 4 DECIDER ---

def test_argon_seat_spec():
    seat = main.ARGON_SEAT
    assert seat["seat_id"] == "gemini-argon-4"
    assert seat["role"] == "DECIDER"
    assert seat["engine"] == "gemini-2.5-pro"
    assert seat["model"] == "google/gemini-carbon-4-extended-pro-thinking"
    assert seat["can_override"] is False
    assert seat["live_calls"] is False


def test_argon_tiers_by_stakes():
    assert main.argon_tier("routine") == 2048
    assert main.argon_tier("standard") == 8192
    assert main.argon_tier("final") == 32768


def test_argon_decide_pipeline_and_trace_deterministic():
    d1 = main.argon_decide(["RSA-2048", "AES-256"])
    d2 = main.argon_decide(["RSA-2048", "AES-256"])
    assert [s["stage"] for s in d1["stages"]] == ["MAP", "MODEL", "STRESS", "DECIDE"]
    assert d1["trace_hash"] == d2["trace_hash"] and len(d1["trace_hash"]) == 64
    assert d1["verdict"] == "NO-GO"


def test_argon_tighten_only_cannot_flip_rsa():
    d = main.argon_decide(["RSA-2048"])
    stress = d["stages"][2]
    assert stress["controls_passed"] is True
    flip = stress["override_attempts"][0]
    assert flip["applied"] is False and flip["actual_status"] == "vulnerable"
    assert main.classify_algorithm("RSA-2048")["status"] == "vulnerable"
    # and it cannot raise the readiness score either
    assert d["stages"][3]["score_after_decide"] == d["readiness_score"]


def test_argon_go_for_clean_pqc_inventory():
    d = main.argon_decide(["ML-KEM-1024", "ML-DSA-87", "AES-256", "SHA-384"])
    assert d["verdict"] == "GO" and d["required_actions"] == []


def test_argon_hndl_breach_forces_nogo():
    hndl = main.hndl_risk(10, 5, 10)
    d = main.argon_decide(["ML-KEM-1024", "AES-256"], hndl=hndl)
    assert d["verdict"] == "NO-GO"


# --- Merge 3: SIx Neural Core + ledger ---

def test_six_params_match_spec():
    assert main.six_params_for("THINKING")["appearance"] == "Rapid neural pulses"
    assert main.six_params_for("LISTENING")["ring_count"] == 3
    assert main.six_params_for("RESPONDING")["wave_rate"] == 1.0
    assert main.six_params_for("LEARNING")["link_rate"] == 1.0
    thinking = main.six_params_for("THINKING")["pulse_rate"]
    assert all(main.six_params_for(s)["pulse_rate"] < thinking
               for s in main.SIX_STATE_ORDER if s != "THINKING")


def test_six_legal_and_illegal_transitions():
    import pytest
    core = main.SixNeuralCore()
    assert core.state == "IDLE"
    with pytest.raises(main.IllegalTransitionError):
        core.transition("THINKING")  # IDLE -> THINKING is illegal
    with pytest.raises(main.IllegalTransitionError):
        core.transition("IDLE")  # self-transition is illegal
    core.transition("LISTENING")
    core.transition("THINKING")
    assert core.state == "THINKING" and core.tick == 2
    assert core.history[0] == (0, None, "IDLE")


def test_six_full_cycle():
    cycle = main.run_six_cycle(["RSA-2048", "AES-256"])
    assert cycle["states"] == ["IDLE", "LISTENING", "THINKING", "RESPONDING", "LEARNING", "IDLE"]
    assert cycle["decision"]["verdict"] == "NO-GO"
    assert cycle["plan_phases"] == 5


def test_ledger_chain_verifies_and_tamper_breaks():
    ledger = main.AuditLedger()
    ledger.append_entry({"event": "a"})
    ledger.append_entry({"event": "b"})
    assert main.verify_ledger(ledger.chain) is True
    assert ledger.chain[1]["prev_hash"] == ledger.chain[0]["hash"]
    tampered = [dict(e) for e in ledger.chain]
    tampered[1]["data"] = {"event": "forged"}
    assert main.verify_ledger(tampered) is False


# --- Merge 4: Docker images catalog ---

def test_docker_catalog_count_and_pull_commands():
    images = main.get_docker_images()
    assert len(images) == 29
    for img in images:
        assert img["pull"] == f"docker pull credkellar/{img['slug']}:latest"
        assert img["image"] == f"credkellar/{img['slug']}:latest"
    slugs = {img["slug"] for img in images}
    assert "acd-quantum" in slugs and "diffre-lab" not in slugs  # no invented slugs


def test_docker_top_fleet_puller_flag():
    top = [img for img in main.get_docker_images() if img["top_fleet_puller"]]
    assert len(top) == 1 and top[0]["slug"] == "superconductor-lab"


def test_recommend_all_branches_ranked():
    for branch in ("PQC", "QKD", "QRNG", "AGILITY", "HNDL"):
        recs = main.recommend_images(branch)
        assert len(recs) >= 3
        assert [r["rank"] for r in recs] == list(range(1, len(recs) + 1))
    assert main.recommend_images("QRNG")[0]["slug"] == "quantumrandom-lab"
    assert main.recommend_images("QKD")[0]["slug"] == "quantumrepeater-lab"
    assert main.recommend_images("PQC")[0]["slug"] == "quantumshor-lab"


def test_recommend_keyword_and_default():
    recs = main.recommend_images("levitation")
    assert recs and all("pull" in r for r in recs)
    assert main.recommend_images("zzz-no-match") [0]["slug"] == "acd-quantum"


def test_compose_snippet_contains_images():
    snippet = main.compose_snippet("QRNG")
    assert "services:" in snippet
    assert "credkellar/quantumrandom-lab:latest" in snippet
    assert "credkellar/bosonsampling-lab:latest" in snippet
