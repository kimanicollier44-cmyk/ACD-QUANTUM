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
    assert "CHECKS 30/30" in out
