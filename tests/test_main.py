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
    assert "CHECKS 88/88" in out


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


# --- Street View Service layer (Merge 5) -----------------------------------

import pytest


def test_bearing_and_heading_wrap():
    # Washington DC -> NYC bears roughly north-east (~53 degrees)
    dc = main.get_geo("White House / ONCD")
    nyc = main.get_geo("IEEE")
    b = main.bearing_deg(dc["lat"], dc["lon"], nyc["lat"], nyc["lon"])
    assert 30 <= b <= 80
    assert main.wrap_heading(360) == 0.0
    assert main.wrap_heading(725) == 5.0
    assert main.wrap_heading(-90) == 270.0


def test_pitch_clamp():
    assert main.clamp_pitch(45) == 45.0
    assert main.clamp_pitch(91) == 90.0
    assert main.clamp_pitch(-91) == -90.0


def test_get_panorama_ok_all_bodies_links_real_neighbours():
    names = {b["name"] for b in main.all_bodies_with_geo()}
    for body in main.all_bodies_with_geo():
        result = main.sv_get_panorama(
            location={"lat": body["lat"], "lng": body["lon"]},
            radius=50, source="outdoor")
        assert result["status"] == "OK"
        data = result["data"]
        # A location lookup resolves to the nearest body; bodies that share
        # an HQ coordinate (e.g. two London anchors) resolve to that point.
        matched = main.find_body(result["matched_body"])
        assert (matched["lat"], matched["lon"]) == (body["lat"], body["lon"])
        assert data["location"]["pano"] == main.pano_id_for(matched["name"])
        assert len(data["links"]) == 2
        for link in data["links"]:
            assert link["description"] in names
            assert link["description"] != matched["name"]
            assert 0 <= link["heading"] < 360
            assert link["pano"] == main.pano_id_for(link["description"])


def test_get_panorama_zero_results_open_ocean():
    result = main.sv_get_panorama(location={"lat": -25.0, "lng": -140.0})
    assert result["status"] == "ZERO_RESULTS"
    assert result["data"] is None


def test_get_panorama_unknown_error_and_bad_enums():
    assert main.sv_get_panorama()["status"] == "UNKNOWN_ERROR"
    with pytest.raises(ValueError):
        main.sv_get_panorama(location={"lat": 0, "lng": 0}, source="space")
    with pytest.raises(ValueError):
        main.sv_get_panorama(location={"lat": 0, "lng": 0}, preference="closest")


def test_panorama_options_defaults_and_validation():
    opts = main.validate_panorama_options({"pov": {"heading": 370, "pitch": 200}})
    assert opts["pov"] == {"heading": 10.0, "pitch": 90.0}
    assert opts["clickToGo"] is True and opts["linksControl"] is True
    assert opts["motionTracking"] is True and opts["zoomControl"] is True
    nist = main.find_body("NIST")
    defaults = main.default_panorama_options(nist)
    assert defaults["pano"] == main.pano_id_for("NIST")
    assert defaults["pov"]["pitch"] == 10.0
    with pytest.raises(ValueError):
        main.validate_panorama_options({"bogusOption": True})


def test_custom_provider_round_trip():
    pano = main.pano_id_for("ETSI")
    result = main.sv_get_panorama_by_provider(pano)
    assert result["status"] == "OK"
    assert result["data"]["location"]["shortDescription"] == "ETSI"
    # and the same pano resolves through the service entry point too
    assert main.sv_get_panorama(pano=pano)["status"] == "OK"
    assert main.sv_get_panorama_by_provider("acd-nope")["status"] == "ZERO_RESULTS"


def test_panorama_model_events_on_pov_and_pano_change():
    model = main.StreetViewPanoramaModel(main.find_body("NIST"))
    seen = []
    for event in main.SV_EVENTS:
        model.on(event, lambda detail, e=event: seen.append(e))
    model.set_pov(heading=400, pitch=45)
    assert model.get_pov() == {"heading": 40.0, "pitch": 45.0}
    model.set_pano(main.pano_id_for("ETSI"))
    assert model.get_pano() == main.pano_id_for("ETSI")
    model.set_visible(False)
    for expected in ("pov_changed", "pano_changed", "links_changed",
                     "position_changed", "visible_changed"):
        assert expected in seen
    # no change -> no new pov event
    before = len(model.event_log)
    model.set_pov(heading=40, pitch=45)
    assert len(model.event_log) == before


def test_streetview_html_all_bodies_placeholder():
    page = main.build_streetview_html()
    for body in main.all_bodies_with_geo():
        assert body["name"] in page
    assert main.MAPS_KEY_PLACEHOLDER == "YOUR_API_KEY"
    assert "YOUR_API_KEY" in page
    assert "StreetViewService" in page and "initPanorama" in page
    assert "google.maps.StreetViewSource.OUTDOOR" in page
    assert "<redacted>" not in page


def test_streetview_for_body_record():
    rec = main.streetview_for_body("NIST")
    assert rec["status"] == "OK" and rec["body"] == "NIST"
    assert rec["pov"]["pitch"] == 10.0
    assert len(rec["links"]) == 2
    assert "HTTPS" in rec["motion_tracking_note"]
    assert main.streetview_for_body("no such body") is None


# --- Perfect Map layer (Merge 6) -------------------------------------------


def test_map_markers_count_and_shape():
    markers = main.build_markers()
    assert len(markers) == 30
    for marker in markers:
        assert marker["label"] == "ACD"
        assert marker["draggable"] is False
        assert marker["animation"] in main.MARKER_ANIMATIONS
        assert marker["title"] == marker["body"]
        assert marker["title"] in marker["info"]


def test_map_bounds_contain_all_bodies():
    bounds = main.compute_bounds()
    for body in main.all_bodies_with_geo():
        assert bounds["south"] <= body["lat"] <= bounds["north"]
        assert bounds["west"] <= body["lon"] <= bounds["east"]
    fit = main.fit_bounds()
    assert fit["count"] == 30
    assert fit["center"] == main.bounds_center(bounds)


def test_map_region_zooms_sane():
    for region in ("North America", "Europe", "Asia-Pacific"):
        fit = main.fit_bounds(region)
        assert fit["count"] >= 3
        assert 2 <= fit["zoom"] <= 12
    with pytest.raises(ValueError):
        main.fit_bounds("Atlantis")


def test_map_options_defaults_and_validation():
    opts = main.validate_map_options()
    assert opts["mapTypeId"] == "roadmap"
    assert opts["mapTypeControlOptions"]["style"] in main.MAP_TYPE_CONTROL_STYLES
    assert set(opts["mapTypeControlOptions"]["mapTypeIds"]) == set(main.MAP_TYPES)
    assert opts["streetViewControl"] is True and opts["fullscreenControl"] is True
    clamped = main.validate_map_options({"zoom": 99})
    assert clamped["zoom"] == clamped["maxZoom"]
    with pytest.raises(ValueError):
        main.validate_map_options({"mapTypeId": "moon"})
    with pytest.raises(ValueError):
        main.validate_map_options({"gestureHandling": "wild"})
    with pytest.raises(ValueError):
        main.validate_map_options({"nope": 1})


def test_map_layers_model():
    layers = main.map_layers()
    assert layers["traffic"]["type"] == "TrafficLayer"
    assert layers["transit"]["type"] == "TransitLayer"
    assert layers["bicycling"]["type"] == "BicyclingLayer"
    url = layers["kml"]["url"]
    assert url.startswith("https://") and url.endswith("earth/ACD-QUANTUM.kml")
    overlay = layers["groundOverlay"]
    nist = main.get_geo("NIST")
    assert overlay["bounds"]["south"] < nist["lat"] < overlay["bounds"]["north"]
    assert overlay["bounds"]["west"] < nist["lon"] < overlay["bounds"]["east"]


def test_map_model_events_on_zoom_center_and_type():
    model = main.MapModel()
    seen = []
    for event in main.MAP_EVENTS:
        model.on(event, lambda detail, e=event: seen.append(e))
    model.set_center(40.0, -100.0)
    model.set_zoom(6)
    model.set_map_type_id("terrain")
    model.click(40.0, -100.0)
    model.begin_drag()
    model.end_drag()
    for expected in ("center_changed", "zoom_changed", "bounds_changed",
                     "maptypeid_changed", "click", "dragstart", "drag", "dragend"):
        assert expected in seen
    assert model.get_zoom() == 6 and model.get_map_type_id() == "terrain"
    with pytest.raises(ValueError):
        model.set_map_type_id("moon")


def test_combined_map_html():
    page = main.build_map_html()
    assert "google.maps.Map" in page
    assert "StreetViewPanorama" in page
    assert "setStreetView" in page
    assert "KmlLayer" in page and main.KML_LAYER_URL in page
    for body in main.all_bodies_with_geo():
        assert body["name"] in page
    assert "YOUR_API_KEY" in page
    assert "<redacted>" not in page


def test_geocode_round_trips():
    fwd = main.geocode_forward("NIST")
    assert fwd["status"] == "OK"
    loc = fwd["results"][0]["geometry"]["location"]
    nist = main.get_geo("NIST")
    assert loc["lat"] == nist["lat"] and loc["lng"] == nist["lon"]
    rev = main.geocode_reverse(loc["lat"], loc["lng"])
    assert rev["results"][0]["body"] == "NIST"
    assert rev["results"][0]["formatted_address"].startswith("NIST — ")
    assert main.geocode_forward("no such place")["status"] == "ZERO_RESULTS"
    # a point near ETSI reverse-geocodes to ETSI
    etsi = main.get_geo("ETSI")
    assert main.geocode_reverse(etsi["lat"] + 0.01,
                                etsi["lon"])["results"][0]["body"] == "ETSI"


def test_six_cycle_streetview_readiness():
    cycle = main.run_six_cycle(["ML-KEM-1024", "AES-256"])
    assert cycle["streetview"]["ready"] is True
    assert cycle["streetview"]["bodies"] == 30
    assert cycle["streetview"]["sample_pano"] == main.pano_id_for("NIST")
    responding = [e for e in cycle["ledger"]
                  if isinstance(e["data"], dict)
                  and e["data"].get("event") == "plan_emitted"]
    assert responding and responding[0]["data"]["streetview_ready"] is True


# --- Merge 7: media + sensing layer (models / specs / plans, no hardware) ---

def test_voice_wake_and_scan_slots():
    r = main.parse_voice_command("ACD scan RSA-2048 and AES-256")
    assert r["wake_detected"] is True and r["wake_phrase"] == "acd"
    assert r["mode"] == "scan" and r["status"] == "matched"
    assert r["slots"]["algorithms"] == ["RSA-2048", "AES-256"]
    assert r["confidence_level"] == "exact"


def test_voice_phrase_mapping_six_modes():
    cases = {
        "hey ACD show the structure tree": "tree",
        "ok ACD run the migration plan": "plan",
        "ACD decide now": "decide",
        "hey ACD open google earth": "earth",
        "ACD show docker images": "images",
        "ok ACD show the audit ledger": "ledger",
        "ACD run checks": "checks",
        "hey ACD open street view for NIST": "streetview",
    }
    for phrase, mode in cases.items():
        r = main.parse_voice_command(phrase)
        assert r["mode"] == mode and r["status"] == "matched", phrase


def test_voice_body_and_distance_slots():
    r = main.parse_voice_command("hey ACD open street view for NIST")
    assert r["slots"]["body"] == "NIST"
    d = main.parse_voice_command("ACD distance NIST to ETSI")
    assert d["mode"] == "distance"
    assert d["slots"]["from_body"] == "NIST"
    assert d["slots"]["to_body"] == "ETSI" and d["slots"]["km"] > 5000


def test_voice_unknown_command_path():
    r = main.parse_voice_command("blorp the frobnicate")
    assert r["status"] == "no_match" and r["mode"] is None
    assert r["confidence"] == 0.0 and r["confidence_level"] == "unknown"


def test_voice_route_runs_through_six_states():
    route = main.route_voice_command("ACD scan RSA-2048")
    assert route["states"] == ["IDLE", "LISTENING", "THINKING",
                               "RESPONDING", "IDLE"]
    assert "scan" in route["reply_text"]
    assert route["speech_plan"]["ssml"].startswith("<speak")


def test_diarization_counts():
    d = main.diarize_transcript(
        "SPEAKER 1: welcome to the briefing today\n"
        "DARION: scan everything twice please\n"
        "SPEAKER 1: copy that")
    assert d["speakers"]["SPEAKER 1"]["words"] == 7
    assert d["speakers"]["DARION"]["words"] == 4
    assert d["total_words"] == 11 and len(d["turns"]) == 3


def test_voiceprint_match_and_unknown():
    hit = main.match_voiceprint(main.ENROLLED_VOICEPRINTS["Analyst (demo)"])
    assert hit["matched"] is True and hit["speaker"] == "Analyst (demo)"
    assert hit["synthetic_demo_data"] is True
    assert hit["biometric_identification"] is False
    miss = main.match_voiceprint([1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
    assert miss["speaker"] == "UNKNOWN" and miss["matched"] is False
    assert main.cosine_similarity([1.0, 0.0], [1.0, 0.0]) == 1.0


def test_speech_plan_clamping_and_escaping():
    plan = main.build_speech_plan("Hello <world> & friends.",
                                  rate=9, pitch=-99, volume=500)
    assert plan["rate"] == 2.0 and plan["pitch"] == -12
    assert plan["volume"] == 100
    assert "&lt;world&gt;" in plan["ssml"] and "<world>" not in plan["ssml"]
    assert plan["hardware_accessed"] is False


def test_speech_queue_fifo_and_verdict():
    queue = main.SpeechQueue()
    queue.enqueue(main.build_speech_plan("First."))
    queue.enqueue(main.build_speech_plan("Second."))
    assert len(queue) == 2
    assert queue.next()["text"] == "First."
    assert queue.peek()["text"] == "Second."
    verdict = main.speak_verdict(["ML-KEM-1024", "AES-256"])
    assert "decision: GO" in verdict["text"]


def test_wav_round_trip_analysis(tmp_path):
    path = str(tmp_path / "tone.wav")
    main.write_wav(path, main.generate_tone_samples(440, 1.0, 16000),
                   sample_rate=16000)
    info = main.analyse_wav(path)
    assert info["duration_seconds"] == 1.0
    assert info["sample_rate"] == 16000 and info["channels"] == 1
    assert info["bit_depth"] == 16
    assert 0.3 < info["rms"] < 0.4 and 0.49 < info["peak"] < 0.51
    assert info["rms_dbfs"] < 0 and info["silence_ratio"] < 0.1


def test_audio_formats_and_loudness():
    formats = {f["format"] for f in main.AUDIO_FORMATS}
    assert formats == {"WAV", "FLAC", "MP3", "AAC", "Opus"}
    assert main.loudness_check(-16.0, "podcast")["within_tolerance"] is True
    assert main.loudness_check(-14.0, "streaming")["target_lufs"] == -14.0
    assert main.loudness_check(-30.0, "podcast")["within_tolerance"] is False
    pipeline = main.audio_pipeline_spec()
    assert pipeline["input_profile"]["hardware_accessed"] is False
    assert "scan" in pipeline["recognition"]["grammar_modes"]


def test_bluetooth_rssi_distance_monotonic():
    distances = [main.estimate_distance_m(r) for r in (-40, -60, -80, -100)]
    assert distances == sorted(distances)
    assert all(d > 0 for d in distances)


def test_bluetooth_pairing_security_flags():
    weak = main.assess_pairing("just_works")
    assert weak["verdict"] == "WEAK" and weak["mitm_protection"] is False
    strong = main.assess_pairing("numeric_comparison")
    assert strong["verdict"] == "STRONG"
    assert strong["mitm_protection"] is True
    assessment = main.bluetooth_security_assessment()
    assert assessment["weakest"]["verdict"] == "WEAK"
    assert assessment["strongest"]["verdict"] == "STRONG"
    assert assessment["synthetic_scan"] is True


def test_bluetooth_scan_shape_and_bonding_store():
    import re
    devices = main.bluetooth_synthetic_scan()
    assert len(devices) == 5
    for d in devices:
        assert re.fullmatch(r"[0-9A-F]{2}(:[0-9A-F]{2}){5}", d["address"])
        assert d["synthetic"] is True and d["distance_m"] > 0
    uuids = {s["uuid"] for s in main.BLUETOOTH_SERVICES}
    assert {"0x180D", "0x180F", "0x180A"} <= uuids
    store = main.BondingStore()
    store.bond(devices[0])
    assert len(store) == 1
    assert store.get(devices[0]["address"])["assessment"]["verdict"] == "STRONG"
    assert store.remove(devices[0]["address"]) is True


def test_camera_storage_math():
    raw = main.estimate_storage("8K DCI", 24, "RAW")
    h265 = main.estimate_storage("8K DCI", 24, "H.265")
    assert raw["width"] == 8192 and raw["height"] == 4320
    assert raw["gb_per_hour"] > h265["gb_per_hour"] > 0
    assert raw["mb_per_s"] > h265["mb_per_s"]
    uhd = main.estimate_storage("8K UHD", 24, "RAW")
    assert uhd["width"] == 7680 and uhd["gb_per_hour"] < raw["gb_per_hour"]
    slow = main.estimate_storage("8K DCI", 120, "RAW")
    assert slow["frame_rate_class"] == "slow motion"
    assert slow["gb_per_hour"] > raw["gb_per_hour"]


def test_camera_fov_and_stereo_budget():
    fov = main.camera_fov(35)
    assert 50 < fov["hfov_deg"] < 60 and 35 < fov["vfov_deg"] < 42
    wide = main.camera_fov(16)
    assert wide["hfov_deg"] > fov["hfov_deg"]
    frame = main.framing_at_distance(35, 10.0)
    assert frame["frame_width_m"] > frame["frame_height_m"] > 0
    budget = main.stereo_depth_budget()
    assert budget["within_budget"] is True
    assert budget["max_parallax_deg"] <= budget["budget_deg"]
    tight = main.stereo_depth_budget(interaxial_mm=200, nearest_m=0.5,
                                     convergence_m=2.0, farthest_m=8.0)
    assert tight["within_budget"] is False


def test_camera_capture_plan_references_body_and_pano():
    plan = main.camera_capture_plan("NIST")
    nist = main.get_geo("NIST")
    assert plan["body"] == "NIST"
    assert plan["lat"] == nist["lat"] and plan["lon"] == nist["lon"]
    assert plan["streetview_pano"] == main.pano_id_for("NIST")
    assert plan["hardware_accessed"] is False
    assert main.camera_capture_plan("no such body") is None
    spec = main.camera_spec_summary()
    assert spec["resolutions"]["8K DCI"]["width"] == 8192
    assert {c["name"] for c in spec["color_pipelines"]} >= {"RAW", "LOG",
                                                            "HDR10", "HLG"}


def test_six_cycle_media_readiness():
    cycle = main.run_six_cycle(["ML-KEM-1024", "AES-256"])
    media = cycle["media"]
    assert media["voice_ready"] is True and media["speaker_ready"] is True
    assert media["audio_ready"] is True
    assert media["bluetooth_ready"] is True and media["camera_ready"] is True
    assert media["hardware_accessed"] is False
    responding = [e for e in cycle["ledger"]
                  if isinstance(e["data"], dict)
                  and e["data"].get("event") == "plan_emitted"]
    assert responding[0]["data"]["media"]["camera_ready"] is True
