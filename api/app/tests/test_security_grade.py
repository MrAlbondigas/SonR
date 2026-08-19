from app.main import compute_security_grade

CLEAN = {"critical": 0, "high": 0, "medium": 0, "low": 0}


def test_clean_network_gets_a():
    result = compute_security_grade(CLEAN, credential_count=0, attack_path_count=0, aging_count=0, kev_count=0)
    assert result["score"] == 100
    assert result["letter"] == "A"
    assert result["breakdown"] == []


def test_single_critical_vulnerability_deducts_points_but_stays_grade_a():
    counts = {**CLEAN, "critical": 1}
    result = compute_security_grade(counts, credential_count=0, attack_path_count=0, aging_count=0, kev_count=0)
    assert result["score"] == 92
    assert result["letter"] == "A"


def test_two_critical_vulnerabilities_drop_to_grade_b():
    counts = {**CLEAN, "critical": 2}
    result = compute_security_grade(counts, credential_count=0, attack_path_count=0, aging_count=0, kev_count=0)
    assert result["score"] == 84
    assert result["letter"] == "B"


def test_default_credentials_hurt_more_than_a_single_high_vuln():
    cred_result = compute_security_grade(CLEAN, credential_count=1, attack_path_count=0, aging_count=0, kev_count=0)
    high_result = compute_security_grade(
        {**CLEAN, "high": 1}, credential_count=0, attack_path_count=0, aging_count=0, kev_count=0
    )
    assert cred_result["score"] < high_result["score"]


def test_score_never_goes_below_zero():
    counts = {**CLEAN, "critical": 50}
    result = compute_security_grade(counts, credential_count=0, attack_path_count=0, aging_count=0, kev_count=0)
    assert result["score"] == 0
    assert result["letter"] == "F"


def test_grade_letter_thresholds():
    assert compute_security_grade(CLEAN, 0, 0, 0, 0)["letter"] == "A"
    # un unico hallazgo medio (-2) no deberia bajar de la nota A todavia
    assert compute_security_grade({**CLEAN, "medium": 1}, 0, 0, 0, 0)["letter"] == "A"


def test_known_exploited_vulnerability_is_penalized_independently_of_severity():
    with_kev = compute_security_grade(CLEAN, credential_count=0, attack_path_count=0, aging_count=0, kev_count=1)
    without_kev = compute_security_grade(CLEAN, credential_count=0, attack_path_count=0, aging_count=0, kev_count=0)
    assert with_kev["score"] < without_kev["score"]
