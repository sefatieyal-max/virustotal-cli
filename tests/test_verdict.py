import verdict


def test_no_detections_is_clean():
    assert verdict.classify({"malicious": 0, "suspicious": 0,}) == verdict.VERDICT_CLEAN

def test_three_malicious_is_malicious():
    assert verdict.classify({"malicious": 3}) == verdict.VERDICT_MALICIOUS


def test_two_malicious_is_only_suspicious():
    assert verdict.classify({"malicious": 2}) == verdict.VERDICT_SUSPICIOUS


def test_negative_reputation_is_suspicious():
    assert verdict.classify({"malicious" : 0}, reputation=-5) == verdict.VERDICT_SUSPICIOUS

def test_missing_stats_does_not_crash():
    assert verdict.classify(None) == verdict.VERDICT_CLEAN