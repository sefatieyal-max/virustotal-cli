"""Turn VirusTotal detection stats into a simple verdict."""

MALICIOUS_THRESHOLD = 3
NEGATIVE_REPUTATION_THRESHOLD = 0
FLAGGED_CATEGORIES = {"malicious", "suspicious"}
MALICIOUS_CATEGORY = "malicious"

VERDICT_MALICIOUS = "MALICIOUS"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_CLEAN = "CLEAN"
VERDICT_NOT_FOUND = "NOT FOUND"


def classify(stats, reputation=None):
    """Return a verdict from detection stats, plus community reputation if given."""
    stats = stats or {}
    malicious = stats.get("malicious") or 0
    suspicious = stats.get("suspicious") or 0
    bad_reputation = isinstance(reputation, int) and reputation < NEGATIVE_REPUTATION_THRESHOLD
    if malicious >= MALICIOUS_THRESHOLD:
        return VERDICT_MALICIOUS
    if malicious > 0 or suspicious > 0 or bad_reputation:
        return VERDICT_SUSPICIOUS
    return VERDICT_CLEAN

def flagged_engines(results):
    """Return the engines that flagged the indicator, malicious ones first."""
    results = results or {}
    flagged = [
        engine for engine in results.values()
        if isinstance(engine, dict) and engine.get("category") in FLAGGED_CATEGORIES
    ]
    return sorted(
        flagged,
        key=lambda engine: (engine.get("category") != MALICIOUS_CATEGORY,
                            str(engine.get("engine_name"))),
    )