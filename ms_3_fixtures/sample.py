import json
import os
import subprocess
import sys


FIXTURE_DIR = os.path.join("tests", "fixtures", "ms_0")


def run_qscan(args):
    cmd = [sys.executable, "qscan.py"] + args
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result


def test_json_schema_is_stable():
    result = run_qscan([FIXTURE_DIR, "--json"])
    assert result.returncode == 1

    data = json.loads(result.stdout)

    for key in ["schema_version", "tool", "target", "stats", "summary", "findings"]:
        assert key in data

    assert data["schema_version"] == "1.0"

    for key in ["counts_by_category", "findings_total", "exit_code"]:
        assert key in data["summary"]

    counts = data["summary"]["counts_by_category"]
    for key in ["broken", "obsolete_tls", "quantum_vulnerable", "import"]:
        assert key in counts

    assert isinstance(data["findings"], list)
    assert data["summary"]["findings_total"] == len(data["findings"])


def test_text_and_json_counts_match():
    result_json = run_qscan([FIXTURE_DIR, "--json"])
    assert result_json.returncode == 1
    data = json.loads(result_json.stdout)

    result_text = run_qscan([FIXTURE_DIR])
    assert result_text.returncode == 1
    text = result_text.stdout

    counts = data["summary"]["counts_by_category"]

    assert f"Broken: {counts['broken']}" in text
    assert f"Obsolete TLS: {counts['obsolete_tls']}" in text
    assert f"Quantum vulnerable: {counts['quantum_vulnerable']}" in text
    assert f"Imports: {counts['import']}" in text

    assert f"Findings: {data['summary']['findings_total']}" in text
