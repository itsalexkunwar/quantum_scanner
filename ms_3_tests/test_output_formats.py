import json
import subprocess
import sys


FIXTURE_DIR = "ms_3_fixtures"


def run_qscan(args):
    cmd = [sys.executable, "qscan.py"] + args
    return subprocess.run(cmd, capture_output=True, text=True)


def test_json_schema_is_stable():
    result = run_qscan([FIXTURE_DIR, "--json"])

    data = json.loads(result.stdout)

    # exit code must match JSON summary exit_code
    assert result.returncode == data["summary"]["exit_code"]

    # top level keys must always exist
    for key in ["schema_version", "tool", "target", "stats", "summary", "findings"]:
        assert key in data

    summary = data["summary"]

    # summary keys must always exist
    for key in ["counts_by_category", "findings_total", "exit_code"]:
        assert key in summary

    counts = summary["counts_by_category"]

    # category keys must always exist even if zero
    for key in ["broken", "obsolete_tls", "quantum_vulnerable", "import"]:
        assert key in counts

    # findings_total must equal actual findings length
    assert summary["findings_total"] == len(data["findings"])


def test_text_and_json_counts_match():
    result_json = run_qscan([FIXTURE_DIR, "--json"])
    data = json.loads(result_json.stdout)

    # exit code consistency
    assert result_json.returncode == data["summary"]["exit_code"]

    result_text = run_qscan([FIXTURE_DIR])
    assert result_text.returncode == data["summary"]["exit_code"]

    text = result_text.stdout
    counts = data["summary"]["counts_by_category"]

    # text must reflect JSON counts
    assert f"Broken: {counts['broken']}" in text
    assert f"Obsolete TLS: {counts['obsolete_tls']}" in text
    assert f"Quantum vulnerable: {counts['quantum_vulnerable']}" in text
    assert f"Imports: {counts['import']}" in text

    assert f"Findings: {data['summary']['findings_total']}" in text
