"""Focused regression tests for deterministic offline advisory database builder in LogicFalcon."""

import json
from pathlib import Path

import pytest

from packages.review.adapters.advisory_builder import AdvisoryDatabaseBuilder
from packages.review.adapters.dependency_advisory import DependencyAdvisoryAdapter


def test_parse_osv_record() -> None:
    builder = AdvisoryDatabaseBuilder()
    osv_record = {
        "id": "GHSA-j8r2-6x86-q33q",
        "aliases": ["CVE-2023-32681"],
        "summary": "Requests Proxy-Authorization header leak",
        "details": "Requests before 2.31.0 leaks Proxy-Authorization headers to destination servers upon redirect.",
        "affected": [
            {
                "package": {
                    "ecosystem": "PyPI",
                    "name": "requests",
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "2.31.0"},
                        ],
                    }
                ],
            }
        ],
    }

    advisories = builder.parse_osv_record(osv_record)
    assert len(advisories) == 1
    adv = advisories[0]
    assert adv["package"] == "requests"
    assert adv["safe_version"] == "2.31.0"
    assert adv["vulnerable_max"] == (2, 31, 0)
    assert adv["cve"] == "CVE-2023-32681"
    assert "Proxy-Authorization" in adv["description"]


def test_offline_ingest_from_json_files_and_deduplicate(tmp_path: Path) -> None:
    builder = AdvisoryDatabaseBuilder()
    data_file1 = tmp_path / "osv_requests.json"
    data_file2 = tmp_path / "osv_flask.json"

    rec1 = {
        "id": "GHSA-1",
        "aliases": ["CVE-2023-32681"],
        "summary": "Requests leak",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"}, "ranges": [{"events": [{"fixed": "2.31.0"}]}]}],
    }
    rec2 = {
        "id": "GHSA-2",
        "aliases": ["CVE-2023-30861"],
        "summary": "Flask cookie leak",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "flask"}, "ranges": [{"events": [{"fixed": "2.3.2"}]}]}],
    }

    data_file1.write_text(json.dumps(rec1), encoding="utf-8")
    data_file2.write_text(json.dumps(rec2), encoding="utf-8")

    db = builder.ingest_from_json_files([data_file1, data_file2])
    assert len(db) == 2
    # Sorted deterministically by package name
    assert db[0]["package"] == "flask"
    assert db[0]["cve"] == "CVE-2023-30861"
    assert db[1]["package"] == "requests"


def test_network_access_strictly_opt_in() -> None:
    builder = AdvisoryDatabaseBuilder()
    with pytest.raises(ValueError) as exc_info:
        builder.fetch_online_advisories(package_name="flask", enable_network=False)
    assert "External network access is disabled" in str(exc_info.value)


def test_adapter_with_custom_built_advisories() -> None:
    custom_advisories = [
        {
            "package": "custom-pkg",
            "vulnerable_max": (1, 5, 0),
            "safe_version": "1.5.0",
            "cve": "CVE-2026-99999",
            "description": "Test custom advisory flaw",
        }
    ]

    adapter = DependencyAdvisoryAdapter(custom_advisories=custom_advisories)
    reqs_content = "custom-pkg==1.4.2\n"
    findings = adapter.analyze_file("requirements.txt", reqs_content)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "DEP-001"
    assert "CVE-2026-99999" in f.message
    assert f.proposed_fix is not None
    assert "1.5.0" in f.proposed_fix.replacement_code


def test_advisory_provenance_and_aliases_extraction() -> None:
    """Verifies source provenance, source_id, and alias preservation across advisory sources."""
    builder = AdvisoryDatabaseBuilder()
    record = {
        "id": "GHSA-abcd-1234",
        "aliases": ["CVE-2024-11111", "PYSEC-2024-99"],
        "summary": "Sample advisory",
        "database_specific": {"source": "GitHub Security Advisory"},
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "my-lib"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
            }
        ],
    }

    advisories = builder.parse_osv_record(record)
    assert len(advisories) == 1
    adv = advisories[0]
    assert adv["source_id"] == "GHSA-abcd-1234"
    assert adv["cve"] == "CVE-2024-11111"
    assert adv["provenance"] == "GitHub Security Advisory"
    assert "PYSEC-2024-99" in adv["aliases"]
    assert "CVE-2024-11111" in adv["aliases"]


def test_advisory_affected_version_semantics_last_affected_and_explicit_list() -> None:
    """Verifies affected version extraction from last_affected events and explicit versions lists."""
    builder = AdvisoryDatabaseBuilder()

    # 1. last_affected event
    rec_last = {
        "id": "PYSEC-2024-001",
        "aliases": ["CVE-2024-22222"],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "pkg-a"},
                "ranges": [{"events": [{"introduced": "0"}, {"last_affected": "2.0.5"}]}],
            }
        ],
    }
    adv_last = builder.parse_osv_record(rec_last)
    assert len(adv_last) == 1
    assert adv_last[0]["vulnerable_max"] == (2, 0, 5)
    assert adv_last[0]["safe_version"] == ">2.0.5"

    # 2. explicit versions list without ranges
    rec_list = {
        "id": "OSV-2024-002",
        "aliases": ["CVE-2024-33333"],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "pkg-b"},
                "versions": ["1.0.0", "1.1.0", "1.2.4"],
            }
        ],
    }
    adv_list = builder.parse_osv_record(rec_list)
    assert len(adv_list) == 1
    assert adv_list[0]["vulnerable_max"] == (1, 2, 4)
    assert adv_list[0]["safe_version"] == ">1.2.4"


def test_advisory_deduplication_and_alias_merging() -> None:
    """Deduplication merges aliases and keeps the higher vulnerable_max entry."""
    builder = AdvisoryDatabaseBuilder()
    adv1 = {
        "package": "shared-pkg",
        "cve": "CVE-2024-55555",
        "vulnerable_max": (1, 0, 0),
        "safe_version": "1.0.0",
        "source_id": "GHSA-1",
        "aliases": ["CVE-2024-55555", "GHSA-1"],
        "description": "Feed 1",
    }
    adv2 = {
        "package": "shared-pkg",
        "cve": "CVE-2024-55555",
        "vulnerable_max": (1, 2, 0),
        "safe_version": "1.2.0",
        "source_id": "PYSEC-1",
        "aliases": ["CVE-2024-55555", "PYSEC-1"],
        "description": "Feed 2 updated",
    }

    deduped = builder.deduplicate_and_sort([adv1, adv2])
    assert len(deduped) == 1
    entry = deduped[0]
    # Kept higher version
    assert entry["vulnerable_max"] == (1, 2, 0)
    assert entry["safe_version"] == "1.2.0"
    # Merged aliases
    assert "GHSA-1" in entry["aliases"]
    assert "PYSEC-1" in entry["aliases"]


def test_advisory_deterministic_json_serialization(tmp_path: Path) -> None:
    """Exported advisory database JSON must be byte-for-byte deterministic across runs."""
    builder = AdvisoryDatabaseBuilder()
    advisories = [
        {
            "package": "zebra",
            "cve": "CVE-2024-9999",
            "vulnerable_max": (2, 0),
            "safe_version": "2.0",
            "source_id": "GHSA-z",
            "aliases": ["CVE-2024-9999"],
            "description": "Zebra vuln",
        },
        {
            "package": "alpha",
            "cve": "CVE-2024-1111",
            "vulnerable_max": (1, 0),
            "safe_version": "1.0",
            "source_id": "GHSA-a",
            "aliases": ["CVE-2024-1111"],
            "description": "Alpha vuln",
        },
    ]

    deduped = builder.deduplicate_and_sort(advisories)
    out1 = tmp_path / "db1.json"
    out2 = tmp_path / "db2.json"

    builder.export_advisory_database_json(deduped, out1)
    builder.export_advisory_database_json(deduped, out2)

    content1 = out1.read_bytes()
    content2 = out2.read_bytes()
    assert content1 == content2
    # Check package ordering: alpha before zebra
    parsed = json.loads(content1.decode("utf-8"))
    assert parsed[0]["package"] == "alpha"
    assert parsed[1]["package"] == "zebra"


def test_advisory_malformed_input_resilience() -> None:
    """Builder must handle malformed OSV payloads without unhandled exceptions."""
    builder = AdvisoryDatabaseBuilder()
    assert builder.parse_osv_record({}) == []
    assert builder.parse_osv_record(None) == []  # type: ignore[arg-type]
    assert builder.parse_osv_record({"affected": "not-a-list"}) == []
    assert builder.parse_osv_record({"affected": [{"package": "not-a-dict"}]}) == []
    assert builder.parse_osv_record({"affected": [{"package": {"name": "p"}, "ranges": "not-a-list"}]}) == []
    assert builder.parse_osv_record({"affected": [{"package": {"name": "p"}, "ranges": [{"events": "bad"}]}]}) == []

