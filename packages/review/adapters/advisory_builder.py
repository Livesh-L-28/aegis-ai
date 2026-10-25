"""Deterministic offline advisory database synchronization and build utility for LogicFalcon.

Supports ingesting Open Source Vulnerabilities (OSV) and GitHub Advisory Database (GHSA)
JSON records completely offline, with strict opt-in external network synchronization.
"""

import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def _parse_version_tuple(version_str: str) -> tuple[int, ...] | None:
    parts: list[int] = []
    for segment in version_str.split("."):
        clean_seg = re.sub(r"[^\d]", "", segment)
        if clean_seg:
            try:
                parts.append(int(clean_seg))
            except ValueError:
                break
        else:
            break
    return tuple(parts) if parts else None


class AdvisoryDatabaseBuilder:
    """Builds and normalizes local vulnerability advisory databases from OSV/GHSA schemas."""

    def parse_osv_record(self, record: dict[str, Any]) -> list[dict[str, Any]]:
        """Extracts normalized advisory entries from a single OSV-schema record with provenance and aliases."""
        if not isinstance(record, dict):
            return []

        results: list[dict[str, Any]] = []

        advisory_id = str(record.get("id") or "UNKNOWN-ID")
        aliases = record.get("aliases", [])
        if not isinstance(aliases, list):
            aliases = []
        aliases_clean = [str(a) for a in aliases if isinstance(a, (str, int))]

        cve_alias = next((a for a in aliases_clean if a.startswith("CVE-")), advisory_id)
        description = record.get("summary") or record.get("details") or f"Vulnerability advisory {cve_alias}"

        db_spec = record.get("database_specific", {})
        provenance = (
            db_spec.get("source")
            if isinstance(db_spec, dict) and db_spec.get("source")
            else ("GHSA" if advisory_id.startswith("GHSA") else ("PYSEC" if advisory_id.startswith("PYSEC") else "OSV"))
        )

        affected_list = record.get("affected", [])
        if not isinstance(affected_list, list):
            return []

        for affected in affected_list:
            if not isinstance(affected, dict):
                continue
            pkg_info = affected.get("package", {})
            if not isinstance(pkg_info, dict):
                continue
            ecosystem = str(pkg_info.get("ecosystem", "")).lower()
            pkg_name = str(pkg_info.get("name", "")).strip().lower()

            # Focus on PyPI ecosystem
            if ecosystem and ecosystem != "pypi":
                continue
            if not pkg_name:
                continue

            extracted_from_ranges = False
            # 1. Extract from ranges (fixed or last_affected)
            ranges = affected.get("ranges", [])
            if isinstance(ranges, list):
                for r in ranges:
                    if not isinstance(r, dict):
                        continue
                    events = r.get("events", [])
                    if not isinstance(events, list):
                        continue
                    for ev in events:
                        if not isinstance(ev, dict):
                            continue
                        if "fixed" in ev:
                            fixed_ver = str(ev["fixed"]).strip()
                            ver_tuple = _parse_version_tuple(fixed_ver)
                            if ver_tuple:
                                results.append(
                                    {
                                        "package": pkg_name,
                                        "vulnerable_max": ver_tuple,
                                        "safe_version": fixed_ver,
                                        "cve": cve_alias,
                                        "source_id": advisory_id,
                                        "provenance": provenance,
                                        "aliases": aliases_clean,
                                        "description": str(description).strip(),
                                    }
                                )
                                extracted_from_ranges = True
                        elif "last_affected" in ev and not extracted_from_ranges:
                            last_ver = str(ev["last_affected"]).strip()
                            ver_tuple = _parse_version_tuple(last_ver)
                            if ver_tuple:
                                results.append(
                                    {
                                        "package": pkg_name,
                                        "vulnerable_max": ver_tuple,
                                        "safe_version": f">{last_ver}",
                                        "cve": cve_alias,
                                        "source_id": advisory_id,
                                        "provenance": provenance,
                                        "aliases": aliases_clean,
                                        "description": str(description).strip(),
                                    }
                                )
                                extracted_from_ranges = True

            # 2. Extract from explicit versions list if ranges didn't yield fixed versions
            if not extracted_from_ranges:
                versions = affected.get("versions", [])
                if isinstance(versions, list) and versions:
                    parsed_vers = []
                    for v in versions:
                        vt = _parse_version_tuple(str(v))
                        if vt:
                            parsed_vers.append((vt, str(v)))
                    if parsed_vers:
                        max_vt, max_str = max(parsed_vers, key=lambda x: x[0])
                        results.append(
                            {
                                "package": pkg_name,
                                "vulnerable_max": max_vt,
                                "safe_version": f">{max_str}",
                                "cve": cve_alias,
                                "source_id": advisory_id,
                                "provenance": provenance,
                                "aliases": aliases_clean,
                                "description": str(description).strip(),
                            }
                        )

        return results

    def ingest_from_json_files(
        self, file_paths: Sequence[Path | str]
    ) -> list[dict[str, Any]]:
        """Ingests local OSV JSON files completely offline, deduplicating and sorting deterministically."""
        all_advisories: list[dict[str, Any]] = []

        for fp in file_paths:
            path_obj = Path(fp)
            if not path_obj.is_file():
                continue
            try:
                content = path_obj.read_text(encoding="utf-8")
                data = json.loads(content)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            all_advisories.extend(self.parse_osv_record(item))
                elif isinstance(data, dict):
                    all_advisories.extend(self.parse_osv_record(data))
            except (OSError, json.JSONDecodeError):
                continue

        return self.deduplicate_and_sort(all_advisories)

    def ingest_from_directory(self, dir_path: Path | str) -> list[dict[str, Any]]:
        """Discovers and parses all .json files in a directory offline."""
        p = Path(dir_path)
        if not p.is_dir():
            return []
        json_files = sorted(p.rglob("*.json"))
        return self.ingest_from_json_files(json_files)

    def deduplicate_and_sort(
        self, advisories: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Deduplicates advisories by (package, cve) and sorts deterministically."""
        seen: dict[tuple[str, str], dict[str, Any]] = {}
        for adv in advisories:
            key = (adv["package"], adv["cve"])
            if key not in seen:
                seen[key] = dict(adv)
            else:
                existing = seen[key]
                # Merge aliases
                existing_aliases = set(existing.get("aliases", []))
                existing_aliases.update(adv.get("aliases", []))
                existing["aliases"] = sorted(existing_aliases)

                # Keep entry with higher vulnerable_max
                if adv.get("vulnerable_max", ()) > existing.get("vulnerable_max", ()):
                    adv_copy = dict(adv)
                    adv_copy["aliases"] = existing["aliases"]
                    seen[key] = adv_copy

        sorted_entries = sorted(
            seen.values(),
            key=lambda a: (a["package"], a["cve"], str(a.get("source_id", ""))),
        )
        return sorted_entries

    def fetch_online_advisories(
        self, package_name: str, enable_network: bool = False
    ) -> list[dict[str, Any]]:
        """Fetches latest advisories from OSV API. External network access is strictly opt-in."""
        if not enable_network:
            raise ValueError(
                "External network access is disabled. Pass enable_network=True to fetch online."
            )

        import httpx

        url = "https://api.osv.dev/v1/query"
        payload = {"package": {"name": package_name, "ecosystem": "PyPI"}}

        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.post(url, json=payload)
                if resp.status_code != 200:
                    return []
                data = resp.json()
                vulns = data.get("vulns", [])
                advisories: list[dict[str, Any]] = []
                for v in vulns:
                    advisories.extend(self.parse_osv_record(v))
                return self.deduplicate_and_sort(advisories)
        except Exception:
            return []

    def export_advisory_database_json(
        self, advisories: list[dict[str, Any]], output_path: Path | str
    ) -> None:
        """Serializes advisories to a deterministic JSON file."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        # Convert tuple vulnerable_max to list for JSON serialization
        serializable = []
        for adv in advisories:
            c = dict(adv)
            if isinstance(c.get("vulnerable_max"), tuple):
                c["vulnerable_max"] = list(c["vulnerable_max"])
            serializable.append(c)
        out.write_text(json.dumps(serializable, indent=2, sort_keys=True) + "\n", encoding="utf-8")
