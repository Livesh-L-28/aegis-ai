"""Atomic, contained checkpoint persistence for LogicFalcon FDE missions and evidence."""

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from packages.review.adapters.ast_security import redact_secrets_in_text
from packages.review.fde.orchestration.orchestrator import MissionExecutionReport
from packages.review.security.path_validation import validate_contained_path


class FdeCheckpointStore:
    """Manages atomic, secret-safe persistence and recovery of mission execution state."""

    SCHEMA_VERSION = "1.0.0"

    def __init__(self, storage_dir: Path | str = ".logicfalcon/fde/checkpoints") -> None:
        self.storage_dir = Path(storage_dir).resolve()
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _sanitize_payload(self, obj: Any) -> Any:
        """Recursively sanitizes dictionary keys and text values for secrets."""
        if isinstance(obj, dict):
            clean: dict[str, Any] = {}
            for k, v in obj.items():
                k_lower = str(k).lower()
                if any(s in k_lower for s in ("token", "key", "secret", "password", "auth", "credential")):
                    clean[k] = "[REDACTED]"
                elif isinstance(v, (dict, list)):
                    clean[k] = self._sanitize_payload(v)
                elif isinstance(v, str):
                    clean[k] = redact_secrets_in_text(v)
                else:
                    clean[k] = v
            return clean
        elif isinstance(obj, list):
            return [self._sanitize_payload(item) for item in obj]
        elif isinstance(obj, str):
            return redact_secrets_in_text(obj)
        return obj

    def save_checkpoint(
        self,
        report: MissionExecutionReport,
        metadata: dict[str, Any] | None = None,
    ) -> Path:
        """Atomically saves mission report and evidence to a versioned, secret-redacted JSON file."""
        file_name = f"mission_{report.mission_id}.json"
        target_path = self.storage_dir / file_name

        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "mission": report.to_dict(),
            "evidence": [ev.model_dump(mode="json") for ev in report.evidence_records],
            "metadata": metadata or {},
        }

        # Redact any secrets before writing
        sanitized_payload = self._sanitize_payload(payload)
        raw_json = json.dumps(sanitized_payload, indent=2, default=str)
        sanitized_json = redact_secrets_in_text(raw_json)

        # Atomic write pattern: write to temporary file in same directory, then atomic rename
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=self.storage_dir,
            delete=False,
            encoding="utf-8",
        ) as temp_file:
            temp_file.write(sanitized_json)
            temp_file.flush()
            os.fsync(temp_file.fileno())
            temp_name = temp_file.name

        try:
            os.replace(temp_name, target_path)
            target_path.chmod(0o600)
            return target_path
        except Exception:
            if os.path.exists(temp_name):
                os.remove(temp_name)
            raise

    def load_checkpoint(self, checkpoint_target: Path | str) -> dict[str, Any] | None:
        """Safely loads a previously saved mission checkpoint by ID or Path."""
        if isinstance(checkpoint_target, Path) or ("/" in str(checkpoint_target) or "\\" in str(checkpoint_target)):
            target_path = Path(checkpoint_target).resolve()
            if not target_path.is_file():
                return None
        else:
            file_name = f"mission_{checkpoint_target}.json"
            target_path = self.storage_dir / file_name
            contained = validate_contained_path(self.storage_dir, Path(file_name))
            if not contained or not target_path.is_file():
                return None

        try:
            content = target_path.read_text(encoding="utf-8")
            data = json.loads(content)
            if not isinstance(data, dict):
                return None
            return data
        except Exception:
            return None

    def list_checkpoints(self) -> list[str]:
        """Lists all stored mission checkpoint IDs."""
        missions: list[str] = []
        for p in self.storage_dir.glob("mission_*.json"):
            if p.is_file():
                m_id = p.stem.replace("mission_", "")
                missions.append(m_id)
        return sorted(missions)
