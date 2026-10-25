"""Preflight readiness assessment and bounded environment probes for LogicFalcon FDE."""

import os
import socket
import subprocess
import sys
from pathlib import Path

from packages.review.adapters.ast_security import redact_secrets_in_text
from packages.review.fde.discovery import DeploymentDiscoveryEngine
from packages.review.fde.models import (
    DeploymentInventory,
    PreflightFinding,
    PreflightReport,
    PreflightSeverity,
    PreflightStatus,
)


class PreflightRunner:
    """Executes safe, bounded, read-only preflight verification probes."""

    def __init__(
        self,
        repo_root: Path | str = ".",
        check_ports: bool = True,
        check_env_vars: bool = True,
        check_docker: bool = False,
        check_dns: bool = False,
        dns_hosts: list[str] | None = None,
        http_health_url: str | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.check_ports = check_ports
        self.check_env_vars = check_env_vars
        self.check_docker = check_docker
        self.check_dns = check_dns
        self.dns_hosts = dns_hosts or []
        self.http_health_url = http_health_url
        self.timeout_seconds = timeout_seconds

    def run_preflight(
        self,
        inventory: DeploymentInventory | None = None,
    ) -> PreflightReport:
        """Executes discovery and preflight probes to evaluate environment deployment readiness."""
        findings: list[PreflightFinding] = []
        observed_evidence: list[str] = []
        inferred_risks: list[str] = []
        recommended_remediations: list[str] = []

        # 1. Discover static requirements if not provided
        if inventory is None:
            discovery_engine = DeploymentDiscoveryEngine(self.repo_root)
            inventory = discovery_engine.discover()

        observed_evidence.append(
            f"Static discovery found {len(inventory.frameworks)} framework(s), "
            f"{len(inventory.declared_ports)} port(s), and {len(inventory.required_env_vars)} required env var(s)."
        )

        # 2. Runtime Python version verification
        self._probe_runtime_python(inventory, findings, observed_evidence, recommended_remediations)

        # 3. Local port availability verification
        if self.check_ports and inventory.declared_ports:
            self._probe_ports(inventory.declared_ports, findings, observed_evidence, recommended_remediations)

        # 4. Environment variable presence verification
        if self.check_env_vars and inventory.required_env_vars:
            self._probe_env_vars(inventory.required_env_vars, findings, observed_evidence, recommended_remediations)

        # 5. DNS resolution probe (opt-in)
        if self.check_dns and self.dns_hosts:
            self._probe_dns(self.dns_hosts, findings, observed_evidence, recommended_remediations)

        # 6. Docker daemon probe (opt-in or if compose/dockerfile present)
        if self.check_docker or (inventory.container_definitions and self.check_docker):
            self._probe_docker(findings, observed_evidence, recommended_remediations)

        # 7. HTTP endpoint probe (opt-in)
        if self.http_health_url:
            self._probe_http_health(self.http_health_url, findings, observed_evidence, recommended_remediations)

        # 8. Infer deployment risks based on findings
        critical_count = sum(1 for f in findings if f.severity == PreflightSeverity.CRITICAL)
        error_count = sum(1 for f in findings if f.severity == PreflightSeverity.ERROR)
        warning_count = sum(1 for f in findings if f.severity == PreflightSeverity.WARNING)

        if critical_count > 0:
            status = PreflightStatus.BLOCKED
            inferred_risks.append(
                f"Deployment is strictly blocked by {critical_count} critical prerequisite failure(s)."
            )
        elif error_count > 0:
            status = PreflightStatus.FAILED
            inferred_risks.append(
                f"Deployment preflight failed due to {error_count} missing requirement(s)."
            )
        elif warning_count > 0:
            status = PreflightStatus.READY
            inferred_risks.append(
                f"Deployment may proceed with caution; {warning_count} non-blocking warning(s) observed."
            )
        else:
            status = PreflightStatus.READY
            observed_evidence.append("All verified deployment prerequisites satisfied.")

        return PreflightReport(
            status=status,
            findings=findings,
            observed_evidence=observed_evidence,
            inferred_risks=inferred_risks,
            recommended_remediations=recommended_remediations,
        )

    def _probe_runtime_python(
        self,
        inventory: DeploymentInventory,
        findings: list[PreflightFinding],
        evidence: list[str],
        remediations: list[str],
    ) -> None:
        current_version = sys.version_info
        major, minor, micro = current_version[0], current_version[1], current_version[2]
        evidence.append(f"Current Python runtime: {major}.{minor}.{micro}")

        spec = inventory.runtime_versions.get("python")
        if spec and ">=3.12" in spec and (major, minor) < (3, 12):
            findings.append(
                PreflightFinding(
                    rule_id="PRE-RUN-001",
                    severity=PreflightSeverity.CRITICAL,
                    category="RUNTIME",
                    title="Python Version Incompatibility",
                    message=f"Current runtime Python {major}.{minor} does not satisfy {spec}.",
                    remediation="Upgrade environment to Python 3.12 or newer.",
                    blocking=True,
                )
            )
            remediations.append("Switch active virtual environment to Python >= 3.12.")

    def _probe_ports(
        self,
        ports: list[int],
        findings: list[PreflightFinding],
        evidence: list[str],
        remediations: list[str],
    ) -> None:
        for port in ports[:10]:  # bound to at most 10 ports
            is_free = self._is_port_free(port)
            if is_free:
                evidence.append(f"Port {port} is available for binding on localhost.")
            else:
                findings.append(
                    PreflightFinding(
                        rule_id="PRE-NET-PORT",
                        severity=PreflightSeverity.ERROR,
                        category="NETWORK",
                        title=f"Port Conflict on Port {port}",
                        message=f"Target port {port} is already in use or cannot be bound on localhost.",
                        remediation=f"Stop competing process on port {port} or configure an alternative host port.",
                        blocking=True,
                    )
                )
                remediations.append(f"Free port {port} before launching deployment.")

    def _is_port_free(self, port: int) -> bool:
        """Safely checks if a local TCP port can be bound without mutating system state."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False
        finally:
            sock.close()

    def _probe_env_vars(
        self,
        required_vars: list[str],
        findings: list[PreflightFinding],
        evidence: list[str],
        remediations: list[str],
    ) -> None:
        present_count = 0
        missing_vars: list[str] = []

        for var in required_vars:
            val = os.environ.get(var)
            if val is not None and len(val.strip()) > 0:
                present_count += 1
            else:
                missing_vars.append(var)

        evidence.append(f"Environment variables check: {present_count}/{len(required_vars)} variables present.")

        if missing_vars:
            for m_var in missing_vars:
                findings.append(
                    PreflightFinding(
                        rule_id="PRE-ENV-MISSING",
                        severity=PreflightSeverity.ERROR,
                        category="CONFIG",
                        title=f"Missing Environment Variable '{m_var}'",
                        message=f"Required environment variable '{m_var}' is unset or empty in host environment.",
                        remediation=f"Export '{m_var}' in environment or populate in local .env configuration.",
                        blocking=True,
                    )
                )
            remediations.append(f"Configure {len(missing_vars)} missing environment variable(s): {', '.join(missing_vars[:5])}.")

    def _probe_dns(
        self,
        hosts: list[str],
        findings: list[PreflightFinding],
        evidence: list[str],
        remediations: list[str],
    ) -> None:
        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(3.0)
        try:
            for host in hosts[:5]:
                try:
                    socket.getaddrinfo(host, None)
                    evidence.append(f"DNS resolution succeeded for host: {host}")
                except socket.gaierror as e:
                    findings.append(
                        PreflightFinding(
                            rule_id="PRE-NET-DNS",
                            severity=PreflightSeverity.ERROR,
                            category="NETWORK",
                            title=f"DNS Resolution Failed for '{host}'",
                            message=f"Unable to resolve host '{host}': {e}",
                            remediation=f"Verify network connectivity, DNS configuration, and host address '{host}'.",
                            blocking=True,
                        )
                    )
                    remediations.append(f"Fix DNS resolution for {host}.")
        finally:
            socket.setdefaulttimeout(orig_timeout)

    def _probe_docker(
        self,
        findings: list[PreflightFinding],
        evidence: list[str],
        remediations: list[str],
    ) -> None:
        try:
            res = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=4.0,
                shell=False,
            )
            if res.returncode == 0:
                evidence.append("Docker daemon is reachable and responding.")
            else:
                findings.append(
                    PreflightFinding(
                        rule_id="PRE-DOC-DAEMON",
                        severity=PreflightSeverity.WARNING,
                        category="CONTAINER",
                        title="Docker Daemon Unreachable",
                        message=redact_secrets_in_text(f"Docker command failed with code {res.returncode}: {res.stderr.strip()[:200]}"),
                        remediation="Ensure Docker service is running if container deployment is desired.",
                        blocking=False,
                    )
                )
                remediations.append("Start Docker daemon.")
        except FileNotFoundError:
            findings.append(
                PreflightFinding(
                    rule_id="PRE-DOC-NOTFOUND",
                    severity=PreflightSeverity.INFO,
                    category="CONTAINER",
                    title="Docker CLI Not Installed",
                    message="Docker executable not found on host PATH.",
                    remediation="Install Docker Desktop or Docker engine if containerized workflows are required.",
                    blocking=False,
                )
            )
        except subprocess.TimeoutExpired:
            findings.append(
                PreflightFinding(
                    rule_id="PRE-DOC-TIMEOUT",
                    severity=PreflightSeverity.WARNING,
                    category="CONTAINER",
                    title="Docker Daemon Timeout",
                    message="Timed out waiting for 'docker info' response after 4.0 seconds.",
                    remediation="Check Docker daemon responsiveness.",
                    blocking=False,
                )
            )

    def _probe_http_health(
        self,
        url: str,
        findings: list[PreflightFinding],
        evidence: list[str],
        remediations: list[str],
    ) -> None:
        try:
            import httpx

            with httpx.Client(timeout=5.0, verify=True) as client:
                resp = client.get(url)
                if 200 <= resp.status_code < 400:
                    evidence.append(f"HTTP health probe to {url} returned status {resp.status_code}.")
                else:
                    findings.append(
                        PreflightFinding(
                            rule_id="PRE-HTTP-UNHEALTHY",
                            severity=PreflightSeverity.ERROR,
                            category="HEALTH",
                            title="HTTP Health Endpoint Returned Error",
                            message=f"Endpoint '{url}' responded with non-healthy status code {resp.status_code}.",
                            remediation="Inspect application logs to resolve health check failure.",
                            blocking=True,
                        )
                    )
                    remediations.append(f"Ensure service at {url} returns 200 OK.")
        except Exception as e:
            sanitized_err = redact_secrets_in_text(str(e))
            findings.append(
                PreflightFinding(
                    rule_id="PRE-HTTP-FAILED",
                    severity=PreflightSeverity.ERROR,
                    category="HEALTH",
                    title="HTTP Health Probe Connection Failed",
                    message=f"Failed to connect to health endpoint '{url}': {sanitized_err}",
                    remediation="Verify target service is running and accessible.",
                    blocking=True,
                )
            )
            remediations.append(f"Verify endpoint reachability: {url}")
