"""
Network AI traffic collector for TRACE.

Detects live AI/LLM network activity by correlating running processes with
their outbound connections and classifying the destination domains against
the AI provider catalog. This is the "live network" layer that static
artifact collectors miss — it answers "which process is talking to which
AI provider, right now."

Inspired by the process-to-domain classification approach of tools like
AgentSonar, but implemented as a read-only, forensically-sound collector
that feeds the same chain-of-custody and analysis pipeline as every other
TRACE collector.
"""

import re
import subprocess
from pathlib import Path

from ionsec_trace.collector.ai_providers import classify_domain
from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class NetworkAICollector(BaseCollector):
    PLATFORM_NAME = "network_ai"
    PLATFORM_CATEGORY = PlatformCategory.CLOUD
    PROCESS_NAMES = []
    SERVICE_PORTS = []

    # Known AI service ports (inference endpoints)
    AI_PORTS = [11434, 1234, 8080, 8000, 5000, 4000, 3000, 11435]

    def discover(self) -> bool:
        """Network AI detection is always available (it inspects live traffic)."""
        return True

    def _get_connections(self) -> list[dict]:
        """Gather live network connections with owning process info.

        Returns a list of dicts: {pid, process, domain, port, state}.
        Cross-platform: uses `lsof -i` on macOS/Linux, `netstat` on Windows.
        """
        connections = []
        system = self.detect_os()

        try:
            if system == "windows":
                result = subprocess.run(
                    ["netstat", "-ano"], capture_output=True, text=True, timeout=15
                )
                # netstat -ano gives: proto local foreign state PID
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and parts[0] in ("TCP", "UDP"):
                        foreign = parts[2]
                        pid = parts[-1]
                        domain = self._extract_domain(foreign)
                        if domain:
                            connections.append({
                                "pid": pid,
                                "process": self._pid_to_process(pid),
                                "domain": domain,
                                "port": self._extract_port(foreign),
                                "state": parts[3] if len(parts) > 3 else "",
                            })
            else:
                # macOS / Linux: lsof -i gives process + domain
                result = subprocess.run(
                    ["lsof", "-i", "-n", "-P"], capture_output=True, text=True, timeout=15
                )
                for line in result.stdout.splitlines():
                    # lsof columns: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
                    parts = line.split()
                    if len(parts) >= 9 and parts[0] != "COMMAND":
                        name = parts[8]  # e.g. "host:port->1.2.3.4:443"
                        domain = self._extract_domain(name)
                        if domain:
                            connections.append({
                                "pid": parts[1],
                                "process": parts[0],
                                "domain": domain,
                                "port": self._extract_port(name),
                                "state": "",
                            })
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return connections

    def _extract_domain(self, net_str: str) -> str | None:
        """Extract a hostname/domain from a network string like 'host:port->1.2.3.4:443'."""
        if not net_str:
            return None
        # Strip protocol and arrows
        net_str = net_str.replace("->", " ").replace("TCP ", "").replace("UDP ", "")
        # Take the first token that looks like a hostname (not an IP)
        for token in net_str.split():
            token = token.strip("[]()")
            if ":" in token:
                token = token.split(":")[0]
            # Skip IP addresses and localhost
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", token):
                continue
            if token in ("localhost", "*", "0.0.0.0", "::", "::1"):
                continue
            if re.match(r"^[a-zA-Z0-9.-]+$", token):
                return token
        return None

    def _extract_port(self, net_str: str) -> str:
        """Extract a port from a network string."""
        if not net_str:
            return ""
        m = re.search(r":(\d+)$", net_str.strip())
        return m.group(1) if m else ""

    def _pid_to_process(self, pid: str) -> str:
        """Resolve a PID to a process name (best-effort)."""
        try:
            system = self.detect_os()
            if system == "windows":
                result = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if parts and parts[0].lower() not in ("info:", "image", "="):
                        return parts[0]
            else:
                result = subprocess.run(
                    ["ps", "-p", str(pid), "-o", "comm="], capture_output=True, text=True, timeout=10
                )
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return ""

    def collect(self) -> list[CollectedFile]:
        """Collect live network AI connections as volatile evidence."""
        collected = []
        connections = self._get_connections()

        # Write a snapshot of AI connections to the evidence dir
        if connections:
            ai_conns = [c for c in connections if classify_domain(c["domain"])]
            if ai_conns:
                snapshot_path = Path(self.output_dir) / "network_ai_connections.json"
                import json
                snapshot_path.parent.mkdir(parents=True, exist_ok=True)
                snapshot_path.write_text(
                    json.dumps(ai_conns, indent=2), encoding="utf-8"
                )
                cf = CollectedFile(
                    original_path=str(snapshot_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="network_ai_snapshot",
                    size_bytes=snapshot_path.stat().st_size,
                    sha256=self.calculate_hash(str(snapshot_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

        return collected

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected network AI connections into classified findings."""
        artifacts = []
        connections = self._get_connections()

        # Group by domain
        by_domain: dict[str, list[dict]] = {}
        for conn in connections:
            domain = conn["domain"]
            if classify_domain(domain):
                by_domain.setdefault(domain, []).append(conn)

        for domain, conns in by_domain.items():
            info = classify_domain(domain)
            if not info:
                continue
            processes = sorted({c["process"] for c in conns if c["process"]})
            pids = sorted({c["pid"] for c in conns if c["pid"]})

            iocs = [{
                "type": "ai_network_connection",
                "detail": f"Process {', '.join(processes) or 'unknown'} connected to AI provider {info['provider']} ({domain})",
                "domain": domain,
                "provider": info["provider"],
                "category": info["category"],
                "processes": processes,
                "pids": pids,
            }]

            artifacts.append(ParsedArtifact(
                platform=self.PLATFORM_NAME,
                artifact_type="ai_network_connection",
                severity=Severity.MEDIUM,
                data={
                    "domain": domain,
                    "provider": info["provider"],
                    "category": info["category"],
                    "processes": processes,
                    "pids": pids,
                    "connection_count": len(conns),
                },
                source_file="live_network",
                iocs=iocs,
                mitre_atlas=["AML.T0050"],  # LLM Data Exfiltration
            ))

        return artifacts
