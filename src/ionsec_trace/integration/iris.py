"""
TRACE → DFIR-IRIS connector.

Pushes a collected evidence directory (CHAIN_OF_CUSTODY.json +
analysis_results.json) into an IRIS case via the official
``dfir-iris-client`` Python client.

What gets pushed
----------------
* A new IRIS case (or an existing one) carrying a risk-oriented summary.
* A ``TRACE Findings`` notes directory with one note per finding.
* Extracted IOCs mapped onto IRIS IOC types (domain, ip-any, md5, sha256, ...).
* Timeline events (from ``analysis_results.json``) as IRIS timeline events.
* Priority actions as IRIS tasks.
* A host asset for the source machine, with IOCs linked to it.
* Collected artifact files uploaded to the case Datastore.

The connector is defensive: each step is isolated so a failure in one
(e.g. an IOC type mismatch) is reported without aborting the whole push.

Dependencies
------------
``dfir-iris-client`` is an optional extra (``pip install ionsec-trace[iris]``).
It is imported lazily so the core tool never requires it.

References
----------
* https://docs.dfir-iris.org/latest/operations/api/
* https://client.docs.dfir-iris.org/
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ionsec_trace.collector.base import Severity

# ---------------------------------------------------------------------------
# IRIS API constants (names are resolved to IDs server-side by the client)
# ---------------------------------------------------------------------------

IRIS_AGENT = "trace"

# Default analysis status applied to pushed assets ("Unspecified" ships with IRIS)
DEFAULT_ANALYSIS_STATUS = "Unspecified"

# TRACE IOC type -> IRIS IOC type name. IRIS types come from its authoritative
# IOC type catalog (domain, url, ip-any, md5, sha1, sha256, email, file-path, ...).
_IOC_TYPE_MAP = {
    "ip": "ip-any",
    "ipv4": "ip-any",
    "url": "url",
    "domain": "domain",
    "hostname": "hostname",
    "email": "email",
    "filepath": "file-path",
    "path": "file-path",
    "hash_md5": "md5",
    "hash_sha1": "sha1",
    "hash_sha256": "sha256",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha512": "sha512",
    "api_key": "other",
    "command": "text",
    "exfil_pattern": "text",
    "jailbreak": "text",
    "credential": "other",
}

# source_os -> IRIS asset type name
_ASSET_TYPE_MAP = {
    "linux": "Linux - Server",
    "darwin": "Mac - Computer",
    "macos": "Mac - Computer",
    "windows": "Windows - Computer",
    "win32": "Windows - Computer",
}

_FINDINGS_NOTE_DIR = "TRACE Findings"
_EVIDENCE_FOLDER = "TRACE Evidence"


def _lazy_import_client():
    """Import the official IRIS client (lazy, so it is optional)."""
    try:
        from dfir_iris_client.case import Case
        from dfir_iris_client.session import ClientSession
        return ClientSession, Case
    except ImportError as exc:  # pragma: no cover - depends on optional dep
        raise ImportError(
            "The DFIR-IRIS client is not installed. Install it with "
            "`pip install dfir-iris-client` (or `pip install ionsec-trace[iris]`)."
        ) from exc


class IrisIntegration:
    """Push TRACE evidence into a DFIR-IRIS case.

    Args:
        host: IRIS server base URL, e.g. ``https://iris.example.com``.
        apikey: IRIS user API key (Bearer token).
        ssl_verify: Verify the server TLS certificate.
        timeout: Request timeout in seconds.
        agent: User-agent reported to IRIS.
    """

    def __init__(
        self,
        host: str,
        apikey: str,
        ssl_verify: bool = True,
        timeout: int = 120,
        agent: str = IRIS_AGENT,
    ) -> None:
        self.host = host.rstrip("/")
        self.apikey = apikey
        self.ssl_verify = ssl_verify
        self.timeout = timeout
        self.agent = agent
        self._session = None
        self._case = None

    # ------------------------------------------------------------------ setup

    def _get_session(self):
        """Build and cache the IRIS client session (verifies key + API compat)."""
        if self._session is None:
            ClientSession, _ = _lazy_import_client()
            self._session = ClientSession(
                apikey=self.apikey,
                host=self.host,
                agent=self.agent,
                ssl_verify=self.ssl_verify,
                timeout=self.timeout,
            )
        return self._session

    def _get_case(self, case_id: int | None = None):
        """Build a Case handle, optionally bound to an existing case id."""
        _, Case = _lazy_import_client()
        case = Case(session=self._get_session(), case_id=case_id)
        return case

    def check(self) -> dict:
        """Verify connectivity + credentials. Returns a status dict.

        Raises:
            Exception: If the session cannot be established (bad key/host/API).
        """
        # Establish the session (verifies API key + version compatibility).
        self._get_session()
        case = self._get_case()
        cases_resp = case.list_cases()
        if cases_resp.is_error():
            raise RuntimeError(f"IRIS returned an error: {cases_resp.get_msg()}")
        data = cases_resp.get_data() or []
        return {
            "ok": True,
            "host": self.host,
            "agent": self.agent,
            "case_count": len(data) if isinstance(data, list) else 0,
        }

    # ------------------------------------------------------------- data load

    def _load_evidence(self, evidence_dir: str) -> dict:
        """Load custody + analysis JSON into a single data bag."""
        evidence_path = Path(evidence_dir)
        bag: dict[str, Any] = {
            "evidence_dir": evidence_path,
            "custody": {},
            "analysis": {},
        }

        custody_path = evidence_path / "CHAIN_OF_CUSTODY.json"
        if custody_path.exists():
            with open(custody_path, encoding="utf-8") as fh:
                bag["custody"] = json.load(fh)

        analysis_path = evidence_path / "analysis_results.json"
        if analysis_path.exists():
            with open(analysis_path, encoding="utf-8") as fh:
                bag["analysis"] = json.load(fh)

        return bag

    def _get_findings(self, bag: dict) -> list[dict]:
        findings = bag["custody"].get("findings", []) or []
        return [f for f in findings if isinstance(f, dict)]

    def _get_iocs(self, bag: dict) -> list[dict]:
        # Prefer analysis_results.json, fall back to custody.
        iocs = bag["analysis"].get("iocs") or bag["custody"].get("iocs", []) or []
        return [i for i in iocs if isinstance(i, dict)]

    def _get_timeline(self, bag: dict) -> list[dict]:
        timeline = bag["analysis"].get("timeline", []) or []
        return [e for e in timeline if isinstance(e, dict)]

    def _get_priority_actions(self, bag: dict) -> list[dict]:
        actions = bag["analysis"].get("priority_actions", []) or []
        return [a for a in actions if isinstance(a, dict)]

    def _get_risk(self, bag: dict) -> dict:
        risk = bag["analysis"].get("risk_scores") or bag["analysis"].get("enhanced_risk")
        if isinstance(risk, dict):
            return risk
        return {}

    def _source_host(self, bag: dict) -> str | None:
        return (
            bag["custody"].get("hostname")
            or bag["custody"].get("source_host")
            or bag["analysis"].get("hostname")
            or os.uname().nodename  # type: ignore[attr-defined]
        )

    # ------------------------------------------------------------ IRIS steps

    def _resolve_or_create_case(
        self,
        case: Any,
        bag: dict,
        case_name: str,
        customer: str,
        classification: str,
        soc_id: str,
        create_customer: bool,
    ) -> tuple[bool, int | None]:
        """Create a case (or reuse the bound one). Returns (created, case_id)."""
        if case._cid:  # existing case provided
            return False, int(case._cid)

        description = self._build_case_description(bag)
        resp = case.add_case(
            case_name=case_name,
            case_description=description,
            case_customer=customer,
            case_classification=classification,
            soc_id=soc_id,
            create_customer=create_customer,
        )
        if resp.is_error():
            raise RuntimeError(f"Failed to create IRIS case: {resp.get_msg()}")
        data = resp.get_data() or {}
        raw_case_id = data.get("case_id")
        if raw_case_id is None:
            raise RuntimeError("IRIS created a case but returned no case_id")
        case_id = int(raw_case_id)
        case.set_cid(case_id)
        return True, case_id

    def _build_case_description(self, bag: dict) -> str:
        """Compose a short markdown summary of the evidence."""
        findings = self._get_findings(bag)
        iocs = self._get_iocs(bag)
        risk = self._get_risk(bag)

        sev = Severity.CRITICAL
        try:
            score = int(risk.get("score") or 0)
            if score >= 90:
                sev = Severity.CRITICAL
            elif score >= 70:
                sev = Severity.HIGH
            elif score >= 40:
                sev = Severity.MEDIUM
        except (TypeError, ValueError):
            pass

        lines = [
            "**TRACE — AI & Compute Evidence Collection**",
            "",
            (
                f"- Findings: **{len(findings)}**  "
                f"(Critical: {self._count_sev(findings, 'critical')}, "
                f"High: {self._count_sev(findings, 'high')}, "
                f"Medium: {self._count_sev(findings, 'medium')})"
            ),
            f"- IOCs: **{len(iocs)}**",
            (
                f"- Risk score: **{risk.get('score', 'n/a')}/100** "
                f"(severity: {risk.get('severity', sev.value)})"
            ),
            f"- Source host: **{self._source_host(bag)}**",
        ]
        return "\n".join(lines)

    @staticmethod
    def _count_sev(findings: list[dict], sev: str) -> int:
        return sum(1 for f in findings if str(f.get("severity", "")).lower() == sev)

    def _push_findings_notes(self, case: Any, bag: dict) -> list[dict]:
        """Create a 'TRACE Findings' notes directory with one note per finding."""
        findings = self._get_findings(bag)
        if not findings:
            return []

        # Create a root-level notes directory.
        dir_resp = case.add_notes_directory(directory_name=_FINDINGS_NOTE_DIR, parent_directory_id=0)
        if dir_resp.is_error():
            return [{"ok": False, "item": "notes-directory", "error": dir_resp.get_msg()}]

        dir_data = dir_resp.get_data() or {}
        # add_notes_directory returns an object with "id"; fall back for safety.
        directory_id = dir_data.get("id") or dir_data.get("directory_id") or dir_data.get("group_id")

        results = []
        for f in findings:
            title = f.get("title", "TRACE Finding")
            body = self._finding_to_markdown(f)
            note_resp = case.add_note(
                note_title=title,
                note_content=body,
                directory_id=directory_id,
                cid=case._cid,
            )
            results.append(
                {"ok": note_resp.is_success(), "item": f"finding:{title}", "error": None}
                if note_resp.is_success()
                else {"ok": False, "item": f"finding:{title}", "error": note_resp.get_msg()}
            )
        return results

    @staticmethod
    def _finding_to_markdown(f: dict) -> str:
        parts = [
            (
                f"**Severity:** `{f.get('severity', 'info')}`  ·  "
                f"**Platform:** `{f.get('platform', 'unknown')}`  ·  "
                f"**Artifact:** `{f.get('artifact_type', 'unknown')}`"
            ),
            "",
            f.get("description", ""),
        ]
        evidence = f.get("evidence") or []
        if evidence:
            parts += ["", "**Evidence:**"]
            parts += [f"- `{e}`" for e in evidence]
        if f.get("mitre_atlas"):
            parts += ["", f"**MITRE ATLAS:** {', '.join(f['mitre_atlas'])}"]
        if f.get("recommendation"):
            parts += ["", f"**Recommendation:** {f['recommendation']}"]
        return "\n".join(parts)

    def _push_iocs(self, case: Any, bag: dict) -> list[dict]:
        """Add extracted IOCs to the case, mapped to IRIS IOC types."""
        iocs = self._get_iocs(bag)
        if not iocs:
            return []

        results = []
        for ioc in iocs:
            value = str(ioc.get("value") or ioc.get("ioc") or "").strip()
            if not value:
                continue
            ioc_type = str(ioc.get("ioc_type") or ioc.get("type") or "other").lower()
            iris_type = _IOC_TYPE_MAP.get(ioc_type, "other")
            description = ioc.get("context") or f"Collected by TRACE ({ioc.get('platform', 'unknown')})"
            tags = [f"trace:{ioc.get('platform', 'unknown')}"]
            resp = case.add_ioc(
                value=value,
                ioc_type=iris_type,
                description=description,
                ioc_tlp="amber",
                ioc_tags=tags,
                cid=case._cid,
            )
            results.append(
                {"ok": resp.is_success(), "item": f"ioc:{value[:40]}", "error": None}
                if resp.is_success()
                else {"ok": False, "item": f"ioc:{value[:40]}", "error": resp.get_msg()}
            )
        return results

    def _push_timeline(self, case: Any, bag: dict) -> list[dict]:
        """Add timeline events as IRIS case events."""
        events = self._get_timeline(bag)
        if not events:
            return []

        results = []
        for event in events:
            title = str(event.get("description") or event.get("platform") or "TRACE event")
            content = self._event_to_markdown(event)
            raw = event.get("content_preview") or event.get("source_path") or ""
            ts_str = event.get("timestamp")
            try:
                dt = datetime.fromisoformat(str(ts_str))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                dt = datetime.now(timezone.utc)

            tags = [f"trace:{event.get('platform', 'unknown')}"]
            resp = case.add_event(
                title=title[:255],
                date_time=dt,
                content=content,
                raw_content=raw,
                source="TRACE",
                tags=tags,
                cid=case._cid,
            )
            results.append(
                {"ok": resp.is_success(), "item": f"event:{title[:40]}", "error": None}
                if resp.is_success()
                else {"ok": False, "item": f"event:{title[:40]}", "error": resp.get_msg()}
            )
        return results

    @staticmethod
    def _event_to_markdown(event: dict) -> str:
        parts = [
            (
                f"**Platform:** `{event.get('platform', 'unknown')}`  ·  "
                f"**Severity:** `{event.get('severity', 'info')}`"
            ),
        ]
        if event.get("source_path"):
            parts.append(f"**Source:** `{event['source_path']}`")
        return "\n".join(parts)

    def _push_priority_tasks(self, case: Any, bag: dict) -> list[dict]:
        """Add priority actions as IRIS tasks."""
        actions = self._get_priority_actions(bag)
        if not actions:
            return []

        results = []
        for action in actions:
            title = str(action.get("action") or "TRACE priority action")[:255]
            urgency = str(action.get("urgency") or "MEDIUM").upper()
            evidence = action.get("evidence") or []
            description = "\n".join(
                [f"**Urgency:** {urgency}"] + ([f"- `{e}`" for e in evidence] if evidence else [])
            )
            resp = case.add_task(
                title=title,
                status="Open",
                assignees=[],
                description=description,
                tags=["trace"],
                cid=case._cid,
            )
            results.append(
                {"ok": resp.is_success(), "item": f"task:{title[:40]}", "error": None}
                if resp.is_success()
                else {"ok": False, "item": f"task:{title[:40]}", "error": resp.get_msg()}
            )
        return results

    def _push_host_asset(self, case: Any, bag: dict) -> dict | None:
        """Register the source host as an asset so IOCs/events can link to it."""
        host = self._source_host(bag)
        if not host:
            return None
        source_os = str(bag["custody"].get("source_os") or "linux").lower()
        asset_type = _ASSET_TYPE_MAP.get(source_os, "Linux - Server")
        resp = case.add_asset(
            name=host,
            asset_type=asset_type,
            analysis_status=DEFAULT_ANALYSIS_STATUS,
            description="AI/compute evidence source host (TRACE)",
            tags=["trace"],
            cid=case._cid,
        )
        if resp.is_error():
            return {"ok": False, "item": f"asset:{host}", "error": resp.get_msg()}
        data = resp.get_data() or {}
        asset_id = data.get("asset_id")
        return {"ok": True, "item": f"asset:{host}", "asset_id": asset_id, "error": None}

    def _push_evidence_files(self, case: Any, bag: dict) -> list[dict]:
        """Upload collected artifact files to the case Datastore."""
        custody = bag["custody"]
        files = (
            custody.get("files")
            or custody.get("collected_files")
            or custody.get("artifacts")
            or []
        )
        if not files:
            return []

        # Resolve datastore root folder id (key like "d-1").
        tree_resp = case.list_ds_tree()
        if tree_resp.is_error():
            return [{"ok": False, "item": "datastore-root", "error": tree_resp.get_msg()}]
        tree = tree_resp.get_data() or {}
        root_id = None
        for key, node in (tree.items() if isinstance(tree, dict) else []):
            if isinstance(node, dict) and node.get("is_root"):
                root_id = int(str(key).replace("d-", ""))
                break
        if root_id is None:
            return [{"ok": False, "item": "datastore-root", "error": "No root folder found"}]

        results = []
        for entry in files:
            if not isinstance(entry, dict):
                continue
            path = entry.get("original_path")
            if not path:
                continue
            p = Path(path)
            if not p.exists():
                # Some collectors write a local copy under evidence_dir; try that.
                local = bag["evidence_dir"] / p.name
                p = local if local.exists() else p
            if not p.exists():
                results.append({"ok": False, "item": f"evidence:{p.name}", "error": "file missing on disk"})
                continue

            description = (
                f"Platform: {entry.get('platform', 'unknown')} | "
                f"Artifact: {entry.get('artifact_type', 'unknown')}"
            )
            try:
                with open(p, "rb") as fh:
                    resp = case.add_ds_file(
                        parent_id=root_id,
                        file_stream=fh,
                        filename=p.name,
                        file_description=description,
                        file_is_ioc=False,
                        file_is_evidence=True,
                        cid=case._cid,
                    )
            except OSError as exc:
                results.append({"ok": False, "item": f"evidence:{p.name}", "error": str(exc)})
                continue

            results.append(
                {"ok": resp.is_success(), "item": f"evidence:{p.name}", "error": None}
                if resp.is_success()
                else {"ok": False, "item": f"evidence:{p.name}", "error": resp.get_msg()}
            )
        return results

    # ------------------------------------------------------------- public API

    def push(
        self,
        evidence_dir: str,
        case_name: str = "TRACE — AI Evidence Collection",
        customer: str = "TRACE",
        classification: str = "not-classified",
        soc_id: str = "",
        create_customer: bool = True,
        push_evidence_files: bool = True,
        push_timeline: bool = True,
        case_id: int | None = None,
    ) -> dict:
        """Push an evidence directory into an IRIS case.

        Returns a dict with per-step result lists and an overall summary.
        Raises RuntimeError if the case cannot be created / connected.
        """
        bag = self._load_evidence(evidence_dir)
        case = self._get_case(case_id)

        created, resolved_case_id = self._resolve_or_create_case(
            case, bag, case_name, customer, classification, soc_id, create_customer
        )

        host_asset = self._push_host_asset(case, bag)

        findings_notes = self._push_findings_notes(case, bag)
        iocs = self._push_iocs(case, bag)
        tasks = self._push_priority_tasks(case, bag)
        timeline = self._push_timeline(case, bag) if push_timeline else []
        evidence_files = self._push_evidence_files(case, bag) if push_evidence_files else []

        all_results = findings_notes + iocs + tasks + timeline + evidence_files
        if host_asset:
            all_results.append(host_asset)

        ok_count = sum(1 for r in all_results if r.get("ok"))
        return {
            "ok": True,
            "host": self.host,
            "case_id": resolved_case_id,
            "created_case": created,
            "summary": {
                "findings": len(self._get_findings(bag)),
                "iocs": len(self._get_iocs(bag)),
                "timeline_events": len(self._get_timeline(bag)),
                "priority_actions": len(self._get_priority_actions(bag)),
                "evidence_files_uploaded": sum(
                    1 for r in evidence_files if r.get("ok")
                ),
            },
            "results": all_results,
            "ok_count": ok_count,
            "total_count": len(all_results),
            "errors": [r for r in all_results if not r.get("ok")],
        }


def push_to_iris(
    evidence_dir: str,
    host: str,
    apikey: str,
    case_name: str = "TRACE — AI Evidence Collection",
    customer: str = "TRACE",
    classification: str = "not-classified",
    soc_id: str = "",
    create_customer: bool = True,
    push_evidence_files: bool = True,
    push_timeline: bool = True,
    case_id: int | None = None,
    ssl_verify: bool = True,
    timeout: int = 120,
) -> dict:
    """Convenience wrapper: build an ``IrisIntegration`` and push."""
    integration = IrisIntegration(host=host, apikey=apikey, ssl_verify=ssl_verify, timeout=timeout)
    return integration.push(
        evidence_dir=evidence_dir,
        case_name=case_name,
        customer=customer,
        classification=classification,
        soc_id=soc_id,
        create_customer=create_customer,
        push_evidence_files=push_evidence_files,
        push_timeline=push_timeline,
        case_id=case_id,
    )
