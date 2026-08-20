"""
Base collector abstract class for TRACE platform collectors.
"""

import hashlib
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class PlatformCategory(Enum):
    INFERENCE = "inference"
    AGENT = "agent"
    DEVTOOL = "devtool"
    CLOUD = "cloud"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class CollectedFile:
    """A single collected file with forensic metadata."""
    original_path: str
    source_os: str
    platform: str
    artifact_type: str  # config, conversation, model_manifest, log, credential, etc.
    size_bytes: int
    sha256: str
    collected_at: str  # ISO 8601 UTC
    collector_version: str = "1.0.1"

    def to_dict(self):
        return {
            "original_path": self.original_path,
            "source_os": self.source_os,
            "platform": self.platform,
            "artifact_type": self.artifact_type,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "collected_at": self.collected_at,
            "collector_version": self.collector_version,
        }


@dataclass
class ParsedArtifact:
    """A parsed forensic artifact extracted from collected data."""
    platform: str
    artifact_type: str
    severity: Severity
    data: dict
    source_file: str
    timestamp: str | None = None
    iocs: list = field(default_factory=list)
    mitre_atlas: list = field(default_factory=list)
    risk_score: int = 0


@dataclass
class Finding:
    """A forensic finding with risk assessment.

    ``occurrences`` and ``locations`` exist so a rule tripped many times by one
    artifact is reported as a single finding with every location listed, rather
    than as one near-identical alert per match.
    """
    id: str
    title: str
    description: str
    severity: Severity
    platform: str
    artifact_type: str
    evidence: list
    iocs: list = field(default_factory=list)
    mitre_atlas: list = field(default_factory=list)
    risk_score: int = 0
    recommendation: str = ""
    occurrences: int = 1
    locations: list = field(default_factory=list)


class BaseCollector(ABC):
    """Abstract base class for all platform collectors."""

    PLATFORM_NAME: str = ""
    PLATFORM_CATEGORY: PlatformCategory = PlatformCategory.INFERENCE
    VERSION: str = "1.0.1"

    LINUX_PATHS: list = []
    MACOS_PATHS: list = []
    WINDOWS_PATHS: list = []

    PROCESS_NAMES: list = []
    SERVICE_PORTS: list = []

    def __init__(self, output_dir: str, deep: bool = False):
        self.output_dir = Path(output_dir)
        self.deep = deep
        self.findings: list[Finding] = []
        self.collected_files: list[CollectedFile] = []
        self.parsed_artifacts: list[ParsedArtifact] = []

    @abstractmethod
    def discover(self) -> bool:
        """Detect if this platform is installed/used on the system."""
        ...

    @abstractmethod
    def collect(self) -> list[CollectedFile]:
        """Collect all forensic artifacts for this platform."""
        ...

    @abstractmethod
    def parse(self) -> list[ParsedArtifact]:
        """Parse collected artifacts into structured data."""
        ...

    def calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def timestamp(self) -> str:
        """Return current UTC timestamp in ISO 8601 format."""
        return datetime.now(timezone.utc).isoformat()

    def detect_os(self) -> str:
        """Detect the current operating system."""
        import platform
        system = platform.system().lower()
        if system == "darwin":
            return "macos"
        return system

    def get_user_home_dirs(self) -> list[Path]:
        """Get home directories for all users on the system."""
        homes = []
        system = self.detect_os()
        if system in ("linux", "macos"):
            homes.append(Path.home())
            base = Path("/Users") if system == "macos" else Path("/home")
            if base.exists():
                for entry in base.iterdir():
                    if entry.is_dir() and entry != Path.home():
                        homes.append(entry)
        elif system == "windows":
            homes.append(Path.home())
            for user_dir in Path("C:/Users").iterdir():
                if user_dir.is_dir() and user_dir.name not in (
                    "Public", "Default", "Default User", "All Users"
                ):
                    homes.append(user_dir)
        return homes

    def safe_read_json(self, file_path: str) -> dict | None:
        """Safely read and parse a JSON file."""
        try:
            with open(file_path, encoding="utf-8", errors="replace") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return None

    def safe_read_file(self, file_path: str, max_bytes: int = 10 * 1024 * 1024) -> str | None:
        """Safely read a text file up to max_bytes."""
        try:
            size = os.path.getsize(file_path)
            if size > max_bytes:
                return None
            with open(file_path, encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return None
