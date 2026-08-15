"""
llama.cpp forensic artifact collector for TRACE.

Collects: running process information, downloaded models from HuggingFace cache,
common binary locations, configuration files, and shell history references.
Since llama.cpp has no standard install path, this collector focuses on
process detection and model discovery.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class LlamaCppCollector(BaseCollector):
    PLATFORM_NAME = "llama_cpp"
    PLATFORM_CATEGORY = PlatformCategory.INFERENCE
    PROCESS_NAMES = ["llama-server", "llama-cli", "llama-cpp", "main", "server"]
    SERVICE_PORTS = [8080]

    LINUX_PATHS = []
    MACOS_PATHS = []
    WINDOWS_PATHS = []

    # Common binary names to search for in PATH
    BINARY_NAMES = ["llama-server", "llama-cli", "llama", "main", "server"]

    # Common build/install directories
    COMMON_INSTALL_DIRS = [
        "~/llama.cpp",
        "~/src/llama.cpp",
        "~/build/llama.cpp",
        "/opt/llama.cpp",
        "/usr/local/bin",
    ]

    def discover(self) -> bool:
        """Detect if llama.cpp is installed or running."""
        # Check for binaries in PATH
        for binary in self.BINARY_NAMES:
            if shutil.which(binary):
                return True

        # Check for running processes
        try:
            result = subprocess.run(
                ["pgrep", "-f", "llama"],
                capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                return True
        except Exception:
            pass

        # Check common install directories
        for home in self.get_user_home_dirs():
            for subdir in ["llama.cpp", "src/llama.cpp", "build/llama.cpp"]:
                if (home / subdir).exists():
                    return True

        if Path("/opt/llama.cpp").exists():
            return True

        # Check HuggingFace cache for GGUF models (likely used with llama.cpp)
        for home in self.get_user_home_dirs():
            hf_cache = home / ".cache" / "huggingface"
            if hf_cache.exists():
                hub_dir = hf_cache / "hub"
                if hub_dir.exists():
                    for model_dir in hub_dir.iterdir():
                        if model_dir.is_dir():
                            for _ in model_dir.rglob("*.gguf"):
                                return True

        return False

    def _find_install_dirs(self) -> list[Path]:
        """Find llama.cpp installation directories."""
        found = []
        seen = set()

        # Check PATH-resolved binaries
        for binary in self.BINARY_NAMES:
            binary_path = shutil.which(binary)
            if binary_path:
                parent = Path(binary_path).parent
                if str(parent) not in seen:
                    seen.add(str(parent))
                    found.append(parent)

        # Check common install directories
        for home in self.get_user_home_dirs():
            for subdir in ["llama.cpp", "src/llama.cpp", "build/llama.cpp"]:
                candidate = home / subdir
                if candidate.exists() and str(candidate) not in seen:
                    seen.add(str(candidate))
                    found.append(candidate)

        for system_path in ["/opt/llama.cpp"]:
            if Path(system_path).exists() and str(system_path) not in seen:
                seen.add(str(system_path))
                found.append(Path(system_path))

        # Check running processes for install paths
        try:
            result = subprocess.run(
                ["pgrep", "-af", "llama"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    parts = line.split()
                    for part in parts:
                        if "llama" in part.lower():
                            p = Path(part)
                            if p.exists():
                                parent = p.parent
                                if str(parent) not in seen:
                                    seen.add(str(parent))
                                    found.append(parent)
        except Exception:
            pass

        return found

    def collect(self) -> list[CollectedFile]:
        """Collect all llama.cpp forensic artifacts."""
        collected = []

        # ── Collect from installation directories ──
        for install_dir in self._find_install_dirs():
            if not install_dir.exists():
                continue

            # Config / make files
            for config_name in ["Makefile", "CMakeLists.txt", "config.mk", ".env"]:
                config_path = install_dir / config_name
                if config_path.exists() and config_path.is_file():
                    cf = CollectedFile(
                        original_path=str(config_path),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="build_config",
                        size_bytes=config_path.stat().st_size,
                        sha256=self.calculate_hash(str(config_path)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

            # YAML / JSON config files at top level
            for pattern in ["*.yaml", "*.yml", "*.json"]:
                for cfg in install_dir.glob(pattern):
                    if cfg.is_file():
                        cf = CollectedFile(
                            original_path=str(cfg),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="config",
                            size_bytes=cfg.stat().st_size,
                            sha256=self.calculate_hash(str(cfg)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

            # Binary executables
            for binary_name in self.BINARY_NAMES:
                bin_path = install_dir / binary_name
                if bin_path.exists() and bin_path.is_file():
                    cf = CollectedFile(
                        original_path=str(bin_path),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="binary",
                        size_bytes=bin_path.stat().st_size,
                        sha256=self.calculate_hash(str(bin_path)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

            # Log files in the install directory
            for log_pattern in ["*.log", "*.txt"]:
                for log_file in install_dir.glob(log_pattern):
                    if log_file.is_file() and log_file.stat().st_size < 10 * 1024 * 1024:
                        cf = CollectedFile(
                            original_path=str(log_file),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="log",
                            size_bytes=log_file.stat().st_size,
                            sha256=self.calculate_hash(str(log_file)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

        # ── Collect GGUF models from HuggingFace cache ──
        for home in self.get_user_home_dirs():
            hf_hub = home / ".cache" / "huggingface" / "hub"
            if not hf_hub.exists():
                continue

            for model_dir in hf_hub.iterdir():
                if not model_dir.is_dir():
                    continue

                for gguf_file in model_dir.rglob("*.gguf"):
                    # Only hash small files in non-deep mode; record existence for large files
                    if self.deep or gguf_file.stat().st_size < 100 * 1024 * 1024:
                        sha = self.calculate_hash(str(gguf_file))
                    else:
                        sha = "skipped_large_file"

                    cf = CollectedFile(
                        original_path=str(gguf_file),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="model_file",
                        size_bytes=gguf_file.stat().st_size,
                        sha256=sha,
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

            # Also check common LLM model directories
            for models_dir_name in ["models", "llm-models", "gguf-models"]:
                models_dir = home / models_dir_name
                if models_dir.exists():
                    for gguf_file in models_dir.rglob("*.gguf"):
                        if self.deep or gguf_file.stat().st_size < 100 * 1024 * 1024:
                            sha = self.calculate_hash(str(gguf_file))
                        else:
                            sha = "skipped_large_file"

                        cf = CollectedFile(
                            original_path=str(gguf_file),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="model_file",
                            size_bytes=gguf_file.stat().st_size,
                            sha256=sha,
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

            # ── Shell history entries referencing llama ──
            history_path = home / ".bash_history"
            if history_path.exists():
                try:
                    content = history_path.read_text(errors="replace")
                    llama_lines = [
                        line for line in content.splitlines()
                        if "llama" in line.lower()
                    ]
                    if llama_lines:
                        cf = CollectedFile(
                            original_path=str(history_path),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="shell_history_reference",
                            size_bytes=history_path.stat().st_size,
                            sha256=self.calculate_hash(str(history_path)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)
                except OSError:
                    pass

        # ── Process information snapshot ──
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                llama_lines = [
                    line for line in result.stdout.splitlines()
                    if "llama" in line.lower() or "gguf" in line.lower()
                ]
                if llama_lines:
                    proc_path = Path(tempfile.mkdtemp()) / "llama_processes.txt"
                    proc_path.write_text("\n".join(llama_lines))
                    cf = CollectedFile(
                        original_path=str(proc_path),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="process_info",
                        size_bytes=proc_path.stat().st_size,
                        sha256=self.calculate_hash(str(proc_path)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)
        except Exception:
            pass

        return collected

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected llama.cpp artifacts."""
        artifacts = []

        for cf in self.collected_files:
            if cf.artifact_type == "build_config":
                content = self.safe_read_file(cf.original_path)
                if content:
                    iocs = []
                    if "API_KEY" in content or "api_key" in content.lower():
                        iocs.append({
                            "type": "api_key_in_build_config",
                            "detail": "API key reference found in llama.cpp build config",
                        })

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="build_config",
                        severity=Severity.HIGH if iocs else Severity.INFO,
                        data={"content_preview": content[:2000], "full_length": len(content)},
                        source_file=cf.original_path,
                        iocs=iocs,
                    ))

            elif cf.artifact_type == "config":
                data = self.safe_read_json(cf.original_path)
                if data:
                    iocs = []
                    config_str = str(data).lower()
                    if "api_key" in config_str or "apikey" in config_str:
                        iocs.append({
                            "type": "api_key_in_config",
                            "detail": "API key found in llama.cpp config",
                        })

                    model_names = []
                    for key in ["model", "model_path", "default_model"]:
                        if key in data:
                            model_names.append(f"{key}={data[key]}")

                    parsed_data = dict(data) if isinstance(data, dict) else {"raw": str(data)}
                    if model_names:
                        parsed_data["_extracted_model_info"] = model_names

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.HIGH if iocs else Severity.INFO,
                        data=parsed_data,
                        source_file=cf.original_path,
                        iocs=iocs,
                    ))

            elif cf.artifact_type == "binary":
                fname = Path(cf.original_path).name
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="binary",
                    severity=Severity.INFO,
                    data={
                        "filename": fname,
                        "size_bytes": cf.size_bytes,
                        "path": cf.original_path,
                    },
                    source_file=cf.original_path,
                ))

            elif cf.artifact_type == "model_file":
                fname = Path(cf.original_path).name
                # Extract model name from HuggingFace hub path format
                model_name = "unknown"
                parts = Path(cf.original_path).parts
                for part in parts:
                    if part.startswith("models--"):
                        model_name = part.replace("models--", "").replace("--", "/")
                        break

                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="model_file",
                    severity=Severity.INFO,
                    data={
                        "filename": fname,
                        "model_name": model_name,
                        "size_bytes": cf.size_bytes,
                        "size_mb": round(cf.size_bytes / (1024 * 1024), 2),
                        "path": cf.original_path,
                    },
                    source_file=cf.original_path,
                ))

            elif cf.artifact_type == "process_info":
                content = self.safe_read_file(cf.original_path)
                if content:
                    processes = []
                    for line in content.splitlines():
                        parts = line.split(None, 10)
                        if len(parts) >= 11:
                            processes.append({
                                "user": parts[0],
                                "pid": parts[1],
                                "command": parts[10] if len(parts) > 10 else "",
                            })

                    # Extract model paths from command lines
                    model_paths = []
                    for proc in processes:
                        cmd = proc.get("command", "")
                        if "--model" in cmd:
                            idx = cmd.find("--model")
                            remainder = cmd[idx + 7:].strip()
                            if remainder.startswith("="):
                                remainder = remainder[1:].strip()
                            model_path = remainder.split()[0] if remainder.split() else ""
                            if model_path:
                                model_paths.append(model_path)

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="process_info",
                        severity=Severity.MEDIUM,
                        data={
                            "running_processes": processes,
                            "model_paths": model_paths,
                        },
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "log":
                content = self.safe_read_file(cf.original_path, max_bytes=2 * 1024 * 1024)
                if content:
                    errors = [line for line in content.splitlines() if "error" in line.lower()]
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="log",
                        severity=Severity.LOW,
                        data={
                            "path": cf.original_path,
                            "line_count": len(content.splitlines()),
                            "error_lines": len(errors),
                            "preview": content[:2000],
                        },
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "shell_history_reference":
                content = self.safe_read_file(cf.original_path)
                if content:
                    llama_lines = [
                        line for line in content.splitlines()
                        if "llama" in line.lower()
                    ]
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="shell_history",
                        severity=Severity.LOW,
                        data={"matching_lines": llama_lines[:50]},
                        source_file=cf.original_path,
                    ))

        return artifacts
