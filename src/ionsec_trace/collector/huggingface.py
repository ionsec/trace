"""
HuggingFace Cache forensic artifact collector for TRACE.

Collects: cached model metadata, refs, snapshots, auth tokens,
download timestamps, and dataset/module cache information.
"""

from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class HuggingFaceCacheCollector(BaseCollector):
    PLATFORM_NAME = "huggingface"
    PLATFORM_CATEGORY = PlatformCategory.CLOUD
    PROCESS_NAMES = ["huggingface-cli", "transformers", "huggingface"]
    SERVICE_PORTS = []

    LINUX_PATHS = [
        "~/.cache/huggingface",
        "~/.huggingface",
    ]
    MACOS_PATHS = [
        "~/.cache/huggingface",
        "~/.huggingface",
    ]
    WINDOWS_PATHS = [
        "%USERPROFILE%\\.cache\\huggingface",
        "%USERPROFILE%\\.huggingface",
    ]

    def discover(self) -> bool:
        """Detect if HuggingFace cache is present on the system."""
        for home in self.get_user_home_dirs():
            hf_cache = home / ".cache" / "huggingface"
            if hf_cache.exists():
                return True

            # Alternative config location
            hf_dir = home / ".huggingface"
            if hf_dir.exists():
                return True

        # Check for huggingface-cli binary
        import shutil
        return bool(shutil.which("huggingface-cli"))

    def collect(self) -> list[CollectedFile]:
        """Collect all HuggingFace cache forensic artifacts."""
        collected = []

        for home in self.get_user_home_dirs():
            hf_cache = home / ".cache" / "huggingface"
            if hf_cache.exists():
                collected.extend(self._collect_cache_dir(hf_cache))

            hf_dir = home / ".huggingface"
            if hf_dir.exists():
                collected.extend(self._collect_hf_dir(hf_dir))

        return collected

    def _collect_hf_dir(self, hf_dir: Path) -> list[CollectedFile]:
        """Collect artifacts from ~/.huggingface directory."""
        collected = []

        # Auth token file (legacy location)
        token_path = hf_dir / "token"
        if token_path.exists():
            cf = CollectedFile(
                original_path=str(token_path),
                source_os=self.detect_os(),
                platform=self.PLATFORM_NAME,
                artifact_type="auth",
                size_bytes=token_path.stat().st_size,
                sha256=self.calculate_hash(str(token_path)),
                collected_at=self.timestamp(),
            )
            collected.append(cf)
            self.collected_files.append(cf)

        # Config file
        for config_name in ["config.json", "default_config.json"]:
            config_path = hf_dir / config_name
            if config_path.exists():
                cf = CollectedFile(
                    original_path=str(config_path),
                    source_os=self.detect_os(),
                    platform=self.PLATFORM_NAME,
                    artifact_type="config",
                    size_bytes=config_path.stat().st_size,
                    sha256=self.calculate_hash(str(config_path)),
                    collected_at=self.timestamp(),
                )
                collected.append(cf)
                self.collected_files.append(cf)

        return collected

    def _collect_cache_dir(self, cache_dir: Path) -> list[CollectedFile]:
        """Collect artifacts from ~/.cache/huggingface directory."""
        collected = []

        # Auth token (primary location)
        token_path = cache_dir / "token"
        if token_path.exists():
            cf = CollectedFile(
                original_path=str(token_path),
                source_os=self.detect_os(),
                platform=self.PLATFORM_NAME,
                artifact_type="auth",
                size_bytes=token_path.stat().st_size,
                sha256=self.calculate_hash(str(token_path)),
                collected_at=self.timestamp(),
            )
            collected.append(cf)
            self.collected_files.append(cf)

        # Hub cache — model metadata, refs, snapshots
        hub_dir = cache_dir / "hub"
        if hub_dir.exists():
            for model_dir in hub_dir.iterdir():
                if not model_dir.is_dir():
                    continue

                if model_dir.name.startswith("models--"):
                    # Model metadata file
                    metadata_path = model_dir / "metadata"
                    if metadata_path.exists():
                        cf = CollectedFile(
                            original_path=str(metadata_path),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="model_metadata",
                            size_bytes=metadata_path.stat().st_size,
                            sha256=self.calculate_hash(str(metadata_path)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

                    # Model refs (branches/tags)
                    refs_dir = model_dir / "refs"
                    if refs_dir.exists():
                        for ref_file in refs_dir.rglob("*"):
                            if ref_file.is_file():
                                cf = CollectedFile(
                                    original_path=str(ref_file),
                                    source_os=self.detect_os(),
                                    platform=self.PLATFORM_NAME,
                                    artifact_type="model_ref",
                                    size_bytes=ref_file.stat().st_size,
                                    sha256=self.calculate_hash(str(ref_file)),
                                    collected_at=self.timestamp(),
                                )
                                collected.append(cf)
                                self.collected_files.append(cf)

                    # Model snapshots
                    snapshots_dir = model_dir / "snapshots"
                    if snapshots_dir.exists():
                        for snapshot_dir in snapshots_dir.iterdir():
                            if snapshot_dir.is_dir():
                                # Model config
                                config_path = snapshot_dir / "config.json"
                                if config_path.exists():
                                    cf = CollectedFile(
                                        original_path=str(config_path),
                                        source_os=self.detect_os(),
                                        platform=self.PLATFORM_NAME,
                                        artifact_type="model_config",
                                        size_bytes=config_path.stat().st_size,
                                        sha256=self.calculate_hash(str(config_path)),
                                        collected_at=self.timestamp(),
                                    )
                                    collected.append(cf)
                                    self.collected_files.append(cf)

                                # Tokenizer config
                                tokenizer_config = snapshot_dir / "tokenizer_config.json"
                                if tokenizer_config.exists():
                                    cf = CollectedFile(
                                        original_path=str(tokenizer_config),
                                        source_os=self.detect_os(),
                                        platform=self.PLATFORM_NAME,
                                        artifact_type="tokenizer_config",
                                        size_bytes=tokenizer_config.stat().st_size,
                                        sha256=self.calculate_hash(str(tokenizer_config)),
                                        collected_at=self.timestamp(),
                                    )
                                    collected.append(cf)
                                    self.collected_files.append(cf)

                                # Model card
                                model_card = snapshot_dir / "README.md"
                                if model_card.exists():
                                    cf = CollectedFile(
                                        original_path=str(model_card),
                                        source_os=self.detect_os(),
                                        platform=self.PLATFORM_NAME,
                                        artifact_type="model_card",
                                        size_bytes=model_card.stat().st_size,
                                        sha256=self.calculate_hash(str(model_card)),
                                        collected_at=self.timestamp(),
                                    )
                                    collected.append(cf)
                                    self.collected_files.append(cf)

                                # .huggingface download metadata
                                for hf_file in snapshot_dir.glob(".huggingface"):
                                    if hf_file.is_file():
                                        cf = CollectedFile(
                                            original_path=str(hf_file),
                                            source_os=self.detect_os(),
                                            platform=self.PLATFORM_NAME,
                                            artifact_type="download_metadata",
                                            size_bytes=hf_file.stat().st_size,
                                            sha256=self.calculate_hash(str(hf_file)),
                                            collected_at=self.timestamp(),
                                        )
                                        collected.append(cf)
                                        self.collected_files.append(cf)

                                # In deep mode, collect all model files
                                if self.deep:
                                    for model_file in snapshot_dir.rglob("*"):
                                        if model_file.is_file() and model_file.name not in [
                                            "config.json", "tokenizer_config.json", "README.md",
                                        ] and not model_file.name.startswith(".huggingface"):
                                            cf = CollectedFile(
                                                original_path=str(model_file),
                                                source_os=self.detect_os(),
                                                platform=self.PLATFORM_NAME,
                                                artifact_type="model_file",
                                                size_bytes=model_file.stat().st_size,
                                                sha256=self.calculate_hash(str(model_file)),
                                                collected_at=self.timestamp(),
                                            )
                                            collected.append(cf)
                                            self.collected_files.append(cf)

                        # Blobs directory — only collect in deep mode (large binary files)
                        if self.deep:
                            blobs_dir = model_dir / "blobs"
                            if blobs_dir.exists():
                                for blob_file in blobs_dir.iterdir():
                                    if blob_file.is_file() and blob_file.stat().st_size < 100 * 1024 * 1024:  # skip files > 100MB
                                        cf = CollectedFile(
                                            original_path=str(blob_file),
                                            source_os=self.detect_os(),
                                            platform=self.PLATFORM_NAME,
                                            artifact_type="model_blob",
                                            size_bytes=blob_file.stat().st_size,
                                            sha256=self.calculate_hash(str(blob_file)),
                                            collected_at=self.timestamp(),
                                        )
                                        collected.append(cf)
                                        self.collected_files.append(cf)

                # Dataset directories
                elif model_dir.name.startswith("datasets--"):
                    # Dataset metadata
                    metadata_path = model_dir / "metadata"
                    if metadata_path.exists():
                        cf = CollectedFile(
                            original_path=str(metadata_path),
                            source_os=self.detect_os(),
                            platform=self.PLATFORM_NAME,
                            artifact_type="dataset_metadata",
                            size_bytes=metadata_path.stat().st_size,
                            sha256=self.calculate_hash(str(metadata_path)),
                            collected_at=self.timestamp(),
                        )
                        collected.append(cf)
                        self.collected_files.append(cf)

                    # Dataset refs
                    refs_dir = model_dir / "refs"
                    if refs_dir.exists():
                        for ref_file in refs_dir.rglob("*"):
                            if ref_file.is_file():
                                cf = CollectedFile(
                                    original_path=str(ref_file),
                                    source_os=self.detect_os(),
                                    platform=self.PLATFORM_NAME,
                                    artifact_type="dataset_ref",
                                    size_bytes=ref_file.stat().st_size,
                                    sha256=self.calculate_hash(str(ref_file)),
                                    collected_at=self.timestamp(),
                                )
                                collected.append(cf)
                                self.collected_files.append(cf)

        # Modules cache
        modules_dir = cache_dir / "modules"
        if modules_dir.exists():
            for module_file in modules_dir.rglob("*"):
                if module_file.is_file():
                    cf = CollectedFile(
                        original_path=str(module_file),
                        source_os=self.detect_os(),
                        platform=self.PLATFORM_NAME,
                        artifact_type="module_cache",
                        size_bytes=module_file.stat().st_size,
                        sha256=self.calculate_hash(str(module_file)),
                        collected_at=self.timestamp(),
                    )
                    collected.append(cf)
                    self.collected_files.append(cf)

        # Version file
        version_path = cache_dir / "version.txt"
        if version_path.exists():
            cf = CollectedFile(
                original_path=str(version_path),
                source_os=self.detect_os(),
                platform=self.PLATFORM_NAME,
                artifact_type="version",
                size_bytes=version_path.stat().st_size,
                sha256=self.calculate_hash(str(version_path)),
                collected_at=self.timestamp(),
            )
            collected.append(cf)
            self.collected_files.append(cf)

        return collected

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected HuggingFace artifacts."""
        artifacts = []

        for cf in self.collected_files:
            if cf.artifact_type == "auth":
                # Token file — critical finding
                content = self.safe_read_file(cf.original_path)
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="auth",
                    severity=Severity.CRITICAL,
                    data={
                        "note": "HuggingFace auth token file found (contents redacted)",
                        "filename": Path(cf.original_path).name,
                        "token_present": bool(content and content.strip()),
                    },
                    source_file=cf.original_path,
                    iocs=[{"type": "hf_auth_token", "detail": "HuggingFace auth token file detected", "path": cf.original_path}],
                    mitre_atlas=["AML.T0055"],
                ))

            elif cf.artifact_type == "config":
                data = self.safe_read_json(cf.original_path)
                if data:
                    iocs = []
                    if isinstance(data, dict) and "token" in str(data).lower():
                        iocs.append({"type": "token_in_config", "detail": "Token reference in HuggingFace config"})
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="config",
                        severity=Severity.HIGH if iocs else Severity.INFO,
                        data=data,
                        source_file=cf.original_path,
                        iocs=iocs,
                    ))

            elif cf.artifact_type == "model_metadata":
                # Parse model name from directory structure
                parent_name = Path(cf.original_path).parent.name
                # models--<org>--<name> format
                model_id = parent_name.replace("models--", "").replace("--", "/") if parent_name.startswith("models--") else parent_name

                content = self.safe_read_file(cf.original_path)
                data = {"model_id": model_id}
                if content:
                    json_data = self.safe_read_json(cf.original_path)
                    if json_data:
                        data["metadata"] = json_data

                # Extract download timestamp from file mtime
                try:
                    mtime = Path(cf.original_path).stat().st_mtime
                    from datetime import datetime, timezone
                    data["last_modified"] = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
                except Exception:
                    pass

                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="model_metadata",
                    severity=Severity.INFO,
                    data=data,
                    source_file=cf.original_path,
                ))

            elif cf.artifact_type == "model_ref":
                content = self.safe_read_file(cf.original_path)
                if content:
                    parent_name = Path(cf.original_path).parent.parent.name
                    model_id = parent_name.replace("models--", "").replace("--", "/") if parent_name.startswith("models--") else parent_name
                    ref_name = Path(cf.original_path).name

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="model_ref",
                        severity=Severity.INFO,
                        data={
                            "model_id": model_id,
                            "ref_name": ref_name,
                            "commit_hash": content.strip(),
                        },
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "model_config":
                data = self.safe_read_json(cf.original_path)
                if data:
                    parent_name = Path(cf.original_path).parent.parent.parent.name
                    model_id = parent_name.replace("models--", "").replace("--", "/") if parent_name.startswith("models--") else parent_name

                    parsed_data = {"model_id": model_id}
                    for key in ["model_type", "architectures", "torch_dtype", "vocab_size", "_name_or_path"]:
                        if key in data:
                            parsed_data[key] = data[key]

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="model_config",
                        severity=Severity.INFO,
                        data=parsed_data,
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "model_card":
                content = self.safe_read_file(cf.original_path, max_bytes=50 * 1024)
                if content:
                    parent_name = Path(cf.original_path).parent.parent.parent.name
                    model_id = parent_name.replace("models--", "").replace("--", "/") if parent_name.startswith("models--") else parent_name

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="model_card",
                        severity=Severity.INFO,
                        data={
                            "model_id": model_id,
                            "content_preview": content[:3000],
                            "full_length": len(content),
                        },
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "tokenizer_config":
                data = self.safe_read_json(cf.original_path)
                if data:
                    parent_name = Path(cf.original_path).parent.parent.parent.name
                    model_id = parent_name.replace("models--", "").replace("--", "/") if parent_name.startswith("models--") else parent_name

                    parsed_data = {"model_id": model_id}
                    for key in ["tokenizer_class", "model_type", "auto_map", "use_fast"]:
                        if key in data:
                            parsed_data[key] = data[key]

                    iocs = []
                    if "auto_map" in data:
                        iocs.append({
                            "type": "custom_tokenizer",
                            "detail": "Custom tokenizer code referenced (potential code execution vector)",
                            "model_id": model_id,
                        })

                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="tokenizer_config",
                        severity=Severity.HIGH if iocs else Severity.INFO,
                        data=parsed_data,
                        source_file=cf.original_path,
                        iocs=iocs,
                        mitre_atlas=["AML.T0010"] if iocs else [],
                    ))

            elif cf.artifact_type == "download_metadata":
                content = self.safe_read_file(cf.original_path)
                if content:
                    json_data = self.safe_read_json(cf.original_path)
                    if json_data:
                        artifacts.append(ParsedArtifact(
                            platform=self.PLATFORM_NAME,
                            artifact_type="download_metadata",
                            severity=Severity.INFO,
                            data=json_data,
                            source_file=cf.original_path,
                        ))

            elif cf.artifact_type == "dataset_metadata":
                parent_name = Path(cf.original_path).parent.name
                dataset_id = parent_name.replace("datasets--", "").replace("--", "/") if parent_name.startswith("datasets--") else parent_name

                content = self.safe_read_file(cf.original_path)
                data = {"dataset_id": dataset_id}
                if content:
                    json_data = self.safe_read_json(cf.original_path)
                    if json_data:
                        data["metadata"] = json_data

                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type="dataset_metadata",
                    severity=Severity.INFO,
                    data=data,
                    source_file=cf.original_path,
                ))

            elif cf.artifact_type == "module_cache":
                data = self.safe_read_json(cf.original_path)
                if data:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="module_cache",
                        severity=Severity.INFO,
                        data=data,
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "version":
                content = self.safe_read_file(cf.original_path)
                if content:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type="version",
                        severity=Severity.INFO,
                        data={"version": content.strip()},
                        source_file=cf.original_path,
                    ))

        return artifacts
