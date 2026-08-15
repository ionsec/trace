"""
Docker AI forensic artifact collector for TRACE.

Collects evidence of AI workloads running in Docker containers and the
Docker AI assistant "Gordon":

  - Gordon (Docker's built-in AI assistant): ~/.docker/gordon/{config,history,threads}
  - Docker-hosted LLM images: ollama, localai, vllm, text-generation-webui,
    llama-cpp, gpt4all, jan, anythingllm, OpenWebUI, LiteLLM, etc.
  - Running AI containers (docker ps) with image/port metadata
  - AI model registries under ~/.docker/models

Gordon is Docker's AI coding assistant (formerly part of Docker Desktop's
AI features). Its threads directory contains the full conversation history
of what the developer asked an AI to do — a high-value forensic artifact.
"""

import json
import subprocess
from pathlib import Path

from ionsec_trace.collector.base import (
    BaseCollector,
    CollectedFile,
    ParsedArtifact,
    PlatformCategory,
    Severity,
)


class DockerAICollector(BaseCollector):
    PLATFORM_NAME = "docker_ai"
    PLATFORM_CATEGORY = PlatformCategory.AGENT
    PROCESS_NAMES = ["docker", "docker desktop", "gordon"]
    SERVICE_PORTS = []

    # AI-related Docker images we look for (name substrings).
    AI_IMAGE_PATTERNS = [
        "ollama", "localai", "vllm", "text-generation-webui", "textgen",
        "llama-cpp", "llamacpp", "gpt4all", "jan", "anythingllm",
        "open-webui", "openwebui", "litellm", "bifrost", "unsloth",
        "koboldcpp", "tabby", "gpt-engineer", "openhands", "autogpt",
        "crewai", "langchain", "chromadb", "weaviate", "qdrant",
        "milvus", "pgvector", "comfyui", "stable-diffusion", "automatic1111",
    ]

    LINUX_PATHS = ["~/.docker"]
    MACOS_PATHS = ["~/.docker"]
    WINDOWS_PATHS = ["%USERPROFILE%\\.docker"]

    # ── Discover ──────────────────────────────────────────────

    def discover(self) -> bool:
        """Detect Docker AI usage: Gordon present, AI images, or AI containers."""
        for home in self.get_user_home_dirs():
            if (home / ".docker" / "gordon").exists():
                return True
            if (home / ".docker" / "models").exists():
                return True
        if self._running_ai_containers():
            return True
        return bool(self._installed_ai_images())

    # ── Helpers ───────────────────────────────────────────────

    def _gordon_dir(self) -> Path | None:
        """Return the Gordon config dir if present."""
        for home in self.get_user_home_dirs():
            g = home / ".docker" / "gordon"
            if g.exists():
                return g
        return None

    def _models_dir(self) -> Path | None:
        """Return the Docker AI models registry dir if present."""
        for home in self.get_user_home_dirs():
            m = home / ".docker" / "models"
            if m.exists():
                return m
        return None

    def _running_ai_containers(self) -> list[dict]:
        """List running/stopped containers whose image matches an AI pattern."""
        containers = []
        try:
            result = subprocess.run(
                ["docker", "ps", "-a", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}"],
                capture_output=True, text=True, timeout=20,
            )
            for line in result.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 4:
                    image = parts[1]
                    if any(p in image.lower() for p in self.AI_IMAGE_PATTERNS):
                        containers.append({
                            "id": parts[0], "image": image, "name": parts[2],
                            "status": parts[3], "ports": parts[4] if len(parts) > 4 else "",
                        })
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return containers

    def _installed_ai_images(self) -> list[str]:
        """List installed Docker images that match an AI pattern."""
        images = []
        try:
            result = subprocess.run(
                ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                capture_output=True, text=True, timeout=20,
            )
            for line in result.stdout.splitlines():
                if any(p in line.lower() for p in self.AI_IMAGE_PATTERNS):
                    images.append(line.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return images

    # ── Collect ───────────────────────────────────────────────

    def collect(self) -> list[CollectedFile]:
        """Collect Docker AI artifacts: Gordon data, AI models, container list."""
        collected = []

        # Gordon conversation/config data
        gordon = self._gordon_dir()
        if gordon:
            for rel in ["config.json", "history"]:
                p = gordon / rel
                if p.is_file():
                    cf = self._mk_cf(p, "gordon_config" if rel == "config.json" else "gordon_history")
                    collected.append(cf)
                    self.collected_files.append(cf)
            threads = gordon / "threads"
            if threads.is_dir():
                for tf in threads.rglob("*"):
                    if tf.is_file() and tf.stat().st_size < 5 * 1024 * 1024:
                        cf = self._mk_cf(tf, "gordon_conversation")
                        collected.append(cf)
                        self.collected_files.append(cf)

        # Docker AI model registry
        models = self._models_dir()
        if models:
            for mf in ["models.json", "layout.json"]:
                p = models / mf
                if p.is_file():
                    cf = self._mk_cf(p, "ai_model_registry")
                    collected.append(cf)
                    self.collected_files.append(cf)
            manifests = models / "manifests"
            if manifests.is_dir():
                for m in manifests.rglob("*.json"):
                    if m.is_file() and m.stat().st_size < 2 * 1024 * 1024:
                        cf = self._mk_cf(m, "ai_model_manifest")
                        collected.append(cf)
                        self.collected_files.append(cf)

        # Running AI containers — write a volatile snapshot
        containers = self._running_ai_containers()
        if containers:
            snap = Path(self.output_dir) / "docker_ai_containers.json"
            snap.parent.mkdir(parents=True, exist_ok=True)
            snap.write_text(json.dumps(containers, indent=2), encoding="utf-8")
            cf = CollectedFile(
                original_path=str(snap),
                source_os=self.detect_os(),
                platform=self.PLATFORM_NAME,
                artifact_type="ai_container_snapshot",
                size_bytes=snap.stat().st_size,
                sha256=self.calculate_hash(str(snap)),
                collected_at=self.timestamp(),
            )
            collected.append(cf)
            self.collected_files.append(cf)

        return collected

    def _mk_cf(self, path: Path, artifact_type: str) -> CollectedFile:
        return CollectedFile(
            original_path=str(path),
            source_os=self.detect_os(),
            platform=self.PLATFORM_NAME,
            artifact_type=artifact_type,
            size_bytes=path.stat().st_size,
            sha256=self.calculate_hash(str(path)),
            collected_at=self.timestamp(),
        )

    # ── Parse ─────────────────────────────────────────────────

    def parse(self) -> list[ParsedArtifact]:
        """Parse collected Docker AI artifacts into structured findings."""
        artifacts = []
        self._running_ai_containers()
        images = self._installed_ai_images()

        # Gordon presence is itself a shadow-AI signal
        for cf in self.collected_files:
            if cf.artifact_type in ("gordon_config", "gordon_history", "gordon_conversation"):
                content = self.safe_read_file(cf.original_path, max_bytes=2 * 1024 * 1024)
                data = {"path": cf.original_path}
                if content:
                    data["preview"] = content[:2000]
                artifacts.append(ParsedArtifact(
                    platform=self.PLATFORM_NAME,
                    artifact_type=cf.artifact_type,
                    severity=Severity.MEDIUM,
                    data=data,
                    source_file=cf.original_path,
                    mitre_atlas=["AML.T0048"],  # AI Tool Integration
                ))

            elif cf.artifact_type in ("ai_model_registry", "ai_model_manifest"):
                data = self.safe_read_json(cf.original_path)
                if data:
                    artifacts.append(ParsedArtifact(
                        platform=self.PLATFORM_NAME,
                        artifact_type=cf.artifact_type,
                        severity=Severity.INFO,
                        data=data,
                        source_file=cf.original_path,
                    ))

            elif cf.artifact_type == "ai_container_snapshot":
                data = self.safe_read_json(cf.original_path)
                if data:
                    for c in data:
                        artifacts.append(ParsedArtifact(
                            platform=self.PLATFORM_NAME,
                            artifact_type="ai_container",
                            severity=Severity.HIGH,
                            data=c,
                            source_file=cf.original_path,
                            mitre_atlas=["AML.T0048"],
                        ))

        # Installed AI images not covered by container snapshot
        for img in images:
            artifacts.append(ParsedArtifact(
                platform=self.PLATFORM_NAME,
                artifact_type="ai_image",
                severity=Severity.MEDIUM,
                data={"image": img},
                source_file="docker_images",
                mitre_atlas=["AML.T0048"],
            ))

        return artifacts
