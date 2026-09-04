"""Evidence store (PRD §8.2).

Raw output is stored on disk under the application data directory; the database
keeps only metadata (path, hash, size, flags). Each blob gets a SHA-256 digest.
A per-job budget (default 10 MiB) bounds total retained bytes; content beyond
the budget is truncated and the record says so.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

PER_JOB_LIMIT_BYTES = 10 * 1024 * 1024  # 10 MiB (PRD §8.2)


@dataclass(frozen=True)
class StoredEvidence:
    name: str
    relative_path: str
    media_type: str
    size_bytes: int
    sha256: str
    truncated: bool
    sensitive: bool
    provider: str | None


def _safe_name(name: str) -> str:
    """Reduce an evidence name to a safe filename (no path traversal)."""
    keep = [c if c.isalnum() or c in ("-", "_", ".") else "_" for c in name]
    cleaned = "".join(keep).strip("._") or "evidence"
    return cleaned[:128]


class EvidenceStore:
    def __init__(self, root: Path):
        # ``root`` is the evidence directory (settings.evidence_dir).
        self._root = Path(root)

    def write(
        self,
        job_id: str,
        name: str,
        media_type: str,
        content: bytes,
        *,
        remaining_budget: int,
        provider: str | None = None,
        sensitive: bool = False,
    ) -> StoredEvidence:
        truncated = False
        if remaining_budget <= 0:
            content = b""
            truncated = True
        elif len(content) > remaining_budget:
            content = content[:remaining_budget]
            truncated = True

        job_dir = self._root / "evidence" / _safe_name(job_id)
        job_dir.mkdir(parents=True, exist_ok=True)
        filename = _safe_name(name)
        path = job_dir / filename

        # Avoid clobbering if two blobs share a name within one job.
        counter = 1
        while path.exists():
            stem = path.stem
            suffix = path.suffix
            path = job_dir / f"{stem}-{counter}{suffix}"
            counter += 1

        path.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        relative = path.relative_to(self._root).as_posix()

        return StoredEvidence(
            name=name,
            relative_path=relative,
            media_type=media_type,
            size_bytes=len(content),
            sha256=digest,
            truncated=truncated,
            sensitive=sensitive,
            provider=provider,
        )
