"""Markdown report + evidence ZIP (PRD §11).

Facts, interpretation, and guidance are visually distinct. Every finding line
cites its source and the evidence file that backs it, so each claim is either
traceable to evidence or lives under an explicitly labeled Interpretation /
Guidance section (drawn from reviewed module manifests, never fabricated). The
builder makes no network request.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import zipfile

from sqlalchemy import select
from sqlalchemy.orm import Session

from reconscope.models import (
    ActivityLog,
    AssignmentWorksheet,
    AuthorizationRecord,
    Evidence,
    Finding,
    Job,
    Project,
    ScopeEntry,
)
from reconscope.modules.registry import get_module, list_modules

_FAILED_STATES = ("failed", "partial", "interrupted", "cancelled")


def _h2(title: str) -> str:
    return f"\n## {title}\n"


def _load(session: Session, project_id: str):
    project = session.get(Project, project_id)
    if project is None:
        raise ValueError("project_not_found")
    scope = session.scalars(
        select(ScopeEntry).where(ScopeEntry.project_id == project_id)
    ).all()
    attest = session.scalars(
        select(AuthorizationRecord)
        .where(
            AuthorizationRecord.project_id == project_id,
            AuthorizationRecord.invalidated_at.is_(None),
        )
        .order_by(AuthorizationRecord.accepted_at.desc())
    ).first()
    jobs = session.scalars(
        select(Job).where(Job.project_id == project_id).order_by(Job.created_at)
    ).all()
    findings = session.scalars(
        select(Finding)
        .where(Finding.project_id == project_id)
        .order_by(Finding.finding_type, Finding.value)
    ).all()
    job_ids = [j.id for j in jobs]
    evidence = (
        session.scalars(select(Evidence).where(Evidence.job_id.in_(job_ids))).all()
        if job_ids
        else []
    )
    activity = session.scalars(
        select(ActivityLog)
        .where(ActivityLog.project_id == project_id)
        .order_by(ActivityLog.id)
    ).all()
    worksheet = session.scalars(
        select(AssignmentWorksheet).where(
            AssignmentWorksheet.project_id == project_id
        )
    ).first()
    return project, scope, attest, jobs, findings, evidence, activity, worksheet


def build_markdown_report(session: Session, project_id: str) -> str:
    project, scope, attest, jobs, findings, evidence, activity, worksheet = _load(
        session, project_id
    )
    evidence_by_id = {e.id: e for e in evidence}
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    out: list[str] = []

    out.append(f"# ReconScope Report — {project.name}\n")
    out.append(f"_Generated {now.isoformat()} UTC. All times are UTC._\n")
    out.append(
        "> **How to read this report.** *Facts* are observations that each cite "
        "their source and evidence. *Interpretation* and *Guidance* are labeled "
        "sections; they never assert a system is vulnerable from a port or version "
        "alone.\n"
    )

    # 1. Project
    out.append(_h2("1. Project"))
    out.append(f"- **Name:** {project.name}")
    out.append(f"- **ID:** `{project.id}`")
    if project.description:
        out.append(f"- **Description:** {project.description}")
    out.append(f"- **Created:** {project.created_at.isoformat()}")

    # 2. Scope & authorization
    out.append(_h2("2. Scope & authorization"))
    if scope:
        out.append("| Entry | Type | Canonical | Enabled |")
        out.append("|---|---|---|---|")
        for s in scope:
            out.append(
                f"| `{s.entered_value}` | {s.entry_type} | `{s.normalized_value}` | "
                f"{'yes' if s.enabled else 'no'} |"
            )
    else:
        out.append("_No scope entries (passive only)._")
    if attest is not None:
        out.append(
            f"\n**Authorization attested:** {attest.accepted_at.isoformat()} "
            f"(notice {attest.notice_version}). This is a self-attestation, not "
            "verified ownership."
        )
    else:
        out.append("\n**Authorization:** none current — passive only.")

    # 3. Methodology — modules run
    out.append(_h2("3. Methodology — modules run"))
    if jobs:
        out.append("| Module | Target | Status | Error | Started | Finished |")
        out.append("|---|---|---|---|---|---|")
        for j in jobs:
            out.append(
                f"| {j.module_id} | `{j.target}` | {j.status} | "
                f"{j.error_code or '—'} | "
                f"{j.started_at.isoformat() if j.started_at else '—'} | "
                f"{j.finished_at.isoformat() if j.finished_at else '—'} |"
            )
    else:
        out.append("_No modules have been run._")

    # 4. Findings (facts)
    out.append(_h2("4. Findings — evidence-backed facts"))
    out.append(
        "_Each row is an observation. 'Evidence' names the stored raw output that "
        "backs it (see the evidence manifest for its hash)._\n"
    )
    if findings:
        by_type: dict[str, list[Finding]] = {}
        for f in findings:
            by_type.setdefault(f.finding_type, []).append(f)
        for ftype, rows in by_type.items():
            out.append(f"\n### {ftype} ({len(rows)})\n")
            out.append("| Value | Confidence | Source | Evidence | Target | Last seen |")
            out.append("|---|---|---|---|---|---|")
            for f in rows:
                ev = evidence_by_id.get(f.evidence_id) if f.evidence_id else None
                ev_ref = f"`{ev.name}`" if ev else "—"
                out.append(
                    f"| `{f.value}` | {f.confidence} | {f.source or '—'} | {ev_ref} | "
                    f"`{f.target_requested or '—'}` | {f.last_seen.isoformat()} |"
                )
    else:
        out.append("_No findings recorded._")

    # 5. Interpretation (labeled)
    out.append(_h2("5. Interpretation (derived, labeled)"))
    conf_counts: dict[str, int] = {}
    for f in findings:
        conf_counts[f.confidence] = conf_counts.get(f.confidence, 0) + 1
    if conf_counts:
        out.append(
            "Findings by confidence: "
            + ", ".join(f"{k}={v}" for k, v in sorted(conf_counts.items()))
            + "."
        )
    out.append(
        "\n- `derived-hint` items are **candidates**, not confirmed live assets or "
        "exposures.\n"
        "- `tool-inferred` items (e.g. service/version guesses) are **claims from a "
        "fingerprint**, not verified inventory, and do not by themselves prove a "
        "vulnerability.\n"
        "- `confirmed-by-response` items were directly observed from a source or "
        "tool response."
    )

    # 6. Guidance (labeled, from manifests of modules that ran)
    out.append(_h2("6. Defensive guidance (educational, labeled)"))
    ran_modules = sorted({j.module_id for j in jobs})
    any_guidance = False
    for mid in ran_modules:
        module = get_module(mid)
        if module is None:
            continue
        any_guidance = True
        out.append(f"\n**{module.display_name}**")
        out.append(f"- Defender view: {module.manifest.defender_relevance}")
        out.append(f"- Safe next steps: {module.manifest.safe_next_steps}")
    if not any_guidance:
        out.append("_No modules run yet._")

    # 7. Incomplete/failed jobs
    out.append(_h2("7. Incomplete, failed, or partial jobs"))
    problem_jobs = [j for j in jobs if j.status in _FAILED_STATES]
    if problem_jobs:
        for j in problem_jobs:
            out.append(f"- {j.module_id} on `{j.target}`: {j.status} ({j.error_code or '—'})")
    else:
        out.append("_None._")

    # 8. Activity timeline
    out.append(_h2("8. Activity timeline"))
    if activity:
        for a in activity:
            out.append(
                f"- {a.timestamp.isoformat()} — {a.action} "
                f"{a.module_id or ''} `{a.target or ''}` ({a.scope_decision or '—'})"
            )
    else:
        out.append("_No activity recorded._")

    # 9. Tools & limitations
    out.append(_h2("9. Tools, sources & limitations"))
    out.append(
        "- Results reflect one moment in time and the coverage actually run.\n"
        "- Passive data comes from third parties with their own accuracy and "
        "freshness; active results depend on network conditions and privileges.\n"
        "- Nothing here should be read as proof of a vulnerability."
    )

    # 10. Evidence manifest
    out.append(_h2("10. Evidence manifest"))
    if evidence:
        out.append("| File | Provider | Type | Size (B) | SHA-256 |")
        out.append("|---|---|---|---|---|")
        for e in evidence:
            out.append(
                f"| `{e.relative_path}` | {e.provider or '—'} | {e.media_type} | "
                f"{e.size_bytes} | `{e.sha256}` |"
            )
    else:
        out.append("_No evidence stored._")

    # 11. Coverage
    out.append(_h2("11. Coverage — what was and was not run"))
    ran_status: dict[str, str] = {}
    for j in jobs:
        ran_status[j.module_id] = j.status
    out.append("| Module | Interaction | Status |")
    out.append("|---|---|---|")
    for m in list_modules():
        out.append(
            f"| {m.module_id} | {m.interaction.value} | "
            f"{ran_status.get(m.module_id, 'not run')} |"
        )

    # 12. Assignment worksheet
    if worksheet is not None:
        out.append(_h2("12. Assignment worksheet (learner-authored)"))
        out.append("_The text below was written by the learner, not observed._\n")
        pairs = [
            ("Title", worksheet.title),
            ("Prompt", worksheet.prompt),
            ("Hypothesis", worksheet.hypothesis),
            ("Method", worksheet.method),
            ("Predicted traffic/output", worksheet.predicted_traffic),
            ("Interpretation", worksheet.interpretation),
            ("False-positive considerations", worksheet.false_positive_considerations),
            ("Defender interpretation", worksheet.defender_interpretation),
            ("Conclusion", worksheet.conclusion),
            ("Remaining unknowns", worksheet.remaining_unknowns),
        ]
        for label, value in pairs:
            if value:
                out.append(f"- **{label}:** {value}")

    return "\n".join(out) + "\n"


def build_report_zip(
    session: Session, project_id: str, evidence_store
) -> tuple[bytes, str]:
    """Return (zip_bytes, manifest_sha256).

    The ZIP contains ``report.md``, an ``evidence/`` tree, and ``manifest.json``.
    ``manifest_sha256`` is the hash of the manifest content (deterministic,
    independent of ZIP timestamps).
    """
    markdown = build_markdown_report(session, project_id)
    _p, _s, _a, jobs, findings, evidence, _act, _ws = _load(session, project_id)

    manifest_files: list[dict] = []
    file_bytes: dict[str, bytes] = {}
    for e in evidence:
        path = evidence_store._root / e.relative_path
        try:
            data = path.read_bytes()
        except OSError:
            continue
        # relative_path already begins with "evidence/"; guard against traversal.
        arc = e.relative_path.replace("..", "_")
        file_bytes[arc] = data
        manifest_files.append(
            {
                "path": arc,
                "provider": e.provider,
                "media_type": e.media_type,
                "size_bytes": e.size_bytes,
                "sha256": e.sha256,
            }
        )

    manifest = {
        "project_id": project_id,
        "job_count": len(jobs),
        "finding_count": len(findings),
        "files": manifest_files,
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("report.md", markdown)
        zf.writestr("manifest.json", manifest_bytes)
        for arc, data in file_bytes.items():
            zf.writestr(arc, data)
    return buffer.getvalue(), manifest_hash
