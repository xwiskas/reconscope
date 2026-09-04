"""Reporting, recommendations, and argument explanation (PRD §8.4, §8.5, §11)."""

from reconscope.reporting.argv_explain import explain_argv
from reconscope.reporting.builder import build_markdown_report, build_report_zip
from reconscope.reporting.recommendations import recommend_next_steps

__all__ = [
    "explain_argv",
    "build_markdown_report",
    "build_report_zip",
    "recommend_next_steps",
]
