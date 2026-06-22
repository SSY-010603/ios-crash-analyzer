"""
Report generator
Assembles the final analysis report from all components
"""

import json
import logging
from datetime import datetime
from typing import Optional

from .crash_parser import CrashReport
from .analysis_agent import CrashAnalysisResult
from .clustering import CrashCluster

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Assembles a rich analysis report"""

    def generate(
        self,
        report: CrashReport,
        analysis: Optional[CrashAnalysisResult],
        cluster_info: Optional[dict] = None,
    ) -> dict:
        """Generate a full report dict for a single crash"""
        result = {
            "generated_at": datetime.now().isoformat(),
            "file_name": report.file_name,
            "file_format": report.file_format,
            "metadata": {
                "process": report.process_name,
                "version": report.app_version,
                "build": report.build_version,
                "os_version": report.os_version,
                "hardware": report.hardware_model,
                "date_time": report.date_time,
                "incident_id": report.incident_identifier,
            },
            "exception": {
                "type": report.exception_type,
                "codes": report.exception_codes,
                "note": report.exception_note,
                "termination_reason": report.termination_reason,
                "triggered_by_thread": report.triggered_by_thread,
            },
            "threads_count": len(report.threads),
            "binary_images_count": len(report.binary_images),
            "crashed_thread_frames": [],
        }

        # Add crashed thread frames
        if report.crashed_thread:
            result["crashed_thread_frames"] = [
                {
                    "frame": f.frame_number,
                    "binary": f.binary_name,
                    "address": f.address,
                    "symbol": f.symbol,
                    "offset": f.offset,
                }
                for f in report.crashed_thread.frames
            ]

        # Add AI analysis
        if analysis:
            result["analysis"] = {
                "exception_description": analysis.exception_description,
                "crashed_thread_summary": analysis.crashed_thread_summary,
                "root_cause_category": analysis.root_cause.category,
                "root_cause_confidence": analysis.root_cause.confidence,
                "root_cause_description": analysis.root_cause.description,
                "root_cause_evidence": analysis.root_cause.evidence,
                "severity": analysis.severity,
                "affected_component": analysis.affected_component,
                "tags": analysis.tags,
                "key_frames": [f.model_dump() for f in analysis.key_frames],
                "fix_suggestions": [s.model_dump() for s in analysis.fix_suggestions],
                "similar_known_issues": analysis.similar_known_issues,
            }
            # Also promote some fields to top level for easy access
            result["severity"] = analysis.severity
            result["root_cause_category"] = analysis.root_cause.category
            result["affected_component"] = analysis.affected_component
            result["tags"] = analysis.tags
        else:
            result["severity"] = "unknown"
            result["root_cause_category"] = "unknown"
            result["affected_component"] = report.process_name
            result["tags"] = []

        # Cluster info
        if cluster_info:
            result["cluster"] = cluster_info

        return result

    def generate_summary_report(
        self,
        reports: list[CrashReport],
        analyses: list[dict],
        clusters: list[CrashCluster],
        charts: dict,
    ) -> dict:
        """Generate a dashboard summary report for multiple crashes"""
        from collections import Counter

        total = len(reports)
        analyzed = len([a for a in analyses if a.get('analysis')])

        exception_types = Counter(r.exception_type or "Unknown" for r in reports)
        severities = Counter(a.get('severity', 'unknown') for a in analyses)
        root_causes = Counter(a.get('root_cause_category', 'unknown') for a in analyses)
        components = Counter(a.get('affected_component', 'Unknown') for a in analyses)

        return {
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total_crashes": total,
                "analyzed_crashes": analyzed,
                "total_clusters": len(clusters),
                "unique_exception_types": len(exception_types),
            },
            "exception_distribution": dict(exception_types.most_common(10)),
            "severity_distribution": dict(severities),
            "root_cause_distribution": dict(root_causes.most_common(10)),
            "affected_components": dict(components.most_common(10)),
            "clusters": [c.to_dict() for c in clusters[:20]],
            "charts": charts,
            "reports": analyses,
        }
