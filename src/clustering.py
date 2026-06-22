"""
Crash clustering module
Groups similar crashes using TF-IDF + cosine similarity on stack traces
"""

import re
import logging
import hashlib
from collections import defaultdict
from typing import Optional

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import AgglomerativeClustering

from .crash_parser import CrashReport

logger = logging.getLogger(__name__)


def _extract_signature(report: CrashReport) -> str:
    """
    Extract a stable signature from a crash report for clustering.
    Uses top N frames from the crashed thread.
    """
    frames = []
    if report.crashed_thread:
        for f in report.crashed_thread.frames[:15]:
            # Normalize: strip addresses and memory-specific info
            symbol = re.sub(r'0x[0-9a-fA-F]+', '', f.symbol)
            symbol = re.sub(r'\s+\+\s*\d+', '', symbol)
            frames.append(f"{f.binary_name}::{symbol.strip()}")
    
    # Also include exception type
    signature_parts = [report.exception_type] + frames
    return ' '.join(signature_parts)


def _stack_fingerprint(report: CrashReport, depth: int = 5) -> str:
    """
    Compute a hash fingerprint from the top N app-code frames.
    Used for exact-match deduplication.
    """
    frames = []
    if report.crashed_thread:
        # Prefer app code frames
        app_frames = [
            f for f in report.crashed_thread.frames
            if not any(sys in f.binary_name for sys in [
                'libsystem', 'CoreFoundation', 'UIKit', 'Foundation',
                'libobjc', 'libdispatch', 'libc++', 'AppKit'
            ])
        ]
        target = app_frames[:depth] if app_frames else report.crashed_thread.frames[:depth]
        for f in target:
            sym = re.sub(r'0x[0-9a-fA-F]+', '', f.symbol).strip()
            frames.append(f"{f.binary_name}::{sym}")

    raw = report.exception_type + '|' + '|'.join(frames)
    return hashlib.md5(raw.encode()).hexdigest()[:12]


class CrashCluster:
    """A group of similar crash reports"""

    def __init__(self, cluster_id: int):
        self.cluster_id = cluster_id
        self.reports: list[CrashReport] = []
        self.representative: Optional[CrashReport] = None
        self.fingerprints: set[str] = set()

    @property
    def size(self) -> int:
        return len(self.reports)

    @property
    def unique_count(self) -> int:
        return len(self.fingerprints)

    def add(self, report: CrashReport, fingerprint: str):
        self.reports.append(report)
        self.fingerprints.add(fingerprint)
        if self.representative is None:
            self.representative = report

    def get_common_exception_type(self) -> str:
        if not self.reports:
            return "Unknown"
        types = [r.exception_type for r in self.reports if r.exception_type]
        if not types:
            return "Unknown"
        return max(set(types), key=types.count)

    def get_common_frames(self, top_n: int = 5) -> list[str]:
        """Find the most common top frames across reports in this cluster"""
        frame_counts: dict[str, int] = defaultdict(int)
        for r in self.reports:
            if r.crashed_thread:
                for f in r.crashed_thread.frames[:10]:
                    key = f"{f.binary_name}::{f.symbol}"
                    frame_counts[key] += 1
        return [k for k, _ in sorted(frame_counts.items(), key=lambda x: -x[1])[:top_n]]

    def to_dict(self) -> dict:
        rep = self.representative
        return {
            "cluster_id": self.cluster_id,
            "size": self.size,
            "unique_count": self.unique_count,
            "exception_type": self.get_common_exception_type(),
            "common_frames": self.get_common_frames(),
            "representative_file": rep.file_name if rep else "",
            "representative_app_version": rep.app_version if rep else "",
            "affected_versions": list({r.app_version for r in self.reports if r.app_version}),
            "affected_os_versions": list({r.os_version for r in self.reports if r.os_version}),
        }


class CrashClusterer:
    """Clusters crash reports using TF-IDF + hierarchical clustering"""

    def __init__(self, similarity_threshold: float = 0.6):
        self.similarity_threshold = similarity_threshold
        self.vectorizer = TfidfVectorizer(
            analyzer='word',
            token_pattern=r'[a-zA-Z_][a-zA-Z0-9_:]+',
            min_df=1,
            max_features=5000,
            sublinear_tf=True,
        )

    def cluster(self, reports: list[CrashReport]) -> list[CrashCluster]:
        """Cluster a list of crash reports"""
        if not reports:
            return []
        if len(reports) == 1:
            c = CrashCluster(0)
            c.add(reports[0], _stack_fingerprint(reports[0]))
            return [c]

        signatures = [_extract_signature(r) for r in reports]
        fingerprints = [_stack_fingerprint(r) for r in reports]

        try:
            tfidf_matrix = self.vectorizer.fit_transform(signatures)
            sim_matrix = cosine_similarity(tfidf_matrix)
        except Exception as e:
            logger.error(f"TF-IDF clustering failed: {e}")
            # Fallback: each report is its own cluster
            clusters = []
            for i, r in enumerate(reports):
                c = CrashCluster(i)
                c.add(r, fingerprints[i])
                clusters.append(c)
            return clusters

        # Convert similarity to distance
        distance_matrix = 1.0 - np.clip(sim_matrix, 0.0, 1.0)

        if len(reports) >= 2:
            try:
                n_clusters = max(1, int(len(reports) * (1 - self.similarity_threshold)))
                n_clusters = min(n_clusters, len(reports))
                clustering = AgglomerativeClustering(
                    n_clusters=None,
                    distance_threshold=1.0 - self.similarity_threshold,
                    metric='precomputed',
                    linkage='average',
                )
                labels = clustering.fit_predict(distance_matrix)
            except Exception as e:
                logger.warning(f"Agglomerative clustering failed: {e}, falling back to simple grouping")
                labels = list(range(len(reports)))
        else:
            labels = [0] * len(reports)

        # Build cluster objects
        cluster_map: dict[int, CrashCluster] = {}
        for idx, (report, label, fp) in enumerate(zip(reports, labels, fingerprints)):
            if label not in cluster_map:
                cluster_map[label] = CrashCluster(label)
            cluster_map[label].add(report, fp)

        # Sort by size descending
        result = sorted(cluster_map.values(), key=lambda c: -c.size)
        # Re-index
        for i, c in enumerate(result):
            c.cluster_id = i

        logger.info(f"Clustered {len(reports)} reports into {len(result)} groups")
        return result
