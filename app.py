"""
Flask web application for iOS Crash Analyzer
"""

import os
import json
import logging
import uuid
from pathlib import Path
from datetime import datetime
from typing import Optional

from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, flash, session, send_from_directory
)
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import colorlog

from src.crash_parser import CrashParser
from src.symbolication import Symbolicator
from src.analysis_agent import CrashAnalysisAgent
from src.clustering import CrashClusterer
from src.report_generator import ReportGenerator
from src.visualization import generate_dashboard_charts, generate_tag_cloud_data

# ──────────────────────────────────────────────
#  Logging setup
# ──────────────────────────────────────────────

handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    '%(log_color)s%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%H:%M:%S',
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'bold_red',
    }
))
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
#  Load environment
# ──────────────────────────────────────────────
load_dotenv()

# ──────────────────────────────────────────────
#  Flask app
# ──────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev-secret-ios-crash-2024')
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 52428800))

UPLOAD_FOLDER = Path(os.getenv('UPLOAD_FOLDER', 'uploads'))
REPORT_FOLDER = Path(os.getenv('REPORT_FOLDER', 'reports'))
UPLOAD_FOLDER.mkdir(exist_ok=True)
REPORT_FOLDER.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {'.crash', '.ips', '.txt'}

# In-memory store for demo purposes
# In production, replace with a real database
_store: dict = {
    "reports": {},       # id -> parsed report dict
    "analyses": {},      # id -> analysis dict
    "clusters": [],      # list of cluster dicts
    "raw_reports": [],   # CrashReport objects
}

# ──────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────

def get_openai_config() -> tuple[str, str, str]:
    api_key = os.getenv('OPENAI_API_KEY', '')
    base_url = os.getenv('OPENAI_BASE_URL', 'https://api.openai.com/v1')
    model = os.getenv('OPENAI_MODEL', 'gpt-4o-mini')
    return api_key, base_url, model


def is_allowed_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def get_agent() -> Optional[CrashAnalysisAgent]:
    api_key, base_url, model = get_openai_config()
    if not api_key or api_key == 'your_openai_api_key_here':
        return None
    return CrashAnalysisAgent(api_key=api_key, base_url=base_url, model=model)


parser = CrashParser()
symbolicate = Symbolicator()
clusterer = CrashClusterer(similarity_threshold=0.55)
reporter = ReportGenerator()

# ──────────────────────────────────────────────
#  Routes
# ──────────────────────────────────────────────

@app.route('/')
def index():
    """Main dashboard"""
    api_key, _, model = get_openai_config()
    api_configured = bool(api_key and api_key != 'your_openai_api_key_here')

    stats = {
        "total_crashes": len(_store["reports"]),
        "analyzed": len(_store["analyses"]),
        "clusters": len(_store["clusters"]),
        "symbolication_available": symbolicate.is_available,
    }

    # Generate charts if we have data
    charts = {}
    if _store["raw_reports"] and _store["analyses"]:
        analyses_list = list(_store["analyses"].values())
        charts = generate_dashboard_charts(
            _store["raw_reports"],
            analyses_list,
            [_build_cluster_obj(c) for c in _store["clusters"]],
        )
        charts["tag_cloud"] = generate_tag_cloud_data(analyses_list)

    recent = sorted(
        _store["reports"].values(),
        key=lambda r: r.get("generated_at", ""),
        reverse=True
    )[:10]

    return render_template(
        'index.html',
        stats=stats,
        api_configured=api_configured,
        model=model,
        charts=charts,
        recent_reports=recent,
        clusters=_store["clusters"][:8],
    )


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """Upload and analyze crash files"""
    if request.method == 'GET':
        return render_template('upload.html')

    files = request.files.getlist('crash_files')
    if not files or all(f.filename == '' for f in files):
        flash('No files selected', 'error')
        return redirect(url_for('upload'))

    agent = get_agent()
    results = []
    raw_reports = []

    for file in files:
        if not file.filename:
            continue
        filename = secure_filename(file.filename)
        if not is_allowed_file(filename):
            flash(f'Skipped {filename}: unsupported format (use .crash or .ips)', 'warning')
            continue

        # Save
        unique_name = f"{uuid.uuid4().hex}_{filename}"
        save_path = UPLOAD_FOLDER / unique_name
        file.save(str(save_path))
        logger.info(f"Saved upload: {unique_name}")

        try:
            content = save_path.read_text(errors='replace')
        except Exception as e:
            flash(f'Could not read {filename}: {e}', 'error')
            continue

        # Parse
        crash_report = parser.parse_file(filename, content)

        # Symbolication (best-effort)
        sym_content, sym_ok = symbolicate.symbolicate(str(save_path))
        if sym_ok:
            crash_report = parser.parse_file(filename, sym_content)

        # AI Analysis
        analysis_result = None
        if agent:
            try:
                analysis_result = agent.analyze(crash_report)
            except Exception as e:
                logger.error(f"Analysis failed for {filename}: {e}", exc_info=True)
                flash(f'AI analysis failed for {filename}: {str(e)[:100]}', 'warning')

        # Generate report
        report_id = uuid.uuid4().hex
        report_dict = reporter.generate(crash_report, analysis_result)
        report_dict["id"] = report_id
        report_dict["original_filename"] = filename
        report_dict["symbolicated"] = sym_ok

        # Store
        _store["reports"][report_id] = report_dict
        raw_reports.append(crash_report)
        _store["raw_reports"].append(crash_report)

        if analysis_result:
            _store["analyses"][report_id] = report_dict

        # Save report to disk
        report_file = REPORT_FOLDER / f"{report_id}.json"
        report_file.write_text(json.dumps(report_dict, indent=2, ensure_ascii=False))

        results.append({"id": report_id, "filename": filename, "success": True})

    # Re-cluster everything
    if _store["raw_reports"]:
        try:
            clusters = clusterer.cluster(_store["raw_reports"])
            _store["clusters"] = [c.to_dict() for c in clusters]
        except Exception as e:
            logger.error(f"Clustering failed: {e}")

    if results:
        flash(f'Successfully processed {len(results)} crash file(s)', 'success')

    if len(results) == 1:
        return redirect(url_for('report_detail', report_id=results[0]['id']))

    return redirect(url_for('index'))


@app.route('/report/<report_id>')
def report_detail(report_id: str):
    """Detailed view of a single crash report"""
    report = _store["reports"].get(report_id)
    if not report:
        # Try loading from disk
        path = REPORT_FOLDER / f"{report_id}.json"
        if path.exists():
            report = json.loads(path.read_text())
        else:
            flash('Report not found', 'error')
            return redirect(url_for('index'))

    return render_template('report_detail.html', report=report)


@app.route('/clusters')
def clusters_view():
    """View crash clusters"""
    return render_template(
        'clusters.html',
        clusters=_store["clusters"],
        total_crashes=len(_store["reports"]),
    )


# ──────────────────────────────────────────────
#  API endpoints
# ──────────────────────────────────────────────

@app.route('/api/status')
def api_status():
    api_key, base_url, model = get_openai_config()
    return jsonify({
        "status": "ok",
        "version": "1.0.0",
        "api_configured": bool(api_key and api_key != 'your_openai_api_key_here'),
        "model": model,
        "symbolication": symbolicate.get_status(),
        "stats": {
            "reports": len(_store["reports"]),
            "analyses": len(_store["analyses"]),
            "clusters": len(_store["clusters"]),
        },
    })


@app.route('/api/upload', methods=['POST'])
def api_upload():
    """REST API for uploading and analyzing crash files"""
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files['file']
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    filename = secure_filename(file.filename)
    if not is_allowed_file(filename):
        return jsonify({"error": f"Unsupported format. Use .crash or .ips"}), 400

    unique_name = f"{uuid.uuid4().hex}_{filename}"
    save_path = UPLOAD_FOLDER / unique_name
    file.save(str(save_path))

    content = save_path.read_text(errors='replace')
    crash_report = parser.parse_file(filename, content)

    sym_content, sym_ok = symbolicate.symbolicate(str(save_path))
    if sym_ok:
        crash_report = parser.parse_file(filename, sym_content)

    agent = get_agent()
    analysis_result = None
    if agent:
        try:
            analysis_result = agent.analyze(crash_report)
        except Exception as e:
            logger.error(f"API analysis error: {e}")

    report_id = uuid.uuid4().hex
    report_dict = reporter.generate(crash_report, analysis_result)
    report_dict["id"] = report_id
    report_dict["symbolicated"] = sym_ok

    _store["reports"][report_id] = report_dict
    _store["raw_reports"].append(crash_report)
    if analysis_result:
        _store["analyses"][report_id] = report_dict

    return jsonify({"id": report_id, "report": report_dict}), 201


@app.route('/api/reports')
def api_reports():
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    reports = list(_store["reports"].values())
    reports.sort(key=lambda r: r.get("generated_at", ""), reverse=True)
    start = (page - 1) * per_page
    end = start + per_page
    return jsonify({
        "total": len(reports),
        "page": page,
        "per_page": per_page,
        "reports": reports[start:end],
    })


@app.route('/api/reports/<report_id>')
def api_report_detail(report_id: str):
    report = _store["reports"].get(report_id)
    if not report:
        path = REPORT_FOLDER / f"{report_id}.json"
        if path.exists():
            return jsonify(json.loads(path.read_text()))
        return jsonify({"error": "Not found"}), 404
    return jsonify(report)


@app.route('/api/clusters')
def api_clusters():
    return jsonify({
        "total": len(_store["clusters"]),
        "clusters": _store["clusters"],
    })


@app.route('/api/dashboard')
def api_dashboard():
    """Dashboard summary data"""
    from collections import Counter
    reports = list(_store["reports"].values())
    analyses = list(_store["analyses"].values())

    return jsonify({
        "stats": {
            "total": len(reports),
            "analyzed": len(analyses),
            "clusters": len(_store["clusters"]),
        },
        "exception_distribution": dict(Counter(
            r.get("exception", {}).get("type", "Unknown") for r in reports
        ).most_common(10)),
        "severity_distribution": dict(Counter(
            a.get("severity", "unknown") for a in analyses
        )),
        "top_components": dict(Counter(
            a.get("affected_component", "Unknown") for a in analyses
        ).most_common(10)),
        "clusters": _store["clusters"][:10],
    })


# ──────────────────────────────────────────────
#  Utility: build cluster object from dict
# ──────────────────────────────────────────────

class _FakeCluster:
    """Temporary wrapper to pass cluster dicts to visualization"""
    def __init__(self, d):
        self.__dict__.update(d)
        self.size = d.get("size", 0)
        self.unique_count = d.get("unique_count", 0)
        self.cluster_id = d.get("cluster_id", 0)
        self.reports = []

    def get_common_exception_type(self):
        return self.__dict__.get("exception_type", "Unknown")

    def to_dict(self):
        return self.__dict__


def _build_cluster_obj(d: dict) -> '_FakeCluster':
    return _FakeCluster(d)


# ──────────────────────────────────────────────
#  Error handlers
# ──────────────────────────────────────────────

@app.errorhandler(413)
def too_large(e):
    flash('File too large. Maximum size is 50MB.', 'error')
    return redirect(url_for('upload'))


@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error="Page not found"), 404


@app.errorhandler(500)
def server_error(e):
    logger.error(f"500 error: {e}", exc_info=True)
    return render_template('error.html', error="Internal server error"), 500


# ──────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────

if __name__ == '__main__':
    debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    port = int(os.getenv('PORT', 5000))
    logger.info(f"Starting iOS Crash Analyzer on port {port}")
    app.run(debug=debug, port=port, host='0.0.0.0')
