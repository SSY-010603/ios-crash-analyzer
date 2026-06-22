# 🔍 iOS Crash Analyzer

> **Intelligent iOS crash log analysis powered by LangChain + OpenAI**

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)](https://flask.palletsprojects.com)
[![LangChain](https://img.shields.io/badge/LangChain-0.2-green)](https://langchain.com)
[![OpenAI](https://img.shields.io/badge/OpenAI-GPT--4o-orange?logo=openai)](https://openai.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 📄 **Multi-format Support** | Parse `.crash` (text) and `.ips` (JSON) files |
| 🔑 **Auto Symbolication** | Calls Apple's `symbolicatecrash` tool automatically |
| 🤖 **AI Root Cause Analysis** | LangChain tool-calling agent investigates the crash |
| 📊 **Structured Output** | OpenAI structured output guarantees reliable JSON results |
| 🔗 **Crash Clustering** | TF-IDF + hierarchical clustering groups similar crashes |
| 📈 **Visualizations** | Interactive Plotly charts for trends & impact |
| 🌐 **Web Interface** | Beautiful dark-mode dashboard with drag-and-drop upload |
| 🔌 **REST API** | Full JSON API for CI/CD integration |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Web Interface (Flask)                  │
│         Upload  ·  Dashboard  ·  Report  ·  Clusters     │
└────────────────────────┬────────────────────────────────┘
                         │
        ┌────────────────▼──────────────────┐
        │          Analysis Pipeline         │
        │                                   │
        │  1. CrashParser                   │
        │     ├── .crash text format        │
        │     └── .ips JSON format          │
        │                                   │
        │  2. Symbolicator                  │
        │     └── symbolicatecrash tool     │
        │                                   │
        │  3. CrashAnalysisAgent (LangChain)│
        │     ├── Tool: get_metadata()      │
        │     ├── Tool: get_crash_frames()  │
        │     ├── Tool: search_frames()     │
        │     └── Structured Output (OpenAI)│
        │                                   │
        │  4. CrashClusterer                │
        │     └── TF-IDF + Agglomerative   │
        │                                   │
        │  5. ReportGenerator               │
        │     └── JSON report + charts      │
        └───────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- pip
- (Optional) Xcode — for `symbolicatecrash` symbolication
- (Optional) OpenAI API key — for AI analysis

### 1. Clone & Install

```bash
git clone https://github.com/sunshengyao/ios-crash-analyzer.git
cd ios-crash-analyzer

python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env and set your OPENAI_API_KEY
```

```env
OPENAI_API_KEY=sk-...
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-4o-mini
```

> **No API key?** The app still works for parsing and clustering — just without AI analysis.

### 3. Run

```bash
python app.py
```

Open http://localhost:5000 in your browser.

---

## 📖 Usage

### Web Interface

1. Navigate to **Upload** tab
2. Drag & drop `.crash` or `.ips` files
3. Click **Analyze Crashes**
4. View the detailed report with AI root cause analysis

### REST API

```bash
# Upload and analyze
curl -X POST http://localhost:5000/api/upload \
  -F "file=@/path/to/your.crash"

# Get report
curl http://localhost:5000/api/reports/{id}

# Get all clusters
curl http://localhost:5000/api/clusters

# Dashboard summary
curl http://localhost:5000/api/dashboard

# System status
curl http://localhost:5000/api/status
```

### Sample Files

Test with the included sample crashes:

```bash
# Open the upload page and upload from sample_crashes/
ls sample_crashes/
# sample_null_ptr.crash   — EXC_BAD_ACCESS null pointer dereference
# sample_array_bounds.crash — NSRangeException array out of bounds  
# sample_watchdog.crash   — 0x8badf00d watchdog timeout
# sample_db_crash.ips     — IPS format, background thread crash
# sample_ui_thread.crash  — UI updated from background thread
```

---

## 🤖 AI Analysis Pipeline

The `CrashAnalysisAgent` uses a **two-phase** approach:

### Phase 1: Tool-Calling Investigation
The LangChain agent is given 5 tools to investigate the crash:

| Tool | Description |
|------|-------------|
| `get_crash_metadata()` | OS version, device, exception type |
| `get_crashed_thread_frames()` | Full stack trace |
| `get_all_threads_summary()` | Summary of all threads |
| `get_binary_images()` | Loaded frameworks/libraries |
| `search_frames_for_pattern(pattern)` | Search for specific symbols |
| `get_raw_crash_excerpt(start, end)` | Raw log section |

### Phase 2: Structured Output
After investigation, the agent produces a **structured analysis** using OpenAI's structured output mode:

```python
class CrashAnalysisResult(BaseModel):
    exception_type: str
    exception_description: str
    root_cause: CrashRootCause      # category, confidence, description, evidence
    fix_suggestions: list[FixSuggestion]
    affected_component: str
    severity: str                   # critical / high / medium / low
    tags: list[str]
    similar_known_issues: list[str]
```

---

## 📊 Crash Clustering

Crashes are clustered using:
1. **Signature extraction** — top 15 frames from crashed thread, normalized
2. **TF-IDF vectorization** — converts stack traces to vectors
3. **Cosine similarity** — measures similarity between crash vectors
4. **Agglomerative clustering** — groups similar crashes (default threshold: 55%)
5. **Fingerprinting** — MD5 hash of top app-code frames for deduplication

---

## 📁 Project Structure

```
ios-crash-analyzer/
├── app.py                    # Flask application & routes
├── requirements.txt
├── .env.example
├── src/
│   ├── __init__.py
│   ├── crash_parser.py       # .crash and .ips parsing
│   ├── symbolication.py      # symbolicatecrash wrapper
│   ├── analysis_agent.py     # LangChain agent + structured output
│   ├── clustering.py         # TF-IDF crash clustering
│   ├── visualization.py      # Plotly chart generation
│   └── report_generator.py   # Report assembly
├── templates/
│   ├── base.html             # Navigation + dark theme
│   ├── index.html            # Dashboard with charts
│   ├── upload.html           # File upload with drag-and-drop
│   ├── report_detail.html    # Detailed crash report view
│   ├── clusters.html         # Cluster browser
│   └── error.html
├── sample_crashes/           # Example crash files for testing
│   ├── sample_null_ptr.crash
│   ├── sample_array_bounds.crash
│   ├── sample_watchdog.crash
│   ├── sample_db_crash.ips
│   └── sample_ui_thread.crash
├── uploads/                  # Uploaded files (gitignored)
└── reports/                  # Generated reports (gitignored)
```

---

## 🔧 Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | — | OpenAI API key (required for AI analysis) |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | API base URL (supports Azure/proxies) |
| `OPENAI_MODEL` | `gpt-4o-mini` | Model name |
| `FLASK_DEBUG` | `false` | Enable Flask debug mode |
| `FLASK_SECRET_KEY` | (set in .env) | Session secret key |
| `UPLOAD_FOLDER` | `uploads` | Upload directory |
| `REPORT_FOLDER` | `reports` | Report storage directory |
| `MAX_CONTENT_LENGTH` | `52428800` | Max upload size (50MB) |
| `PORT` | `5000` | Server port |

---

## 🍎 Symbolication

If Xcode is installed, the tool automatically uses `symbolicatecrash` to resolve memory addresses to symbol names. The tool searches these locations:

- `/Applications/Xcode.app/Contents/SharedFrameworks/DVTFoundation.framework/.../symbolicatecrash`
- Via `xcrun --find symbolicatecrash`
- Via `find /Applications/Xcode.app -name symbolicatecrash`

For `.dSYM` files, place them in a known location and configure the `dsym_folder` parameter.

---

## 🧩 Supported Exception Types

| Exception | Description |
|-----------|-------------|
| `EXC_BAD_ACCESS (SIGSEGV)` | Null pointer / invalid memory access |
| `EXC_BAD_ACCESS (SIGBUS)` | Misaligned memory access |
| `EXC_CRASH (SIGABRT)` | Abort: NSException, assertion, malloc error |
| `EXC_CRASH (SIGTERM)` | Termination (memory pressure, watchdog) |
| `EXC_RESOURCE` | Resource exhaustion (CPU, memory, wakeup) |
| `EXC_GUARD` | Guarded resource violation |
| `0x8badf00d` | Watchdog timeout |
| `0xdeadfa11` | User-force-quit |
| `0xbaaaaaad` | Stackshot |

---

## 📜 License

MIT License — see [LICENSE](LICENSE)

---

## 🙏 Acknowledgments

- [LangChain](https://langchain.com) — agent framework
- [OpenAI](https://openai.com) — LLM + structured output
- [Flask](https://flask.palletsprojects.com) — web framework  
- [Plotly](https://plotly.com) — interactive charts
- [scikit-learn](https://scikit-learn.org) — clustering algorithms
- [Bootstrap 5](https://getbootstrap.com) — UI framework
