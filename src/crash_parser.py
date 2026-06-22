"""
iOS Crash Log Parser
Supports .crash and .ips format files
"""

import re
import json
import logging
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class CrashFrame:
    """Single stack frame in a crash trace"""
    frame_number: int
    binary_name: str
    address: str
    symbol: str
    offset: int = 0
    file_path: str = ""
    line_number: int = 0

    def to_dict(self) -> dict:
        return {
            "frame_number": self.frame_number,
            "binary_name": self.binary_name,
            "address": self.address,
            "symbol": self.symbol,
            "offset": self.offset,
            "file_path": self.file_path,
            "line_number": self.line_number,
        }


@dataclass
class CrashThread:
    """A thread in the crash report"""
    thread_id: int
    thread_name: str
    crashed: bool
    frames: list[CrashFrame] = field(default_factory=list)
    queue: str = ""

    def to_dict(self) -> dict:
        return {
            "thread_id": self.thread_id,
            "thread_name": self.thread_name,
            "crashed": self.crashed,
            "frames": [f.to_dict() for f in self.frames],
            "queue": self.queue,
        }


@dataclass
class CrashReport:
    """Full parsed crash report"""
    # Metadata
    incident_identifier: str = ""
    crash_reporter_key: str = ""
    hardware_model: str = ""
    process_name: str = ""
    process_id: int = 0
    path: str = ""
    identifier: str = ""
    version: str = ""
    app_version: str = ""
    build_version: str = ""
    code_type: str = ""
    role: str = ""
    parent_process: str = ""
    coalition: str = ""
    date_time: str = ""
    os_version: str = ""
    release_type: str = ""
    base_system_version: str = ""
    report_version: int = 0

    # Exception info
    exception_type: str = ""
    exception_codes: str = ""
    exception_note: str = ""
    termination_reason: str = ""
    triggered_by_thread: int = 0

    # Threads
    threads: list[CrashThread] = field(default_factory=list)

    # Binary images
    binary_images: list[dict] = field(default_factory=list)

    # Raw content
    raw_content: str = ""
    file_name: str = ""
    file_format: str = ""  # "crash" or "ips"

    # Analysis helpers
    crashed_thread: Optional[CrashThread] = None

    def to_dict(self) -> dict:
        return {
            "incident_identifier": self.incident_identifier,
            "hardware_model": self.hardware_model,
            "process_name": self.process_name,
            "process_id": self.process_id,
            "version": self.version,
            "app_version": self.app_version,
            "build_version": self.build_version,
            "code_type": self.code_type,
            "date_time": self.date_time,
            "os_version": self.os_version,
            "exception_type": self.exception_type,
            "exception_codes": self.exception_codes,
            "exception_note": self.exception_note,
            "termination_reason": self.termination_reason,
            "triggered_by_thread": self.triggered_by_thread,
            "threads": [t.to_dict() for t in self.threads],
            "binary_images_count": len(self.binary_images),
            "file_name": self.file_name,
            "file_format": self.file_format,
            "crashed_thread_frames": [
                f.to_dict() for f in (self.crashed_thread.frames if self.crashed_thread else [])
            ],
        }


class CrashParser:
    """Parses iOS .crash and .ips log files"""

    # Regex patterns for crash format
    FRAME_PATTERN = re.compile(
        r'^(\d+)\s+(\S+)\s+(0x[0-9a-fA-F]+)\s+(.+?)\s*(?:\+\s*(\d+))?$'
    )
    THREAD_PATTERN = re.compile(r'^Thread\s+(\d+)(?:\s+name:\s*(.+))?:?$')
    THREAD_CRASHED_PATTERN = re.compile(r'^Thread\s+(\d+)\s+Crashed:?.*$')
    BINARY_IMAGE_PATTERN = re.compile(
        r'^\s*(0x[0-9a-fA-F]+)\s*-\s*(0x[0-9a-fA-F]+)\s+(\S+)\s+(\S+)\s+<([^>]+)>\s+(.+)$'
    )

    def parse_file(self, file_path: str, file_content: str) -> CrashReport:
        """Parse a crash file and return a CrashReport"""
        report = CrashReport()
        report.file_name = file_path
        report.raw_content = file_content

        # Detect format
        stripped = file_content.strip()
        if stripped.startswith('{'):
            report.file_format = "ips"
            return self._parse_ips(report, file_content)
        else:
            report.file_format = "crash"
            return self._parse_crash(report, file_content)

    def _parse_ips(self, report: CrashReport, content: str) -> CrashReport:
        """Parse Apple .ips JSON format"""
        try:
            # IPS files may have a header line followed by JSON
            lines = content.strip().split('\n')
            json_start = 0
            for i, line in enumerate(lines):
                if line.strip().startswith('{'):
                    json_start = i
                    break
            json_content = '\n'.join(lines[json_start:])
            data = json.loads(json_content)

            # Extract metadata
            report.incident_identifier = data.get('incident_id', data.get('incidentIdentifier', ''))
            report.process_name = data.get('procName', data.get('process_name', ''))
            report.hardware_model = data.get('modelCode', data.get('product', ''))
            report.os_version = data.get('osVersion', '')
            report.date_time = data.get('captureTime', data.get('timestamp', ''))
            report.app_version = data.get('bundleVersion', '')
            report.build_version = data.get('bundleID', '')
            report.code_type = data.get('cpuType', '')

            # Exception info
            exception = data.get('exception', {})
            if isinstance(exception, dict):
                report.exception_type = exception.get('type', '')
                report.exception_codes = exception.get('codes', '')
                report.triggered_by_thread = exception.get('crashed_thread', 0)
            
            # Try termination
            termination = data.get('termination', {})
            if isinstance(termination, dict):
                report.termination_reason = str(termination.get('code', ''))
                if not report.exception_type:
                    report.exception_type = termination.get('namespace', '')

            # Threads
            threads_data = data.get('threads', [])
            for idx, t_data in enumerate(threads_data):
                crashed = t_data.get('triggered', False)
                thread = CrashThread(
                    thread_id=idx,
                    thread_name=t_data.get('name', ''),
                    crashed=crashed,
                    queue=t_data.get('queue', ''),
                )
                frames_data = t_data.get('frames', [])
                for f_idx, frame_data in enumerate(frames_data):
                    frame = CrashFrame(
                        frame_number=f_idx,
                        binary_name=frame_data.get('imageOffset', {}) if isinstance(frame_data, dict) else '',
                        address=hex(frame_data.get('imageOffset', 0)) if isinstance(frame_data, dict) else '',
                        symbol=frame_data.get('symbol', '') if isinstance(frame_data, dict) else str(frame_data),
                        offset=frame_data.get('symbolLocation', 0) if isinstance(frame_data, dict) else 0,
                    )
                    # Get binary name from image index
                    img_idx = frame_data.get('imageIndex', -1) if isinstance(frame_data, dict) else -1
                    images = data.get('usedImages', [])
                    if 0 <= img_idx < len(images):
                        img = images[img_idx]
                        frame.binary_name = img.get('name', img.get('path', '').split('/')[-1])
                        frame.address = hex(
                            img.get('base', 0) + frame_data.get('imageOffset', 0)
                        )
                    thread.frames.append(frame)
                report.threads.append(thread)
                if crashed:
                    report.crashed_thread = thread
                    report.triggered_by_thread = idx

            # Binary images
            for img in data.get('usedImages', []):
                report.binary_images.append({
                    'name': img.get('name', img.get('path', '').split('/')[-1]),
                    'arch': img.get('arch', ''),
                    'uuid': img.get('uuid', ''),
                    'path': img.get('path', ''),
                    'base_address': hex(img.get('base', 0)),
                })

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse IPS as JSON, falling back to crash format: {e}")
            return self._parse_crash(report, content)
        except Exception as e:
            logger.error(f"Error parsing IPS file: {e}", exc_info=True)

        return report

    def _parse_crash(self, report: CrashReport, content: str) -> CrashReport:
        """Parse classic .crash text format"""
        lines = content.split('\n')
        section = 'header'
        current_thread: Optional[CrashThread] = None

        for line in lines:
            line_stripped = line.strip()

            # Detect section boundaries
            if line_stripped.startswith('Binary Images:'):
                section = 'binary_images'
                continue
            elif re.match(r'^Thread \d+', line_stripped):
                section = 'threads'

            if section == 'header':
                self._parse_header_line(report, line_stripped)

            elif section == 'threads':
                # Check for new thread header
                crashed_match = self.THREAD_CRASHED_PATTERN.match(line_stripped)
                thread_match = self.THREAD_PATTERN.match(line_stripped)

                if crashed_match:
                    tid = int(crashed_match.group(1))
                    current_thread = CrashThread(
                        thread_id=tid,
                        thread_name="",
                        crashed=True,
                    )
                    report.threads.append(current_thread)
                    report.crashed_thread = current_thread
                    report.triggered_by_thread = tid
                elif thread_match and not crashed_match:
                    tid = int(thread_match.group(1))
                    name = thread_match.group(2) or ""
                    current_thread = CrashThread(
                        thread_id=tid,
                        thread_name=name,
                        crashed=False,
                    )
                    report.threads.append(current_thread)
                elif line_stripped.startswith('Dispatch queue:'):
                    if current_thread:
                        current_thread.queue = line_stripped.replace('Dispatch queue:', '').strip()
                elif current_thread and line_stripped:
                    frame = self._parse_frame(line_stripped)
                    if frame:
                        current_thread.frames.append(frame)
                elif not line_stripped:
                    current_thread = None

            elif section == 'binary_images':
                img = self._parse_binary_image(line_stripped)
                if img:
                    report.binary_images.append(img)

        return report

    def _parse_header_line(self, report: CrashReport, line: str):
        """Parse a single header line"""
        kv_map = {
            'Incident Identifier:': 'incident_identifier',
            'CrashReporter Key:': 'crash_reporter_key',
            'Hardware Model:': 'hardware_model',
            'Process:': None,  # special
            'Path:': 'path',
            'Identifier:': 'identifier',
            'Code Type:': 'code_type',
            'Role:': 'role',
            'Date/Time:': 'date_time',
            'OS Version:': 'os_version',
            'Release Type:': 'release_type',
            'Exception Type:': 'exception_type',
            'Exception Codes:': 'exception_codes',
            'Exception Note:': 'exception_note',
            'Termination Reason:': 'termination_reason',
            'Triggered by Thread:': None,  # special - int
        }
        for prefix, attr in kv_map.items():
            if line.startswith(prefix):
                value = line[len(prefix):].strip()
                if attr:
                    setattr(report, attr, value)
                elif prefix == 'Process:':
                    # "MyApp [1234]"
                    m = re.match(r'(.+?)\s+\[(\d+)\]', value)
                    if m:
                        report.process_name = m.group(1).strip()
                        report.process_id = int(m.group(2))
                    else:
                        report.process_name = value
                elif prefix == 'Triggered by Thread:':
                    try:
                        report.triggered_by_thread = int(value)
                    except ValueError:
                        pass
                # Version parsing
        if line.startswith('Version:'):
            value = line[8:].strip()
            m = re.match(r'(.+?)\s+\((.+?)\)', value)
            if m:
                report.app_version = m.group(1).strip()
                report.build_version = m.group(2).strip()
            else:
                report.app_version = value

    def _parse_frame(self, line: str) -> Optional[CrashFrame]:
        """Parse a single stack frame line"""
        m = self.FRAME_PATTERN.match(line)
        if not m:
            return None
        return CrashFrame(
            frame_number=int(m.group(1)),
            binary_name=m.group(2),
            address=m.group(3),
            symbol=m.group(4).strip(),
            offset=int(m.group(5)) if m.group(5) else 0,
        )

    def _parse_binary_image(self, line: str) -> Optional[dict]:
        """Parse a binary image line"""
        m = self.BINARY_IMAGE_PATTERN.match(line)
        if not m:
            return None
        return {
            'start_address': m.group(1),
            'end_address': m.group(2),
            'name': m.group(3),
            'arch': m.group(4),
            'uuid': m.group(5),
            'path': m.group(6),
        }

    def get_crash_summary(self, report: CrashReport) -> str:
        """Get a human-readable summary of the crash"""
        lines = []
        lines.append(f"Process: {report.process_name} v{report.app_version} ({report.build_version})")
        lines.append(f"OS: {report.os_version} on {report.hardware_model}")
        lines.append(f"Date: {report.date_time}")
        lines.append(f"Exception: {report.exception_type} - {report.exception_codes}")
        if report.termination_reason:
            lines.append(f"Termination: {report.termination_reason}")
        lines.append(f"Crashed Thread: #{report.triggered_by_thread}")
        if report.crashed_thread:
            lines.append(f"\nCrash Stack (Thread #{report.triggered_by_thread}):")
            for frame in report.crashed_thread.frames[:20]:
                lines.append(
                    f"  {frame.frame_number:3d}  {frame.binary_name:<30s}  {frame.address}  {frame.symbol}"
                )
        return '\n'.join(lines)
