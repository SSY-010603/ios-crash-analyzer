"""
Symbolication module
Wraps Apple's symbolicatecrash tool and provides fallback logic
"""

import os
import re
import subprocess
import logging
import platform
from pathlib import Path
from typing import Optional

from .crash_parser import CrashReport, CrashFrame

logger = logging.getLogger(__name__)

# Common locations for symbolicatecrash on macOS
SYMBOLICATECRASH_PATHS = [
    "/Applications/Xcode.app/Contents/SharedFrameworks/DVTFoundation.framework/Versions/A/Resources/symbolicatecrash",
    "/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/Library/PrivateFrameworks/DTDeviceKitBase.framework/DTDeviceKitBase",
    "/usr/bin/symbolicatecrash",
    "/usr/local/bin/symbolicatecrash",
]


class Symbolicator:
    """Handles symbolication of iOS crash reports"""

    def __init__(self, dsym_folder: Optional[str] = None):
        self.dsym_folder = dsym_folder
        self._symbolicatecrash_path: Optional[str] = None
        self._find_symbolicatecrash()

    def _find_symbolicatecrash(self):
        """Locate symbolicatecrash binary"""
        # Check known paths
        for path in SYMBOLICATECRASH_PATHS:
            if os.path.exists(path):
                self._symbolicatecrash_path = path
                logger.info(f"Found symbolicatecrash at: {path}")
                return

        # Try xcrun
        try:
            result = subprocess.run(
                ['xcrun', '--find', 'symbolicatecrash'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                self._symbolicatecrash_path = result.stdout.strip()
                logger.info(f"Found symbolicatecrash via xcrun: {self._symbolicatecrash_path}")
                return
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Try Xcode's find
        try:
            result = subprocess.run(
                ['find', '/Applications/Xcode.app', '-name', 'symbolicatecrash', '-type', 'f'],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                paths = result.stdout.strip().split('\n')
                self._symbolicatecrash_path = paths[0]
                logger.info(f"Found symbolicatecrash via find: {self._symbolicatecrash_path}")
                return
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        logger.warning("symbolicatecrash not found. Symbolication will use fallback mode.")

    @property
    def is_available(self) -> bool:
        return self._symbolicatecrash_path is not None

    def symbolicate(self, crash_file_path: str, dsym_path: Optional[str] = None) -> tuple[str, bool]:
        """
        Symbolicate a crash file.
        Returns (symbolicated_content, success_flag)
        """
        if not self.is_available:
            logger.warning("symbolicatecrash not available, returning original")
            with open(crash_file_path, 'r', errors='replace') as f:
                return f.read(), False

        dsym = dsym_path or self.dsym_folder
        env = os.environ.copy()
        env['DEVELOPER_DIR'] = '/Applications/Xcode.app/Contents/Developer'

        cmd = [self._symbolicatecrash_path, crash_file_path]
        if dsym and os.path.exists(dsym):
            cmd.extend(['-d', dsym])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True,
                timeout=120,
                env=env
            )
            if result.returncode == 0 and result.stdout:
                logger.info(f"Successfully symbolicated: {crash_file_path}")
                return result.stdout, True
            else:
                logger.warning(f"symbolicatecrash failed: {result.stderr}")
                with open(crash_file_path, 'r', errors='replace') as f:
                    return f.read(), False
        except subprocess.TimeoutExpired:
            logger.error("symbolicatecrash timed out")
            with open(crash_file_path, 'r', errors='replace') as f:
                return f.read(), False
        except Exception as e:
            logger.error(f"Symbolication error: {e}", exc_info=True)
            with open(crash_file_path, 'r', errors='replace') as f:
                return f.read(), False

    def enhance_report(self, report: CrashReport, symbolicated_content: Optional[str] = None) -> CrashReport:
        """
        Post-process a crash report to enhance symbol information.
        Attempts to resolve addresses and clean up symbol names.
        """
        if report.crashed_thread:
            for frame in report.crashed_thread.frames:
                frame.symbol = self._clean_symbol(frame.symbol)
        return report

    @staticmethod
    def _clean_symbol(symbol: str) -> str:
        """Clean up and simplify a symbol name"""
        if not symbol:
            return symbol
        # Remove template noise for readability
        symbol = re.sub(r'<.*?>', '<...>', symbol)
        return symbol

    def get_status(self) -> dict:
        """Return symbolication tool status"""
        return {
            "available": self.is_available,
            "path": self._symbolicatecrash_path,
            "platform": platform.system(),
            "dsym_folder": self.dsym_folder,
        }
