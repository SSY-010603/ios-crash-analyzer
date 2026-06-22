"""
LangChain-powered crash analysis agent
Uses OpenAI structured output for reliable parsing
"""

import json
import logging
from typing import Optional, Any
from pydantic import BaseModel, Field

from langchain_openai import ChatOpenAI
from langchain.tools import tool
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

from .crash_parser import CrashReport, CrashParser

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
#  Pydantic schemas for structured output
# ──────────────────────────────────────────────

class StackFrame(BaseModel):
    frame_number: int
    binary_name: str
    symbol: str
    address: str = ""
    is_app_code: bool = False
    is_system_code: bool = True


class CrashRootCause(BaseModel):
    category: str = Field(description="Category: null_pointer, memory_corruption, stack_overflow, assertion, deadlock, oom, signal, swift_error, objc_message, ui_on_background, other")
    confidence: float = Field(description="Confidence 0.0-1.0")
    description: str = Field(description="Human-readable description of the root cause")
    evidence: list[str] = Field(description="List of stack frames or clues that support this conclusion")


class FixSuggestion(BaseModel):
    priority: str = Field(description="high/medium/low")
    title: str
    description: str
    code_hint: Optional[str] = Field(default=None, description="Optional code snippet hint")


class CrashAnalysisResult(BaseModel):
    """Structured output from crash analysis"""
    exception_type: str
    exception_description: str
    crashed_thread_summary: str
    key_frames: list[StackFrame]
    root_cause: CrashRootCause
    fix_suggestions: list[FixSuggestion]
    affected_component: str = Field(description="The component/module likely responsible")
    severity: str = Field(description="critical/high/medium/low")
    tags: list[str] = Field(description="Relevant tags like: networking, database, ui, memory, threading, ...")
    similar_known_issues: list[str] = Field(description="Any well-known iOS bug patterns this resembles")


# ──────────────────────────────────────────────
#  Tool definitions for the LangChain agent
# ──────────────────────────────────────────────

def make_tools(report: CrashReport):
    """Create agent tools bound to the given crash report"""

    @tool
    def get_crash_metadata() -> str:
        """Get metadata about the crash: OS version, device, app version, date, exception type"""
        return json.dumps({
            "process": report.process_name,
            "app_version": report.app_version,
            "build": report.build_version,
            "os_version": report.os_version,
            "hardware": report.hardware_model,
            "date": report.date_time,
            "exception_type": report.exception_type,
            "exception_codes": report.exception_codes,
            "exception_note": report.exception_note,
            "termination_reason": report.termination_reason,
        }, ensure_ascii=False, indent=2)

    @tool
    def get_crashed_thread_frames(max_frames: int = 30) -> str:
        """Get the stack frames of the crashed thread. max_frames limits output size."""
        if not report.crashed_thread:
            return "No crashed thread found."
        frames = report.crashed_thread.frames[:max_frames]
        result = []
        for f in frames:
            result.append(
                f"{f.frame_number:3d}  {f.binary_name:<28s}  {f.address:<18s}  {f.symbol}"
            )
        return '\n'.join(result)

    @tool
    def get_all_threads_summary() -> str:
        """Get a summary of all threads in the crash report"""
        lines = []
        for t in report.threads:
            crashed_marker = " *** CRASHED ***" if t.crashed else ""
            lines.append(f"Thread {t.thread_id}{' ('+t.thread_name+')' if t.thread_name else ''}{crashed_marker}")
            if t.queue:
                lines.append(f"  Queue: {t.queue}")
            if t.frames:
                top = t.frames[0]
                lines.append(f"  Top frame: {top.binary_name}  {top.symbol}")
        return '\n'.join(lines)

    @tool
    def get_binary_images() -> str:
        """Get the list of binary images (frameworks/libraries) loaded at crash time"""
        if not report.binary_images:
            return "No binary images recorded."
        images = []
        for img in report.binary_images[:50]:
            name = img.get('name', '')
            arch = img.get('arch', '')
            uuid = img.get('uuid', '')
            path = img.get('path', img.get('start_address', ''))
            images.append(f"{name} ({arch}) [{uuid}] {path}")
        return '\n'.join(images)

    @tool
    def search_frames_for_pattern(pattern: str) -> str:
        """Search all thread frames for a symbol pattern. Useful for finding specific calls."""
        results = []
        for thread in report.threads:
            for frame in thread.frames:
                if pattern.lower() in frame.symbol.lower() or pattern.lower() in frame.binary_name.lower():
                    crashed_marker = " [CRASHED THREAD]" if thread.crashed else ""
                    results.append(
                        f"Thread {thread.thread_id}{crashed_marker} Frame {frame.frame_number}: "
                        f"{frame.binary_name} | {frame.symbol}"
                    )
        return '\n'.join(results) if results else f"No frames matching '{pattern}'"

    @tool
    def get_raw_crash_excerpt(start_line: int = 0, end_line: int = 50) -> str:
        """Get a section of the raw crash log for detailed inspection"""
        lines = report.raw_content.split('\n')
        end = min(end_line, len(lines))
        return '\n'.join(lines[start_line:end])

    return [
        get_crash_metadata,
        get_crashed_thread_frames,
        get_all_threads_summary,
        get_binary_images,
        search_frames_for_pattern,
        get_raw_crash_excerpt,
    ]


# ──────────────────────────────────────────────
#  Analysis Agent
# ──────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert iOS crash analyst with deep knowledge of:
- Objective-C / Swift runtime errors
- iOS memory management (ARC, retain cycles)
- Common crash patterns: EXC_BAD_ACCESS, SIGSEGV, SIGABRT, NSException, Swift fatalError
- Threading issues, deadlocks, and race conditions
- UIKit / SwiftUI lifecycle problems
- Networking, database, and file system errors

Your task is to analyze the provided iOS crash report and produce a structured analysis.

ANALYSIS PROCESS:
1. First call get_crash_metadata() to understand the context
2. Call get_crashed_thread_frames() to see the crash stack
3. If needed, call get_all_threads_summary() or search_frames_for_pattern()
4. Reason about root cause from the evidence collected
5. Produce your final structured analysis

Be precise and evidence-based. Always cite specific frame numbers or symbols as evidence."""

ANALYSIS_PROMPT = ChatPromptTemplate.from_messages([
    ("system", SYSTEM_PROMPT),
    ("human", "Please analyze this iOS crash log thoroughly.\n\nFile: {file_name}\nFormat: {file_format}\n\nBegin your analysis now."),
    MessagesPlaceholder(variable_name="agent_scratchpad"),
])


class CrashAnalysisAgent:
    """LangChain agent for iOS crash analysis"""

    def __init__(self, api_key: str, base_url: str = "https://api.openai.com/v1",
                 model: str = "gpt-4o-mini"):
        self.llm = ChatOpenAI(
            api_key=api_key,
            base_url=base_url,
            model=model,
            temperature=0,
        )
        # LLM with structured output
        self.structured_llm = self.llm.with_structured_output(CrashAnalysisResult)

    def analyze(self, report: CrashReport) -> CrashAnalysisResult:
        """Run the full analysis pipeline on a crash report"""
        logger.info(f"Starting analysis for: {report.file_name}")

        tools = make_tools(report)

        # Create agent for tool-calling phase
        agent = create_openai_tools_agent(self.llm, tools, ANALYSIS_PROMPT)
        executor = AgentExecutor(
            agent=agent,
            tools=tools,
            max_iterations=8,
            verbose=True,
            return_intermediate_steps=True,
        )

        # Run tool-calling phase
        result = executor.invoke({
            "file_name": report.file_name,
            "file_format": report.file_format,
        })

        # Gather all tool output for structured analysis
        intermediate = result.get("intermediate_steps", [])
        tool_context = self._format_tool_context(intermediate)
        agent_output = result.get("output", "")

        # Phase 2: Structured output extraction
        structured_result = self._extract_structured(
            report, tool_context, agent_output
        )

        logger.info(f"Analysis complete. Root cause: {structured_result.root_cause.category}")
        return structured_result

    def _format_tool_context(self, steps: list) -> str:
        """Format intermediate tool call results for the structured output prompt"""
        parts = []
        for action, observation in steps:
            parts.append(f"[Tool: {action.tool}]\n{observation}\n")
        return '\n'.join(parts)

    def _extract_structured(
        self, report: CrashReport, tool_context: str, agent_summary: str
    ) -> CrashAnalysisResult:
        """Use structured output to extract the final analysis"""

        # Build a rich context message
        crash_summary = self._build_crash_summary(report)
        
        prompt = f"""Based on the following iOS crash analysis context, provide a complete structured analysis.

CRASH OVERVIEW:
{crash_summary}

TOOL INVESTIGATION RESULTS:
{tool_context[:6000]}

AGENT PRELIMINARY ANALYSIS:
{agent_summary[:2000]}

Now produce the final structured analysis with all required fields filled in accurately."""

        try:
            result = self.structured_llm.invoke(prompt)
            return result
        except Exception as e:
            logger.error(f"Structured extraction failed: {e}", exc_info=True)
            # Return a minimal fallback
            return self._fallback_analysis(report)

    def _build_crash_summary(self, report: CrashReport) -> str:
        """Build a text summary of the crash for the structured output prompt"""
        parts = [
            f"App: {report.process_name} v{report.app_version}",
            f"OS: {report.os_version}",
            f"Exception: {report.exception_type} ({report.exception_codes})",
            f"Termination: {report.termination_reason}",
        ]
        if report.crashed_thread:
            parts.append(f"\nCrash Stack (Thread #{report.triggered_by_thread}):")
            for f in report.crashed_thread.frames[:25]:
                parts.append(f"  {f.frame_number:3d}  {f.binary_name:<28s}  {f.symbol}")
        return '\n'.join(parts)

    def _fallback_analysis(self, report: CrashReport) -> CrashAnalysisResult:
        """Produce a basic analysis without AI (fallback)"""
        from .crash_parser import CrashFrame as CF
        frames = []
        if report.crashed_thread:
            for f in report.crashed_thread.frames[:10]:
                frames.append(StackFrame(
                    frame_number=f.frame_number,
                    binary_name=f.binary_name,
                    symbol=f.symbol,
                    address=f.address,
                    is_app_code=not any(s in f.binary_name for s in [
                        'libsystem', 'CoreFoundation', 'UIKit', 'Foundation', 'libobjc'
                    ]),
                    is_system_code=any(s in f.binary_name for s in [
                        'libsystem', 'CoreFoundation', 'UIKit', 'Foundation', 'libobjc'
                    ]),
                ))
        return CrashAnalysisResult(
            exception_type=report.exception_type or "Unknown",
            exception_description=f"{report.exception_type}: {report.exception_codes}",
            crashed_thread_summary=f"Thread #{report.triggered_by_thread} crashed",
            key_frames=frames,
            root_cause=CrashRootCause(
                category="other",
                confidence=0.3,
                description="Automatic analysis unavailable. Please review the crash stack manually.",
                evidence=[f.symbol for f in report.crashed_thread.frames[:3]] if report.crashed_thread else [],
            ),
            fix_suggestions=[
                FixSuggestion(
                    priority="high",
                    title="Manual Review Required",
                    description="AI analysis failed. Please review the crash stack manually.",
                )
            ],
            affected_component=report.process_name,
            severity="high",
            tags=["manual-review-required"],
            similar_known_issues=[],
        )
