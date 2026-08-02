"""Higher-level, evidence-backed analysis built on normalized parser models."""

from .functions import analyze_functions, build_call_graph, get_function
from .models import (
    CallGraph,
    CallGraphEdge,
    CallGraphNode,
    Evidence,
    FlowStage,
    FunctionAnalysis,
    ProvenanceKind,
    ProgramFlowSummary,
)


def summarize_program_flow(*args, **kwargs):
    """Lazy import avoids a package cycle with analyzer obfuscation plugins."""
    from .flow import summarize_program_flow as _summarize

    return _summarize(*args, **kwargs)

__all__ = [
    "CallGraph",
    "CallGraphEdge",
    "CallGraphNode",
    "Evidence",
    "FlowStage",
    "FunctionAnalysis",
    "ProvenanceKind",
    "ProgramFlowSummary",
    "analyze_functions",
    "build_call_graph",
    "get_function",
    "summarize_program_flow",
]
