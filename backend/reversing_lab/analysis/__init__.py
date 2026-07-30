"""Higher-level, evidence-backed analysis built on normalized parser models."""

from .functions import analyze_functions, build_call_graph, get_function
from .models import (
    CallGraph,
    CallGraphEdge,
    CallGraphNode,
    Evidence,
    FunctionAnalysis,
    ProvenanceKind,
)

__all__ = [
    "CallGraph",
    "CallGraphEdge",
    "CallGraphNode",
    "Evidence",
    "FunctionAnalysis",
    "ProvenanceKind",
    "analyze_functions",
    "build_call_graph",
    "get_function",
]
