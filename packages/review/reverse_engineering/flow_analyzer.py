"""Static call-graph and execution flow analyzer for LogicFalcon.

Reconstructs direct call relationships between extracted symbols and marks
unresolved dynamic dispatch and reflection paths explicitly.
"""

from packages.review.reverse_engineering.models import (
    CallGraph,
    CallGraphEdge,
    ExtractedSymbol,
)


class FlowAnalyzer:
    """Analyzes execution flow and constructs static call graphs."""

    def __init__(self, max_edges: int = 5000) -> None:
        self.max_edges = max_edges

    def build_call_graph(self, symbols: list[ExtractedSymbol]) -> CallGraph:
        """Constructs static call graph from extracted symbols."""
        symbol_index: dict[str, ExtractedSymbol] = {}
        short_name_index: dict[str, list[ExtractedSymbol]] = {}

        # Index all symbols
        for sym in symbols:
            symbol_index[sym.qualified_name] = sym
            short_name_index.setdefault(sym.name, []).append(sym)

        nodes: list[str] = [s.qualified_name for s in symbols]
        edges: list[CallGraphEdge] = []
        unresolved: list[str] = []

        for caller in symbols:
            if len(edges) >= self.max_edges:
                unresolved.append(f"Call graph maximum edge limit reached ({self.max_edges})")
                break
            for callee_ref in caller.callees:
                # 1. Exact match on qualified name
                if callee_ref in symbol_index:
                    target = symbol_index[callee_ref]
                    edges.append(
                        CallGraphEdge(
                            caller_symbol=caller.qualified_name,
                            callee_symbol=target.qualified_name,
                            caller_file=caller.file_path,
                            callee_file=target.file_path,
                            call_type="direct_call",
                            line_number=caller.start_line,
                            confidence=1.0,
                            is_partial=False,
                        )
                    )
                # 2. Match on short name (e.g. "func_name")
                elif callee_ref in short_name_index:
                    candidates = short_name_index[callee_ref]
                    if len(candidates) == 1:
                        target = candidates[0]
                        edges.append(
                            CallGraphEdge(
                                caller_symbol=caller.qualified_name,
                                callee_symbol=target.qualified_name,
                                caller_file=caller.file_path,
                                callee_file=target.file_path,
                                call_type="direct_call",
                                line_number=caller.start_line,
                                confidence=0.85,
                                is_partial=False,
                            )
                        )
                    else:
                        # Ambiguous: choose the one in the same file if any
                        same_file = [c for c in candidates if c.file_path == caller.file_path]
                        if same_file:
                            edges.append(
                                CallGraphEdge(
                                    caller_symbol=caller.qualified_name,
                                    callee_symbol=same_file[0].qualified_name,
                                    caller_file=caller.file_path,
                                    callee_file=same_file[0].file_path,
                                    call_type="direct_call",
                                    line_number=caller.start_line,
                                    confidence=0.90,
                                    is_partial=False,
                                )
                            )
                        else:
                            unresolved.append(f"{caller.qualified_name} -> {callee_ref} (ambiguous match across {len(candidates)} symbols)")
                # 3. Dynamic or attribute calls (e.g. self.do_something)
                elif "." in callee_ref:
                    attr_name = callee_ref.split(".")[-1]
                    if attr_name in short_name_index:
                        candidates = short_name_index[attr_name]
                        if len(candidates) == 1:
                            target = candidates[0]
                            edges.append(
                                CallGraphEdge(
                                    caller_symbol=caller.qualified_name,
                                    callee_symbol=target.qualified_name,
                                    caller_file=caller.file_path,
                                    callee_file=target.file_path,
                                    call_type="method_call",
                                    line_number=caller.start_line,
                                    confidence=0.75,
                                    is_partial=True,
                                )
                            )
                        else:
                            unresolved.append(f"{caller.qualified_name} -> {callee_ref} (unresolved method dispatch)")
                    else:
                        unresolved.append(f"{caller.qualified_name} -> {callee_ref} (external/built-in)")
                else:
                    unresolved.append(f"{caller.qualified_name} -> {callee_ref} (external/built-in)")

        return CallGraph(
            nodes=nodes,
            edges=edges,
            unresolved_calls=unresolved[:100],  # Bound unresolved count
        )
