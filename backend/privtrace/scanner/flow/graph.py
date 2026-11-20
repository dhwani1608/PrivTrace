"""Data-flow graph: personal-data sources -> code paths -> sinks."""

from __future__ import annotations

from pydantic import BaseModel, Field

from privtrace.scanner.facts import THIRD_PARTY_SINKS, SinkEvent, SinkKind

RISKY_UNSANITIZED = frozenset({SinkKind.llm, SinkKind.log, SinkKind.analytics, SinkKind.http, SinkKind.vector_store})


class GraphNode(BaseModel):
    id: str
    type: str  # source | code | sink
    label: str
    category: str | None = None


class GraphEdge(BaseModel):
    source: str
    target: str
    risky: bool = False
    label: str = ""
    locations: list[str] = Field(default_factory=list)


class DataFlowGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)

    def to_mermaid(self) -> str:
        lines = ["flowchart LR"]
        ids = {n.id: f"n{i}" for i, n in enumerate(self.nodes)}
        for n in self.nodes:
            shape = {"source": '(["{}"])', "code": '["{}"]', "sink": '[("{}")]'}[n.type]
            lines.append(f"  {ids[n.id]}{shape.format(n.label.replace(chr(34), ''))}")
        for i, e in enumerate(self.edges):
            arrow = "==>" if e.risky else "-->"
            lines.append(f"  {ids[e.source]} {arrow} {ids[e.target]}")
            if e.risky:
                lines.append(f"  linkStyle {i} stroke:#d33,stroke-width:2px")
        return "\n".join(lines)


def is_risky(s: SinkEvent) -> bool:
    if not s.carries_pii or s.sanitized:
        return False
    if s.kind in RISKY_UNSANITIZED:
        return True
    sensitive = {"credentials", "government_id", "financial", "health", "biometric"}
    return s.kind in THIRD_PARTY_SINKS or bool({t.category for t in s.taints} & sensitive)


def build_graph(sinks: list[SinkEvent], max_sources_per_edge: int = 6) -> DataFlowGraph:
    g = DataFlowGraph()
    seen_nodes: dict[str, GraphNode] = {}
    edges: dict[tuple[str, str], GraphEdge] = {}

    def node(nid: str, type_: str, label: str, category: str | None = None) -> str:
        if nid not in seen_nodes:
            seen_nodes[nid] = GraphNode(id=nid, type=type_, label=label, category=category)
        return nid

    def edge(a: str, b: str, risky: bool, where: str, label: str = "") -> None:
        e = edges.get((a, b))
        if e is None:
            e = edges[(a, b)] = GraphEdge(source=a, target=b, risky=risky, label=label)
        e.risky = e.risky or risky
        if where not in e.locations and len(e.locations) < 10:
            e.locations.append(where)

    for s in sinks:
        if not s.carries_pii:
            continue
        risky = is_risky(s)
        fn_file = (s.via[0].file if s.via else s.location.file)
        code_id = node(f"code:{fn_file}:{s.function}", "code", f"{s.function}() · {fn_file}")
        sink_label = s.kind.value.replace("_", " ")
        if s.store:
            sink_label += f": {s.store}"
        sink_id = node(f"sink:{s.kind}:{s.store or s.api}", "sink", sink_label, s.kind.value)
        where = f"{s.location.file}:{s.location.line}"
        for t in s.taints[:max_sources_per_edge]:
            src_name = t.name.split(".")[-1]
            src_id = node(f"src:{t.category}:{src_name}", "source", f"{src_name} ({t.category})", t.category)
            edge(src_id, code_id, risky, where)
        edge(code_id, sink_id, risky, where, label="redacted" if s.sanitized else "")

    g.nodes = list(seen_nodes.values())
    g.edges = list(edges.values())
    return g
