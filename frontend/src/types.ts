// Mirrors backend/privtrace/models/results.py (subset used by the UI).

export type Status = "passed" | "failed" | "needs_review" | "not_assessable";
export type Severity = "critical" | "high" | "medium" | "low";
export type Answer = "yes" | "no" | "not_sure";

export interface PackSummary {
  id: string;
  name: string;
  short_name: string;
  jurisdiction: string;
  version: string;
  source_url: string;
  description: string;
  rule_count: number;
  automated: number;
  hybrid: number;
  manual: number;
  unverified_references: number;
}

export interface ChecklistItem {
  pack_id: string;
  pack: string;
  rule_id: string;
  title: string;
  question: string;
  check_type: "manual" | "hybrid";
  severity: Severity;
  reference: string;
}

export interface ScanStatus {
  scan_id: string;
  status: "queued" | "running" | "done" | "error";
  stage: string;
  message: string;
  source_type: "github" | "zip";
  source_ref: string;
  packs: string[];
  overall_score: number | null;
  risk_level: string | null;
  baseline_id: string | null;
  created_at: string;
}

export interface Evidence {
  file: string;
  line: number;
  snippet: string;
  detail: string;
}

export interface AIEnrichment {
  explanation: string | null;
  suggested_fix: string | null;
  suggested_diff: string | null;
  model: string | null;
}

export interface RuleResult {
  pack_id: string;
  rule_id: string;
  title: string;
  status: Status;
  severity: Severity;
  check_type: "automated" | "manual" | "hybrid";
  reference: string;
  reference_verified: boolean;
  source_url: string;
  why_it_matters: string;
  remediation: string;
  message: string;
  evidence: Evidence[];
  question: string | null;
  manual_answer: Answer | null;
  fix_diff: string | null;
  ai: AIEnrichment | null;
}

export interface Coverage {
  total: number;
  automated_checked: number;
  manual_answered: number;
  not_assessable: number;
  needs_review: number;
}

export interface PackScore {
  pack_id: string;
  name: string;
  short_name: string;
  score: number | null;
  passed: number;
  failed: number;
  needs_review: number;
  not_assessable: number;
  coverage: Coverage;
}

export interface FlowNode {
  id: string;
  type: "source" | "code" | "sink";
  label: string;
  category: string | null;
}

export interface FlowEdge {
  source: string;
  target: string;
  risky: boolean;
  label: string;
  locations: string[];
}

export interface DiffItem {
  rule_id: string;
  title: string;
  from: Status;
  to: Status;
}

export interface ScanDiff {
  previous_scan_id: string;
  overall_before: number | null;
  overall_after: number | null;
  overall_delta: number | null;
  risk_before: string;
  risk_after: string;
  packs: { pack_id: string; short_name: string; before: number | null; after: number | null; delta: number | null }[];
  fixed: DiffItem[];
  regressed: DiffItem[];
  still_failing: DiffItem[];
}

export interface ScanResult {
  scan_id: string;
  created_at: string;
  target: string;
  packs: string[];
  overall_score: number | null;
  risk_level: "Low" | "Medium" | "High" | "Critical";
  pack_scores: PackScore[];
  results: RuleResult[];
  summary: { files_scanned: number; python_files: number; models_with_pii: number; pii_sinks: number; risky_flows: number };
  data_flow: { nodes: FlowNode[]; edges: FlowEdge[] };
  ai_used: boolean;
  ai_model: string | null;
  ai_classifications: { name: string; category: string; reason: string; file: string | null; line: number | null }[];
  diff: ScanDiff | null;
  scoring_formula: string;
  disclaimer: string;
}
