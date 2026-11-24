import type { Answer, ChecklistItem, CiRepo, CiRun, PackSummary, ScanResult, ScanStatus } from "./types";

const BASE = (import.meta.env.VITE_API_URL as string | undefined) ?? "";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, init);
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* not JSON */
    }
    throw new Error(detail || `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => req<{ status: string; ai_configured: boolean }>("/health"),
  packs: () => req<PackSummary[]>("/api/packs"),
  checklist: (packs: string[]) => req<ChecklistItem[]>(`/api/checklist?packs=${encodeURIComponent(packs.join(","))}`),
  startScan: (opts: {
    packs: string[];
    answers: Record<string, Answer>;
    githubUrl?: string;
    file?: File;
    baselineId?: string;
    useAi: boolean;
  }) => {
    const fd = new FormData();
    fd.set("packs", opts.packs.join(","));
    fd.set("answers", JSON.stringify(opts.answers));
    fd.set("use_ai", String(opts.useAi));
    if (opts.githubUrl) fd.set("github_url", opts.githubUrl);
    if (opts.file) fd.set("file", opts.file);
    if (opts.baselineId) fd.set("baseline_id", opts.baselineId);
    return req<ScanStatus>("/api/scans", { method: "POST", body: fd });
  },
  rescan: (scanId: string) => req<ScanStatus>(`/api/scans/${scanId}/rescan`, { method: "POST" }),
  scan: (scanId: string) => req<ScanStatus>(`/api/scans/${scanId}`),
  report: (scanId: string) => req<ScanResult>(`/api/scans/${scanId}/report.json`),
  reportHtmlUrl: (scanId: string, download = false) => `${BASE}/api/scans/${scanId}/report.html${download ? "?download=true" : ""}`,
  reportJsonUrl: (scanId: string) => `${BASE}/api/scans/${scanId}/report.json`,
  ciRepos: () => req<CiRepo[]>("/api/ci/repos"),
  ciRuns: (repo: string) => req<CiRun[]>(`/api/ci/runs?repo=${encodeURIComponent(repo)}&limit=200`),
  reportPdfUrl: (scanId: string) => `${BASE}/api/scans/${scanId}/report.pdf`,
};
