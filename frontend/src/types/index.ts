export type AgentStatus = 'idle' | 'running' | 'done' | 'error';

export interface DiscoveredItem {
  id: string;
  label: string;
  icon: 'file-warning' | 'bug' | 'lock' | 'eye' | 'activity' | 'shield';
  delay: number;
}

export interface Agent {
  id: string;
  name: string;
  type?: string;
  task: string;
  status: AgentStatus;
}

export interface MetricState {
  riskScore: number;
  rawRiskScore?: number;
  totalVulns: number;
  vulnCategories: Record<string, number>;
  riskHistory: { time: string; risk: number }[];
  discoveredItems: DiscoveredItem[];
}

export interface LogEntry {
  id: string;
  agent: string;
  message: string;
  timestamp: string;
  type?: 'error' | 'success' | 'info' | 'idle';
  data?: Record<string, unknown>;
}

// ── Backend Report Types ──────────────────────────────────────

export interface VulnData {
  name: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  cvss_score: number;
  confirmed: boolean;
  endpoint: string;
  payload?: string;
  description?: string;
  evidence?: string;
  dumped_data?: string;
  rce_output?: string;
  fix?: string;
}

export interface ScanSummary {
  total_vulns: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  /** Authoritative 0-100 posture score (higher = safer), from the backend's
   * scoring.py — the same formula the CLI's before/after panel uses. This
   * is the ONLY authoritative score; usePipeline's live `riskScore` is a
   * client-side approximation while a scan is in flight, reconciled
   * against this value on `scan_complete`. */
  security_score: number;
  pages_crawled: number;
  forms_found: number;
  endpoints_found: number;
  commands_executed: number;
}

export interface ScanReport {
  scan_id: string;
  target: string;
  scan_time: string;
  timestamp: string;
  framework: string | null;
  database: string | null;
  server: string | null;
  technologies: string[];
  summary: ScanSummary;
  vulnerabilities: VulnData[];
  analysis: Record<string, unknown> | null;
  cure_plan: CurePlan | null;
}

export interface CurePlan {
  patches: PatchItem[];
  security_checklist: string[];
}

export interface PatchItem {
  vuln: string;
  fix_type: string;
  code: string;
  explanation: string;
}

export interface ScanMeta {
  scan_id: string;
  target_url: string;
  status: 'running' | 'completed' | 'error' | 'timeout';
  started_at: string;
  completed_at: string | null;
  report: ScanReport | null;
  error: string | null;
}

// ── WebSocket Event Types ─────────────────────────────────────

export type WSEvent =
  | { type: 'scan_start'; scan_id: string; target: string }
  | { type: 'stage_start'; stage: number; name: string }
  | { type: 'agent_start'; agent_id: string; agent_name: string; task: string }
  | { type: 'agent_complete'; agent_id: string; agent_name: string; vulns_found: number; task: string; detail?: string }
  | { type: 'agent_error'; agent_id: string; agent_name: string; error: string }
  | { type: 'vuln_found'; agent_id: string; agent_name: string; vuln: VulnData }
  | { type: 'terminal_log'; agent_name: string; command: string; stdout: string; success: boolean }
  | { type: 'agent_log'; agent_name: string; message: string; level: string }
  | { type: 'scan_complete'; report: ScanReport }
  | { type: 'scan_error'; error: string }
  | { type: 'pong' }
  | { type: 'keepalive' };
