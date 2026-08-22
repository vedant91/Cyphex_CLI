import { useState, useCallback, useRef, useEffect } from 'react';
import type { Agent, MetricState, LogEntry, ScanReport, WSEvent, VulnData } from '../types';
import { startScan, connectScanWebSocket, getScan } from '../lib/api';

// ── Agent definitions matching the real backend pipeline ──────
const initialAgents: Agent[] = [
  { id: 'recon', name: 'Recon Agent', task: 'Ready', status: 'idle' },
  { id: 'crawler', name: 'Crawler Agent', task: 'Ready', status: 'idle' },
  { id: 'injection', name: 'Injection Agent (SQLi + CMDi)', task: 'Ready', status: 'idle' },
  { id: 'xss', name: 'XSS Agent', task: 'Ready', status: 'idle' },
  { id: 'auth', name: 'Auth Agent', task: 'Ready', status: 'idle' },
  { id: 'lfi', name: 'LFI Agent', task: 'Ready', status: 'idle' },
  { id: 'logic', name: 'Logic Agent', task: 'Ready', status: 'idle' },
  { id: 'supply_chain', name: 'Supply Chain Agent', task: 'Ready', status: 'idle' },
  { id: 'analysis', name: 'Analysis Agent', task: 'Ready', status: 'idle' },
  { id: 'patch', name: 'Patch Agent', task: 'Ready', status: 'idle' },
];

// Live, client-side risk weighting used ONLY to animate the gauge while a
// scan is still in flight (vuln_found events arrive one at a time, well
// before the backend has a final count to score). These weights mirror the
// RELATIVE severity ordering of the backend's authoritative formula
// (scoring.py: Critical=62, High=16, Medium=6, Low=2 — roughly 31:8:3:1),
// not its exact curve — this is deliberately an approximation, not a
// second copy of the real formula. The authoritative 0-100 posture score
// (backend scoring.py, higher = safer) arrives in `report.summary.security_score`
// on `scan_complete` and OVERWRITES `riskScore` below (riskScore is the
// inverse: higher = worse), so this live estimate can never permanently
// disagree with the backend truth the way it used to.
const SEVERITY_RISK: Record<string, number> = {
  Critical: 31,
  High: 8,
  Medium: 3,
  Low: 1,
};

/** Convert the backend's authoritative posture score (0-100, higher =
 * safer) to this dashboard's risk gauge scale (0-100, higher = worse). */
const securityScoreToRiskScore = (securityScore: number): number =>
  Math.max(0, Math.min(100, 100 - securityScore));

const VULN_ICON_MAP: Record<string, string> = {
  injection: 'bug',
  xss: 'activity',
  auth: 'lock',
  lfi: 'file-warning',
  logic: 'eye',
  supply_chain: 'shield',
  recon: 'shield',
  crawler: 'activity',
};

export function usePipeline() {
  const [agents, setAgents] = useState<Agent[]>(initialAgents);
  const [metrics, setMetrics] = useState<MetricState>({
    riskScore: 0,
    rawRiskScore: 0,
    totalVulns: 0,
    vulnCategories: {
      Injection: 0, XSS: 0, Auth: 0, LFI: 0, Logic: 0, SupplyChain: 0, Recon: 0,
    },
    riskHistory: [{ time: new Date().toLocaleTimeString(), risk: 0 }],
    discoveredItems: [],
  });
  const [logs, setLogs] = useState<LogEntry[]>([
    { id: 'sys-1', agent: 'System', message: 'System ready. Awaiting target URL.', timestamp: new Date().toISOString() },
  ]);
  const [isRunning, setIsRunning] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [currentStage, setCurrentStage] = useState(0);
  const [backendConnected, setBackendConnected] = useState(true);

  const wsRef = useRef<WebSocket | null>(null);

  // ── Helpers ──────────────────────────────────────────────────

  const addLog = useCallback((agent: string, message: string, type?: LogEntry['type']) => {
    setLogs(prev => [...prev, {
      id: Date.now().toString() + Math.random(),
      agent,
      message,
      timestamp: new Date().toISOString(),
      type,
    }]);
  }, []);

  const updateAgent = useCallback((id: string, updates: Partial<Agent>) => {
    setAgents(prev => prev.map(a => a.id === id ? { ...a, ...updates } : a));
  }, []);

  const addRisk = useCallback((
    amount: number,
    category?: string,
    count: number = 0,
    findings?: { label: string; icon: string }[]
  ) => {
    setMetrics(prev => {
      const newRawRisk = (prev.rawRiskScore || 0) + amount;
      const newScore = Math.min(99, Math.round(100 * (1 - Math.exp(-0.02 * newRawRisk))));

      const newCats = { ...prev.vulnCategories };
      if (category && category in newCats) {
        newCats[category] += count;
      }

      const newDiscoveries = [...prev.discoveredItems];
      if (findings) {
        findings.forEach(f => {
          newDiscoveries.push({
            id: Date.now() + Math.random().toString(),
            label: f.label,
            icon: f.icon as any,
            delay: Date.now(),
          });
        });
      }

      return {
        ...prev,
        riskScore: newScore,
        rawRiskScore: newRawRisk,
        totalVulns: prev.totalVulns + count,
        vulnCategories: newCats,
        // Only push actual real updates occasionally or keep as is, 
        // the useEffect handles the animated chart plotting now!
        riskHistory: [...prev.riskHistory, { time: new Date().toLocaleTimeString(), risk: newScore }],
        discoveredItems: newDiscoveries,
      };
    });
  }, []);

  const resetState = useCallback(() => {
    setAgents(initialAgents);
    setMetrics({
      riskScore: 0,
      rawRiskScore: 0,
      totalVulns: 0,
      vulnCategories: {
        Injection: 0, XSS: 0, Auth: 0, LFI: 0, Logic: 0, SupplyChain: 0, Recon: 0,
      },
      riskHistory: [{ time: new Date().toLocaleTimeString(), risk: 0 }],
      discoveredItems: [],
    });
    setReport(null);
    setCurrentStage(0);
  }, []);

  // ── Map agent_id to vuln category ────────────────────────────
  const agentToCategory = (agentId: string): string => {
    const map: Record<string, string> = {
      injection: 'Injection',
      xss: 'XSS',
      auth: 'Auth',
      lfi: 'LFI',
      logic: 'Logic',
      supply_chain: 'SupplyChain',
      recon: 'Recon',
    };
    return map[agentId] || agentId;
  };

  // ── Dynamic Graph Animation ──────────────────────────────────
  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    if (isRunning) {
      interval = setInterval(() => {
        setMetrics(prev => {
          const jitter = (Math.random() * 4) - 2;
          const visualRisk = Math.max(0, Math.min(100, prev.riskScore + jitter));
          const newHistory = [...prev.riskHistory, { time: new Date().toLocaleTimeString(), risk: visualRisk }];
          if (newHistory.length > 30) newHistory.shift();
          return { ...prev, riskHistory: newHistory };
        });
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [isRunning]);

  // ── WebSocket Event Handler ──────────────────────────────────

  const handleWSEvent = useCallback((event: WSEvent) => {
    switch (event.type) {
      case 'scan_start':
        addLog('System', `Scan started on ${(event as any).target}`, 'info');
        break;

      case 'stage_start': {
        const e = event as any;
        setCurrentStage(e.stage);
        addLog('System', `━━━ STAGE ${e.stage}/5: ${e.name} ━━━`, 'info');
        break;
      }

      case 'agent_start': {
        const e = event as any;
        updateAgent(e.agent_id, { status: 'running', task: e.task });
        addLog(e.agent_name, `Started: ${e.task}`, 'info');
        break;
      }

      case 'agent_complete': {
        const e = event as any;
        updateAgent(e.agent_id, { status: 'done', task: e.task });
        addLog(e.agent_name, `Complete: ${e.task} (${e.vulns_found} vulns)`, 'success');
        break;
      }

      case 'agent_error': {
        const e = event as any;
        updateAgent(e.agent_id, { status: 'error', task: `Error: ${e.error}` });
        addLog(e.agent_name, `Error: ${e.error}`, 'error');
        break;
      }

      case 'vuln_found': {
        const e = event as any;
        const vuln = e.vuln as VulnData;
        const riskAmount = SEVERITY_RISK[vuln.severity] || 5;
        const category = agentToCategory(e.agent_id);
        const iconType = VULN_ICON_MAP[e.agent_id] || 'bug';

        addRisk(riskAmount, category, 1, [
          { label: vuln.name.substring(0, 20), icon: iconType },
        ]);

        addLog(e.agent_name,
          `🚨 [${vuln.severity}] ${vuln.name} at ${vuln.endpoint} (CVSS: ${vuln.cvss_score})`,
          'error',
        );
        break;
      }

      // terminal_log and agent_log are intentionally not forwarded by the
      // backend to avoid WebSocket floods.  The lifecycle events above
      // (agent_start, agent_complete, vuln_found, stage_start) cover all
      // the important entries the terminal needs to display.

      case 'scan_complete': {
        const e = event as any;
        const finalReport = e.report as ScanReport;
        setReport(finalReport);
        // Reconcile the live client-side estimate with the backend's
        // authoritative score — see securityScoreToRiskScore() above.
        const authoritativeScore = finalReport?.summary?.security_score;
        if (typeof authoritativeScore === 'number') {
          const finalRisk = securityScoreToRiskScore(authoritativeScore);
          setMetrics(prev => ({
            ...prev,
            riskScore: finalRisk,
            riskHistory: [...prev.riskHistory, { time: new Date().toLocaleTimeString(), risk: finalRisk }],
          }));
        }
        setIsRunning(false);
        addLog('System', '✓ Scan completed successfully.', 'success');
        break;
      }

      case 'scan_error': {
        const e = event as any;
        setIsRunning(false);
        addLog('System', `✗ Scan failed: ${e.error}`, 'error');
        break;
      }

      default:
        break;
    }
  }, [addLog, updateAgent, addRisk]);

  // ── Start Pipeline (calls real backend) ──────────────────────

  const startPipeline = useCallback(async (targetURL: string) => {
    if (isRunning) return;
    setIsRunning(true);
    resetState();

    setLogs([{
      id: Date.now().toString(),
      agent: 'System',
      message: `Initializing scan for ${targetURL}...`,
      timestamp: new Date().toISOString(),
      type: 'info',
    }]);

    try {
      // Call the backend API to start the scan
      const result = await startScan(targetURL);
      const newScanId = result.scan_id;
      setScanId(newScanId);
      setBackendConnected(true);

      addLog('System', `Scan ${newScanId} started. Connecting to live feed...`, 'info');

      // Connect WebSocket for real-time updates
      if (wsRef.current) {
        wsRef.current.close();
      }

      wsRef.current = connectScanWebSocket(
        newScanId,
        handleWSEvent,
        () => {
          // On close — check if scan completed
          if (scanId) {
            getScan(newScanId).then(meta => {
              if (meta.report) {
                setReport(meta.report);
                // Same reconciliation as the scan_complete WS event, for the
                // case where the socket closed before that event arrived.
                const authoritativeScore = meta.report.summary?.security_score;
                if (typeof authoritativeScore === 'number') {
                  const finalRisk = securityScoreToRiskScore(authoritativeScore);
                  setMetrics(prev => ({
                    ...prev,
                    riskScore: finalRisk,
                    riskHistory: [...prev.riskHistory, { time: new Date().toLocaleTimeString(), risk: finalRisk }],
                  }));
                }
              }
              setIsRunning(false);
            }).catch(() => setIsRunning(false));
          }
        },
        () => {
          addLog('System', 'WebSocket connection lost. Retrying...', 'error');
        },
      );

    } catch (err: any) {
      // Backend is unreachable — fall back to demo mode
      console.warn('Backend unreachable, running demo mode:', err.message);
      setBackendConnected(false);
      addLog('System', `⚠ Backend unreachable (${err.message}). Running in demo mode...`, 'error');
      await runDemoMode(targetURL);
    }
  }, [isRunning, resetState, addLog, handleWSEvent, scanId]);

  // ── Demo/fallback mode (simulated) ──────────────────────────

  const runDemoMode = useCallback(async (targetURL: string) => {
    const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

    addLog('System', `Demo mode for ${targetURL}`, 'info');

    // Stage 1: Recon
    updateAgent('recon', { status: 'running', task: `Scanning ${targetURL}` });
    addLog('Recon Agent', 'Gathering headers, tech stacks, probing sensitive files...', 'info');
    await sleep(1200);
    addLog('Recon Agent', 'Detected Express.js framework, nginx server', 'success');
    updateAgent('recon', { status: 'done', task: 'Framework detected' });

    // Stage 2: Crawler
    updateAgent('crawler', { status: 'running', task: 'Mapping endpoints' });
    addLog('Crawler Agent', 'Extracting links, forms, and API endpoints...', 'info');
    await sleep(1500);
    addLog('Crawler Agent', 'Found 14 links, 3 forms, 8 API endpoints', 'success');
    updateAgent('crawler', { status: 'done', task: 'Mapped 14 endpoints' });

    // Stage 3: Attack agents (parallel-ish)
    const attackDemo = [
      { id: 'injection', name: 'Injection Agent', delay: 1200, vuln: 'SQL Injection in /api/login', sev: 'Critical', cat: 'Injection' },
      { id: 'xss', name: 'XSS Agent', delay: 1000, vuln: 'Stored XSS in comments', sev: 'High', cat: 'XSS' },
      { id: 'auth', name: 'Auth Agent', delay: 900, vuln: 'Default credentials admin:admin', sev: 'Critical', cat: 'Auth' },
      { id: 'lfi', name: 'LFI Agent', delay: 800, vuln: 'Path traversal in /download', sev: 'High', cat: 'LFI' },
      { id: 'logic', name: 'Logic Agent', delay: 1100, vuln: 'IDOR on /api/users/{id}', sev: 'Medium', cat: 'Logic' },
      { id: 'supply_chain', name: 'Supply Chain Agent', delay: 700, vuln: null, sev: 'Low', cat: 'SupplyChain' },
    ];

    for (const a of attackDemo) {
      updateAgent(a.id, { status: 'running', task: `Attacking ${targetURL}` });
    }

    for (const a of attackDemo) {
      addLog(a.name, `Testing ${targetURL} for vulnerabilities...`, 'info');
      await sleep(a.delay);
      if (a.vuln) {
        addRisk(SEVERITY_RISK[a.sev] || 5, a.cat, 1, [{ label: a.vuln.substring(0, 18), icon: VULN_ICON_MAP[a.id] || 'bug' }]);
        addLog(a.name, `🚨 [${a.sev}] ${a.vuln}`, 'error');
      } else {
        addLog(a.name, 'No vulnerabilities found', 'success');
      }
      updateAgent(a.id, { status: 'done', task: a.vuln || 'Clean' });
    }

    // Stage 4: Analysis
    updateAgent('analysis', { status: 'running', task: 'Sending to Cerebras AI' });
    addLog('Analysis Agent', 'Aggregating findings and sending to AI...', 'info');
    await sleep(2000);
    addLog('Analysis Agent', 'AI threat analysis complete', 'success');
    updateAgent('analysis', { status: 'done', task: 'Analysis complete' });

    // Stage 5: Patch
    updateAgent('patch', { status: 'running', task: 'Generating cure plan' });
    addLog('Patch Agent', 'Generating parameterized query patches, CSP headers...', 'info');
    await sleep(1500);
    addLog('Patch Agent', 'Cure plan ready with 5 patches', 'success');
    updateAgent('patch', { status: 'done', task: 'Cure plan ready' });

    addLog('System', '✓ Demo scan completed.', 'success');
    setIsRunning(false);
  }, [addLog, updateAgent, addRisk]);

  return {
    agents,
    metrics,
    logs,
    isRunning,
    scanId,
    report,
    currentStage,
    backendConnected,
    startPipeline,
  };
}
