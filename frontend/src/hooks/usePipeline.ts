import { useState, useCallback, useRef, useEffect } from 'react';
import type { Agent, MetricState, LogEntry, ScanReport, WSEvent, VulnData } from '../types';
import { startScan, stopScan, connectScanWebSocket, getScan } from '../lib/api';

// ── DeepAgents swarm — display labels only; ids stay wired to the backend ──
const initialAgents: Agent[] = [
  { id: 'recon', name: 'Recon DeepAgent', task: 'Idle', status: 'idle' },
  { id: 'crawler', name: 'Surface-Map DeepAgent', task: 'Idle', status: 'idle' },
  { id: 'injection', name: 'Injection DeepAgent · SQLi/CMDi', task: 'Idle', status: 'idle' },
  { id: 'xss', name: 'XSS DeepAgent', task: 'Idle', status: 'idle' },
  { id: 'auth', name: 'Auth-Bypass DeepAgent', task: 'Idle', status: 'idle' },
  { id: 'lfi', name: 'Path-Traversal DeepAgent', task: 'Idle', status: 'idle' },
  { id: 'logic', name: 'Business-Logic DeepAgent', task: 'Idle', status: 'idle' },
  { id: 'supply_chain', name: 'Supply-Chain DeepAgent', task: 'Idle', status: 'idle' },
  { id: 'analysis', name: 'Oracle Council', task: 'Idle', status: 'idle' },
  { id: 'patch', name: 'Self-Patch DeepAgent', task: 'Idle', status: 'idle' },
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
    { id: 'sys-1', agent: 'System', message: 'DeepAgents swarm idle. Awaiting target.', timestamp: new Date().toISOString() },
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
        addLog('System', `DeepAgents swarm deployed on ${(event as any).target}`, 'info');
        break;

      case 'stage_start': {
        const e = event as any;
        setCurrentStage(e.stage);
        addLog('System', `━━━ PHASE ${e.stage}/5: ${e.name} ━━━`, 'info');
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

      case 'agent_log': {
        // Live narration from an agent (Calling AI, Reasoning, $ curl …) so the
        // user sees the scan is working, not a frozen screen.
        const e = event as any;
        const t: LogEntry['type'] =
          e.level === 'success' ? 'success'
          : (e.level === 'danger' || e.level === 'critical' || e.level === 'error') ? 'error'
          : 'info';
        addLog(e.agent_name || 'Agent', e.message, t);
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
        addLog('System', '✓ DeepAgents swarm complete. Posture scored.', 'success');
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
      message: `Deploying DeepAgents against ${targetURL}...`,
      timestamp: new Date().toISOString(),
      type: 'info',
    }]);

    try {
      // Call the backend API to start the scan
      const result = await startScan(targetURL);
      const newScanId = result.scan_id;
      setScanId(newScanId);
      setBackendConnected(true);

      addLog('System', `Swarm ${newScanId} armed. Connecting to Oracle feed...`, 'info');

      // Connect WebSocket for real-time updates
      if (wsRef.current) {
        wsRef.current.close();
      }

      wsRef.current = connectScanWebSocket(
        newScanId,
        handleWSEvent,
        () => {
          // On close — always clear the running flag (so the next run can
          // start) and pull the final report if one was produced. The old
          // `if (scanId)` guard used a stale closure value that was null on
          // the first run, so isRunning could get stuck on.
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
        },
        () => {
          addLog('System', 'WebSocket connection lost. Retrying...', 'error');
        },
      );

    } catch (err: any) {
      // Backend is unreachable — fall back to demo mode
      console.warn('Backend unreachable, running demo mode:', err.message);
      setBackendConnected(false);
      addLog('System', `⚠ Backend offline (${err.message}). Running swarm simulation...`, 'error');
      await runDemoMode(targetURL);
    }
  }, [isRunning, resetState, addLog, handleWSEvent]);

  // ── Stop / kill the running scan ──────────────────────────────

  const stopPipeline = useCallback(async () => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setIsRunning(false);
    addLog('System', '■ Scan stopped by operator.', 'error');
    if (scanId) {
      try {
        await stopScan(scanId);
      } catch {
        // Backend already gone / demo mode — the UI is stopped regardless.
      }
    }
  }, [scanId, addLog]);

  // ── Demo/fallback mode (simulated) ──────────────────────────

  const runDemoMode = useCallback(async (targetURL: string) => {
    const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

    addLog('System', `Simulation mode — no backend. Emulating the DeepAgents swarm on ${targetURL}`, 'info');

    // Phase 1: Recon
    updateAgent('recon', { status: 'running', task: `Fingerprinting ${targetURL}` });
    addLog('Recon DeepAgent', 'Fingerprinting headers, stack and sensitive files...', 'info');
    await sleep(1200);
    addLog('Recon DeepAgent', 'Detected Express.js framework, nginx server', 'success');
    updateAgent('recon', { status: 'done', task: 'Framework detected' });

    // Phase 2: Attack-surface mapping
    updateAgent('crawler', { status: 'running', task: 'Building attack-surface index' });
    addLog('Surface-Map DeepAgent', 'Indexing links, forms and API endpoints...', 'info');
    await sleep(1500);
    addLog('Surface-Map DeepAgent', 'Indexed 14 links, 3 forms, 8 API endpoints', 'success');
    updateAgent('crawler', { status: 'done', task: '14 endpoints indexed' });

    // Phase 3: Oracle-guided exploitation swarm (parallel)
    const attackDemo = [
      { id: 'injection', name: 'Injection DeepAgent', delay: 1200, vuln: 'SQL Injection in /api/login', sev: 'Critical', cat: 'Injection' },
      { id: 'xss', name: 'XSS DeepAgent', delay: 1000, vuln: 'Stored XSS in comments', sev: 'High', cat: 'XSS' },
      { id: 'auth', name: 'Auth-Bypass DeepAgent', delay: 900, vuln: 'Default credentials admin:admin', sev: 'Critical', cat: 'Auth' },
      { id: 'lfi', name: 'Path-Traversal DeepAgent', delay: 800, vuln: 'Path traversal in /download', sev: 'High', cat: 'LFI' },
      { id: 'logic', name: 'Business-Logic DeepAgent', delay: 1100, vuln: 'IDOR on /api/users/{id}', sev: 'Medium', cat: 'Logic' },
      { id: 'supply_chain', name: 'Supply-Chain DeepAgent', delay: 700, vuln: null, sev: 'Low', cat: 'SupplyChain' },
    ];

    for (const a of attackDemo) {
      updateAgent(a.id, { status: 'running', task: `Firing payloads at ${targetURL}` });
    }

    for (const a of attackDemo) {
      addLog(a.name, `Oracle generating hypotheses, firing payloads at ${targetURL}...`, 'info');
      await sleep(a.delay);
      if (a.vuln) {
        addRisk(SEVERITY_RISK[a.sev] || 5, a.cat, 1, [{ label: a.vuln.substring(0, 18), icon: VULN_ICON_MAP[a.id] || 'bug' }]);
        addLog(a.name, `🚨 [${a.sev}] CONFIRMED · ${a.vuln}`, 'error');
      } else {
        addLog(a.name, 'No exploit confirmed', 'success');
      }
      updateAgent(a.id, { status: 'done', task: a.vuln || 'Clean' });
    }

    // Phase 4: Council debate
    updateAgent('analysis', { status: 'running', task: 'Debating findings' });
    addLog('Oracle Council', 'Multi-model debate — filtering false positives...', 'info');
    await sleep(2000);
    addLog('Oracle Council', 'Council validated findings', 'success');
    updateAgent('analysis', { status: 'done', task: 'Council complete' });

    // Phase 5: Self-patch + verify
    updateAgent('patch', { status: 'running', task: 'Generating patches' });
    addLog('Self-Patch DeepAgent', 'Generating parameterized queries, CSP headers...', 'info');
    await sleep(1500);
    addLog('Self-Patch DeepAgent', 'Applied 5 patches · posture improved', 'success');
    updateAgent('patch', { status: 'done', task: 'Patched · verified' });

    addLog('System', '✓ Simulation complete.', 'success');
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
    stopPipeline,
  };
}
