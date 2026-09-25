import { usePipelineContext } from '../contexts/PipelineContext';
import { Globe, Target, Bug, Activity, CheckCircle, Heart, Lock, FileWarning, Eye, Box } from 'lucide-react';

interface Props {
  agentId: string;
  agentLabel: string;
  agentName: string;
  description: string;
  icon: any;
  accentColor?: string;
}

export function ModuleLayout({ agentId, agentLabel, agentName, description, icon: Icon, accentColor = 'var(--purple-light)' }: Props) {
  const { agents, logs } = usePipelineContext();
  const agent = agents.find(a => a.id === agentId);
  const agentLogs = logs.filter(l => l.agent === agentLabel || l.agent === 'System');

  const statusColors: Record<string, string> = {
    running: 'var(--neon-blue)',
    done:    'var(--neon-green)',
    error:   'var(--fire-red)',
    idle:    'var(--text-dim)',
  };
  const statusColor = statusColors[agent?.status || 'idle'];

  return (
    <div className="module-page">
      {/* ── Header ── */}
      <div style={{ marginBottom: '28px' }}>
        <div className="module-header">
          <div style={{
            width: 40, height: 40,
            background: 'rgba(124,58,237,0.15)',
            border: '1px solid rgba(124,58,237,0.3)',
            borderRadius: '10px',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Icon size={20} color={accentColor} />
          </div>
          <div>
            <h2 className="module-title">//{agentName.toUpperCase().replace(/ /g, '_')}//</h2>
            <p className="module-desc">[ DEEPAGENT ] {description}</p>
          </div>
        </div>

        <div className="module-status-row">
          <div className="status-block" style={{ borderColor: `${statusColor}44` }}>
            <div className="status-block-label">STATUS</div>
            <div className="status-block-value" style={{ color: statusColor }}>
              [{agent?.status?.toUpperCase() || 'IDLE'}]
            </div>
          </div>
          <div className="status-block">
            <div className="status-block-label">HYPOTHESIS</div>
            <div className="status-block-value" style={{ color: 'var(--text-main)', fontSize: '0.78rem' }}>
              {agent?.task || 'STANDBY'}
            </div>
          </div>
        </div>
      </div>

      {/* ── Terminal log ── */}
      <div className="card" style={{
        background: 'rgba(7,0,16,0.9)',
        border: '1px solid var(--border-subtle)',
        padding: 0,
        borderRadius: '10px',
        overflow: 'hidden',
      }}>
        {/* Terminal title bar */}
        <div style={{
          padding: '12px 20px',
          borderBottom: '1px solid var(--border-subtle)',
          background: 'rgba(124,58,237,0.06)',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.68rem',
          color: 'var(--purple-light)',
          letterSpacing: '1px',
        }}>
          {/* Traffic light dots */}
          <div style={{ display: 'flex', gap: '5px' }}>
            {['#ff5f56','#ffbd2e','#27c93f'].map(c => (
              <div key={c} style={{ width: 8, height: 8, borderRadius: '50%', background: c, opacity: 0.7 }} />
            ))}
          </div>
          <span style={{ marginLeft: '6px' }}>
            //AGENT_TERMINAL_FEED// · MODULE: {agentName.toUpperCase()}
          </span>
          <span style={{
            marginLeft: 'auto',
            width: 7, height: 7, borderRadius: '50%',
            background: agent?.status === 'running' ? 'var(--neon-green)' : 'var(--text-dim)',
            display: 'inline-block',
            boxShadow: agent?.status === 'running' ? '0 0 6px var(--neon-green)' : 'none',
          }} />
        </div>

        {/* Log body */}
        <div style={{
          minHeight: '350px',
          maxHeight: '480px',
          overflowY: 'auto',
          padding: '18px 20px',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.7rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '7px',
        }}>
          {agentLogs.length === 0 ? (
            <span style={{ color: 'var(--text-dim)', opacity: 0.45, letterSpacing: '1px' }}>
              WAITING FOR {agentName.toUpperCase()} EXECUTION...
            </span>
          ) : (
            agentLogs.map(log => (
              <div key={log.id} style={{ display: 'flex', gap: '12px' }}>
                <span style={{ color: 'var(--text-dim)', whiteSpace: 'nowrap' }}>
                  [{new Date(log.timestamp).toLocaleTimeString()}]
                </span>
                <span style={{ color: log.type === 'error' ? 'var(--fire-red)' : log.type === 'success' ? 'var(--neon-green)' : accentColor }}>[{log.agent}]</span>
                <span style={{ color: log.type === 'error' ? 'var(--fire-red)' : 'var(--text-main)', wordBreak: 'break-all' }}>{log.message}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

// ── Agent Page Exports (matching all 11 backend agents) ──────

export const ReconPage = () => <ModuleLayout
  agentId="recon" agentLabel="Recon DeepAgent" agentName="Recon DeepAgent"
  description="Fingerprints headers, tech stack, and probes sensitive files (.env, .git/HEAD, robots.txt)."
  icon={Activity} accentColor="var(--neon-blue)"
/>;

export const CrawlerPage = () => <ModuleLayout
  agentId="crawler" agentLabel="Surface-Map DeepAgent" agentName="Surface-Map DeepAgent"
  description="Builds the attack-surface index — paths, API endpoints, forms, and parameters for oracle-guided targeting."
  icon={Globe} accentColor="var(--neon-green)"
/>;

export const InjectionPage = () => <ModuleLayout
  agentId="injection" agentLabel="Injection DeepAgent (SQLi + CMDi)" agentName="Injection DeepAgent"
  description="Oracle-guided SQL Injection and Command Injection exploitation. Blind, error-based, and UNION attacks."
  icon={Target} accentColor="var(--purple-light)"
/>;

export const XSSPage = () => <ModuleLayout
  agentId="xss" agentLabel="XSS DeepAgent" agentName="XSS DeepAgent"
  description="Hypothesis-driven testing of DOM structure and reflection for stored, reflected, and DOM-based XSS."
  icon={Bug} accentColor="var(--fire-red)"
/>;

export const AuthPage = () => <ModuleLayout
  agentId="auth" agentLabel="Auth-Bypass DeepAgent" agentName="Auth-Bypass DeepAgent"
  description="Default-credential attacks, JWT weaknesses, username enumeration, and session hijacking."
  icon={Lock} accentColor="var(--neon-blue)"
/>;

export const LFIPage = () => <ModuleLayout
  agentId="lfi" agentLabel="Path-Traversal DeepAgent" agentName="Path-Traversal DeepAgent"
  description="Path traversal, file-upload bypasses, XXE injection, and local file inclusion."
  icon={FileWarning} accentColor="var(--purple-light)"
/>;

export const LogicPage = () => <ModuleLayout
  agentId="logic" agentLabel="Business-Logic DeepAgent" agentName="Business-Logic DeepAgent"
  description="IDOR, SSRF, CORS misconfigurations, mass assignment, and business-logic exploitation."
  icon={Eye} accentColor="var(--neon-green)"
/>;

export const SupplyChainPage = () => <ModuleLayout
  agentId="supply_chain" agentLabel="Supply-Chain DeepAgent" agentName="Supply-Chain DeepAgent"
  description="Detects exposed manifests, known CVEs in dependencies, and typosquatting risks."
  icon={Box} accentColor="var(--fire-red)"
/>;

export const AnalysisPage = () => <ModuleLayout
  agentId="analysis" agentLabel="Oracle Council" agentName="Oracle Council"
  description="Multi-model council debate that validates confirmed findings and filters false positives."
  icon={CheckCircle} accentColor="var(--neon-green)"
/>;

export const CurePlannerPage = () => {
  const { report, agents, logs } = usePipelineContext();
  const agent = agents.find(a => a.id === 'patch');
  const curePlan = report?.cure_plan;

  const statusColors: Record<string, string> = {
    running: 'var(--neon-blue)',
    done:    'var(--neon-green)',
    error:   'var(--fire-red)',
    idle:    'var(--text-dim)',
  };
  const statusColor = statusColors[agent?.status || 'idle'];

  return (
    <div className="module-page">
      {/* ── Header ── */}
      <div style={{ marginBottom: '28px' }}>
        <div className="module-header">
          <div style={{
            width: 40, height: 40,
            background: 'rgba(124,58,237,0.15)',
            border: '1px solid rgba(124,58,237,0.3)',
            borderRadius: '10px',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Heart size={20} color="var(--purple-light)" />
          </div>
          <div>
            <h2 className="module-title">//SELF-PATCH//</h2>
            <p className="module-desc">[ DEEPAGENT ] Generates framework-specific code patches and a structured cure plan for all findings.</p>
          </div>
        </div>

        <div className="module-status-row">
          <div className="status-block" style={{ borderColor: `${statusColor}44` }}>
            <div className="status-block-label">STATUS</div>
            <div className="status-block-value" style={{ color: statusColor }}>
              [{agent?.status?.toUpperCase() || 'IDLE'}]
            </div>
          </div>
          <div className="status-block">
            <div className="status-block-label">PATCHES</div>
            <div className="status-block-value" style={{ color: 'var(--neon-green)' }}>
              {curePlan?.patches?.length || 0}
            </div>
          </div>
          <div className="status-block">
            <div className="status-block-label">CHECKLIST</div>
            <div className="status-block-value" style={{ color: 'var(--neon-blue)' }}>
              {curePlan?.security_checklist?.length || 0}
            </div>
          </div>
        </div>
      </div>

      {/* ── Cure Plan Content ── */}
      {curePlan ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Patches */}
          {curePlan.patches && curePlan.patches.length > 0 && (
            <div className="card" style={{ background: 'rgba(7,0,16,0.9)', padding: 0, borderRadius: '10px', overflow: 'hidden' }}>
              <div style={{
                padding: '14px 20px',
                borderBottom: '1px solid var(--border-subtle)',
                background: 'rgba(57,255,20,0.04)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.72rem',
                color: 'var(--neon-green)',
                letterSpacing: '1.5px',
                display: 'flex', alignItems: 'center', gap: '8px',
              }}>
                <Heart size={14} /> //CODE_PATCHES// [{curePlan.patches.length} FIXES]
              </div>
              <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
                {curePlan.patches.map((patch, idx) => (
                  <div key={idx} style={{
                    background: 'rgba(124,58,237,0.04)',
                    border: '1px solid rgba(124,58,237,0.15)',
                    borderRadius: '8px',
                    overflow: 'hidden',
                  }}>
                    {/* Patch header */}
                    <div style={{
                      padding: '12px 16px',
                      borderBottom: '1px solid rgba(124,58,237,0.1)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                        <span style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: '0.75rem',
                          fontWeight: 700,
                          color: 'var(--text-main)',
                        }}>
                          {idx + 1}. {patch.vuln}
                        </span>
                        <span style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: '0.62rem',
                          color: 'var(--text-muted)',
                          letterSpacing: '1px',
                        }}>
                          FIX TYPE: {patch.fix_type}
                        </span>
                      </div>
                      <span style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.58rem',
                        padding: '3px 10px',
                        background: 'rgba(57,255,20,0.1)',
                        border: '1px solid rgba(57,255,20,0.2)',
                        borderRadius: '4px',
                        color: 'var(--neon-green)',
                        letterSpacing: '1px',
                      }}>
                        PATCH
                      </span>
                    </div>

                    {/* Explanation */}
                    <div style={{
                      padding: '12px 16px',
                      fontFamily: 'var(--font-sans)',
                      fontSize: '0.78rem',
                      color: 'var(--text-muted)',
                      lineHeight: 1.6,
                      borderBottom: patch.code ? '1px solid rgba(124,58,237,0.1)' : 'none',
                    }}>
                      {patch.explanation}
                    </div>

                    {/* Code block */}
                    {patch.code && (
                      <div style={{
                        padding: '14px 16px',
                        background: 'rgba(0,0,0,0.4)',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.68rem',
                        color: 'var(--neon-green)',
                        lineHeight: 1.6,
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                        overflowX: 'auto',
                        maxHeight: '300px',
                        overflowY: 'auto',
                      }}>
                        {patch.code}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Security Checklist */}
          {curePlan.security_checklist && curePlan.security_checklist.length > 0 && (
            <div className="card" style={{ background: 'rgba(7,0,16,0.9)', padding: 0, borderRadius: '10px', overflow: 'hidden' }}>
              <div style={{
                padding: '14px 20px',
                borderBottom: '1px solid var(--border-subtle)',
                background: 'rgba(0,229,255,0.04)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.72rem',
                color: 'var(--neon-blue)',
                letterSpacing: '1.5px',
                display: 'flex', alignItems: 'center', gap: '8px',
              }}>
                <CheckCircle size={14} /> //SECURITY_CHECKLIST// [{curePlan.security_checklist.length} ITEMS]
              </div>
              <div style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {curePlan.security_checklist.map((item, idx) => (
                  <div key={idx} style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '10px',
                    padding: '8px 12px',
                    background: 'rgba(0,229,255,0.03)',
                    borderRadius: '6px',
                    border: '1px solid rgba(0,229,255,0.08)',
                  }}>
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.65rem',
                      color: 'var(--neon-blue)',
                      fontWeight: 700,
                      flexShrink: 0,
                      marginTop: '1px',
                    }}>
                      [{String(idx + 1).padStart(2, '0')}]
                    </span>
                    <span style={{
                      fontFamily: 'var(--font-sans)',
                      fontSize: '0.78rem',
                      color: 'var(--text-main)',
                      lineHeight: 1.5,
                    }}>
                      {item}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      ) : (
        /* Fallback: show agent terminal log while scan is running */
        <div className="card" style={{
          background: 'rgba(7,0,16,0.9)',
          border: '1px solid var(--border-subtle)',
          padding: 0, borderRadius: '10px', overflow: 'hidden',
        }}>
          <div style={{
            padding: '12px 20px',
            borderBottom: '1px solid var(--border-subtle)',
            background: 'rgba(124,58,237,0.06)',
            display: 'flex', alignItems: 'center', gap: '10px',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.68rem',
            color: 'var(--purple-light)',
            letterSpacing: '1px',
          }}>
            <div style={{ display: 'flex', gap: '5px' }}>
              {['#ff5f56','#ffbd2e','#27c93f'].map(c => (
                <div key={c} style={{ width: 8, height: 8, borderRadius: '50%', background: c, opacity: 0.7 }} />
              ))}
            </div>
            <span style={{ marginLeft: '6px' }}>
              //AGENT_TERMINAL_FEED// · MODULE: PATCH PLANNER
            </span>
          </div>
          <div style={{
            minHeight: '350px',
            maxHeight: '480px',
            overflowY: 'auto',
            padding: '18px 20px',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.7rem',
            display: 'flex', flexDirection: 'column', gap: '7px',
          }}>
            {logs.filter(l => l.agent === 'Patch Agent' || l.agent === 'System').length === 0 ? (
              <span style={{ color: 'var(--text-dim)', opacity: 0.45, letterSpacing: '1px' }}>
                WAITING FOR SCAN TO COMPLETE...
                <br /><br />
                Run a full CYPHEX scan to generate the cure plan.
                <br />
                The cure plan includes code patches and a security checklist.
              </span>
            ) : (
              logs.filter(l => l.agent === 'Patch Agent' || l.agent === 'System').map(log => (
                <div key={log.id} style={{ display: 'flex', gap: '12px' }}>
                  <span style={{ color: 'var(--text-dim)', whiteSpace: 'nowrap' }}>
                    [{new Date(log.timestamp).toLocaleTimeString()}]
                  </span>
                  <span style={{ color: log.type === 'error' ? 'var(--fire-red)' : log.type === 'success' ? 'var(--neon-green)' : 'var(--purple-light)' }}>[{log.agent}]</span>
                  <span style={{ color: log.type === 'error' ? 'var(--fire-red)' : 'var(--text-main)', wordBreak: 'break-all' }}>{log.message}</span>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      <style>{`
        .module-page {
          padding: 32px 40px;
          min-height: 100vh;
          overflow-y: auto;
        }
        .module-header {
          display: flex;
          align-items: center;
          gap: 14px;
          margin-bottom: 16px;
        }
        .module-title {
          font-family: var(--font-mono);
          font-size: 1rem;
          font-weight: 700;
          color: var(--purple-light);
          letter-spacing: 2px;
          margin: 0;
        }
        .module-desc {
          font-family: var(--font-mono);
          font-size: 0.65rem;
          color: var(--text-dim);
          letter-spacing: 0.5px;
          margin: 2px 0 0;
        }
        .module-status-row {
          display: flex;
          gap: 12px;
          flex-wrap: wrap;
        }
        .status-block {
          background: var(--bg-card);
          border: 1px solid var(--border-subtle);
          border-radius: 8px;
          padding: 10px 16px;
          min-width: 110px;
        }
        .status-block-label {
          font-family: var(--font-mono);
          font-size: 0.55rem;
          color: var(--text-dim);
          letter-spacing: 1.5px;
          margin-bottom: 4px;
        }
        .status-block-value {
          font-family: var(--font-mono);
          font-size: 0.85rem;
          font-weight: 700;
        }
      `}</style>
    </div>
  );
};

// ── Kept for backward compatibility ──
export const SQLiPage = InjectionPage;
