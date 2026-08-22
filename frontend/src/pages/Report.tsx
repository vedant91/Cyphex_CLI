import { usePipelineContext } from '../contexts/PipelineContext';
import { Shield, AlertTriangle, CheckCircle, ArrowDown, Bug, FileText, Zap } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useState } from 'react';
import type { VulnData } from '../types';

const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#ff3131',
  High: '#ff8c00',
  Medium: '#ffbd2e',
  Low: '#00e5ff',
};

const SEVERITY_BG: Record<string, string> = {
  Critical: 'rgba(255,49,49,0.1)',
  High: 'rgba(255,140,0,0.1)',
  Medium: 'rgba(255,189,46,0.1)',
  Low: 'rgba(0,229,255,0.1)',
};

export function ReportPage() {
  const { report, isRunning, scanId } = usePipelineContext();
  const [expandedVuln, setExpandedVuln] = useState<number | null>(null);

  if (!report && !isRunning) {
    return (
      <div className="module-page">
        <div style={{ textAlign: 'center', padding: '80px 0' }}>
          <Shield size={64} style={{ color: 'var(--purple-light)', opacity: 0.3, margin: '0 auto 24px' }} />
          <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.5rem', color: '#fff', marginBottom: '12px' }}>
            No Scan Report Available
          </h2>
          <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-dim)', letterSpacing: '1px' }}>
            Start a scan from the Overview page to generate a report.
          </p>
        </div>
      </div>
    );
  }

  if (isRunning && !report) {
    return (
      <div className="module-page">
        <div style={{ textAlign: 'center', padding: '80px 0' }}>
          <div style={{
            width: 40, height: 40, borderRadius: '50%',
            border: '3px solid var(--purple-light)', borderTopColor: 'transparent',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 24px',
          }} />
          <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.5rem', color: '#fff', marginBottom: '12px' }}>
            Scan In Progress...
          </h2>
          <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-dim)', letterSpacing: '1px' }}>
            [ SCAN_ID: {scanId} ] · Report will appear when scan completes.
          </p>
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>
      </div>
    );
  }

  if (!report) return null;

  const { summary, vulnerabilities, cure_plan } = report;

  return (
    <div className="module-page" style={{ paddingBottom: '60px' }}>
      {/* ── Header ── */}
      <div style={{ marginBottom: '32px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '8px' }}>
          <div style={{
            width: 40, height: 40,
            background: 'linear-gradient(135deg, #7c3aed, #a855f7)',
            borderRadius: '10px',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <FileText size={20} color="#fff" />
          </div>
          <div>
            <h2 className="module-title">//SCAN_REPORT//</h2>
            <p className="module-desc">[ TARGET: {report.target} ] · [ DURATION: {report.scan_time} ] · [ ID: {report.scan_id} ]</p>
          </div>
        </div>
      </div>

      {/* ── Summary Cards ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '14px', marginBottom: '32px' }}>
        {[
          { label: 'SCORE', value: `${summary.security_score}/100`, color: '#7dabff', bg: 'rgba(59,130,246,0.1)' },
          { label: 'TOTAL', value: summary.total_vulns, color: '#fff', bg: 'rgba(124,58,237,0.1)' },
          { label: 'CRITICAL', value: summary.critical, color: SEVERITY_COLORS.Critical, bg: SEVERITY_BG.Critical },
          { label: 'HIGH', value: summary.high, color: SEVERITY_COLORS.High, bg: SEVERITY_BG.High },
          { label: 'MEDIUM', value: summary.medium, color: SEVERITY_COLORS.Medium, bg: SEVERITY_BG.Medium },
          { label: 'LOW', value: summary.low, color: SEVERITY_COLORS.Low, bg: SEVERITY_BG.Low },
          { label: 'COMMANDS', value: summary.commands_executed, color: 'var(--neon-green)', bg: 'rgba(57,255,20,0.06)' },
          { label: 'ENDPOINTS', value: summary.endpoints_found, color: 'var(--neon-blue)', bg: 'rgba(0,229,255,0.06)' },
          { label: 'FORMS', value: summary.forms_found, color: 'var(--purple-light)', bg: 'rgba(168,85,247,0.08)' },
        ].map(card => (
          <div key={card.label} className="card" style={{ background: card.bg, padding: '18px', textAlign: 'center' }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.6rem', color: 'var(--text-dim)', letterSpacing: '2px', marginBottom: '8px' }}>
              {card.label}
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '2rem', fontWeight: 900, color: card.color }}>
              {card.value}
            </div>
          </div>
        ))}
      </div>

      {/* ── Tech Stack ── */}
      <div className="card" style={{ marginBottom: '24px', padding: '20px' }}>
        <div className="card-header" style={{ marginBottom: '14px' }}>
          <span className="card-title mono">//TARGET_FINGERPRINT//</span>
        </div>
        <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
          <div><span style={{ color: 'var(--text-dim)' }}>FRAMEWORK:</span> <span style={{ color: '#fff' }}>{report.framework || 'Unknown'}</span></div>
          <div><span style={{ color: 'var(--text-dim)' }}>DATABASE:</span> <span style={{ color: '#fff' }}>{report.database || 'Unknown'}</span></div>
          <div><span style={{ color: 'var(--text-dim)' }}>SERVER:</span> <span style={{ color: '#fff' }}>{report.server || 'Unknown'}</span></div>
          {report.technologies?.length > 0 && (
            <div><span style={{ color: 'var(--text-dim)' }}>TECH:</span> <span style={{ color: 'var(--purple-light)' }}>{report.technologies.join(', ')}</span></div>
          )}
        </div>
      </div>

      {/* ── Vulnerability List ── */}
      <div className="card" style={{ padding: 0, overflow: 'hidden', marginBottom: '24px' }}>
        <div style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border-subtle)',
          background: 'rgba(124,58,237,0.06)',
        }}>
          <span className="card-title mono">//VULNERABILITY_FINDINGS · {vulnerabilities.length} TOTAL//</span>
        </div>

        <div style={{ maxHeight: '600px', overflowY: 'auto' }}>
          {vulnerabilities.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center' }}>
              <CheckCircle size={32} style={{ color: 'var(--neon-green)', margin: '0 auto 12px' }} />
              <p style={{ fontFamily: 'var(--font-mono)', color: 'var(--neon-green)', fontSize: '0.8rem' }}>
                NO VULNERABILITIES FOUND — TARGET IS CLEAN
              </p>
            </div>
          ) : (
            vulnerabilities.map((vuln: VulnData, idx: number) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: idx * 0.05 }}
                style={{
                  padding: '16px 20px',
                  borderBottom: '1px solid var(--border-subtle)',
                  cursor: 'pointer',
                  background: expandedVuln === idx ? 'rgba(124,58,237,0.05)' : 'transparent',
                  transition: 'background 0.2s',
                }}
                onClick={() => setExpandedVuln(expandedVuln === idx ? null : idx)}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <span style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.65rem',
                    fontWeight: 700,
                    padding: '4px 10px',
                    borderRadius: '4px',
                    background: SEVERITY_BG[vuln.severity],
                    color: SEVERITY_COLORS[vuln.severity],
                    border: `1px solid ${SEVERITY_COLORS[vuln.severity]}33`,
                    minWidth: '70px',
                    textAlign: 'center',
                  }}>
                    {vuln.severity.toUpperCase()}
                  </span>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontFamily: 'var(--font-sans)', fontWeight: 700, color: '#fff', fontSize: '0.9rem' }}>
                      {vuln.name}
                    </div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--text-dim)', marginTop: '2px' }}>
                      {vuln.endpoint} · CVSS: {vuln.cvss_score}/10
                    </div>
                  </div>
                  <ArrowDown size={14} style={{
                    color: 'var(--text-dim)',
                    transform: expandedVuln === idx ? 'rotate(180deg)' : 'rotate(0deg)',
                    transition: 'transform 0.2s',
                  }} />
                </div>

                <AnimatePresence>
                  {expandedVuln === idx && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      style={{ overflow: 'hidden', marginTop: '14px' }}
                    >
                      <div style={{
                        background: 'rgba(0,0,0,0.4)',
                        borderRadius: '8px',
                        padding: '16px',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.7rem',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '10px',
                      }}>
                        {vuln.description && (
                          <div><span style={{ color: 'var(--text-dim)' }}>DESCRIPTION:</span> <span style={{ color: 'var(--text-main)' }}>{vuln.description}</span></div>
                        )}
                        {vuln.payload && (
                          <div><span style={{ color: 'var(--fire-red)' }}>PAYLOAD:</span> <span style={{ color: '#fff', wordBreak: 'break-all' }}>{vuln.payload}</span></div>
                        )}
                        {vuln.evidence && (
                          <div><span style={{ color: 'var(--neon-blue)' }}>EVIDENCE:</span> <span style={{ color: 'var(--text-main)', wordBreak: 'break-all' }}>{vuln.evidence}</span></div>
                        )}
                        {vuln.dumped_data && (
                          <div><span style={{ color: 'var(--fire-red)' }}>DATA EXTRACTED:</span> <span style={{ color: '#fff', wordBreak: 'break-all' }}>{vuln.dumped_data}</span></div>
                        )}
                        {vuln.rce_output && (
                          <div><span style={{ color: 'var(--fire-red)' }}>RCE OUTPUT:</span> <span style={{ color: '#fff', wordBreak: 'break-all' }}>{vuln.rce_output}</span></div>
                        )}
                        {vuln.fix && (
                          <div style={{ marginTop: '6px', padding: '10px', background: 'rgba(57,255,20,0.05)', borderRadius: '6px', border: '1px solid rgba(57,255,20,0.15)' }}>
                            <span style={{ color: 'var(--neon-green)' }}>FIX:</span> <span style={{ color: 'var(--text-main)' }}>{vuln.fix}</span>
                          </div>
                        )}
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </motion.div>
            ))
          )}
        </div>
      </div>

      {/* ── Cure Plan ── */}
      {cure_plan && (
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{
            padding: '16px 20px',
            borderBottom: '1px solid var(--border-subtle)',
            background: 'rgba(57,255,20,0.04)',
          }}>
            <span className="card-title mono" style={{ color: 'var(--neon-green)' }}>
              //CURE_PLAN · {cure_plan.patches?.length || 0} PATCHES//
            </span>
          </div>

          <div style={{ padding: '20px' }}>
            {cure_plan.patches?.map((patch: any, idx: number) => (
              <div key={idx} style={{
                padding: '14px',
                marginBottom: '12px',
                background: 'rgba(0,0,0,0.3)',
                borderRadius: '8px',
                border: '1px solid var(--border-subtle)',
              }}>
                <div style={{ fontFamily: 'var(--font-sans)', fontWeight: 700, color: '#fff', marginBottom: '6px' }}>
                  <Zap size={14} style={{ display: 'inline-block', marginRight: '6px', color: 'var(--neon-green)' }} />
                  {patch.vuln || `Patch ${idx + 1}`}
                </div>
                {patch.explanation && (
                  <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '8px' }}>{patch.explanation}</p>
                )}
                {patch.code && (
                  <pre style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.68rem',
                    color: 'var(--neon-green)',
                    background: 'rgba(0,0,0,0.6)',
                    padding: '12px',
                    borderRadius: '6px',
                    overflow: 'auto',
                    maxHeight: '200px',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                  }}>{patch.code}</pre>
                )}
              </div>
            ))}

            {cure_plan.security_checklist?.length > 0 && (
              <div style={{ marginTop: '16px' }}>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--neon-green)', marginBottom: '10px', letterSpacing: '1px' }}>
                  SECURITY CHECKLIST:
                </div>
                {cure_plan.security_checklist.map((item: string, idx: number) => (
                  <div key={idx} style={{
                    display: 'flex', alignItems: 'flex-start', gap: '8px',
                    fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-main)',
                    marginBottom: '6px',
                  }}>
                    <CheckCircle size={12} style={{ color: 'var(--neon-green)', marginTop: '2px', flexShrink: 0 }} />
                    <span>{item}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
