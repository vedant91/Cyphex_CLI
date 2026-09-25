import { useState, useEffect } from 'react';
import { History, ExternalLink, Shield, AlertTriangle, CheckCircle, Clock } from 'lucide-react';
import { motion } from 'framer-motion';
import { listScans } from '../lib/api';
import type { ScanMeta } from '../types';

const STATUS_CONFIG: Record<string, { color: string; icon: any; label: string }> = {
  running:   { color: 'var(--neon-blue)',   icon: Clock,          label: 'RUNNING' },
  completed: { color: 'var(--neon-green)',  icon: CheckCircle,    label: 'COMPLETE' },
  error:     { color: 'var(--fire-red)',    icon: AlertTriangle,  label: 'ERROR' },
  timeout:   { color: '#ff8c00',           icon: AlertTriangle,  label: 'TIMEOUT' },
};

export function ScanHistoryPage() {
  const [scans, setScans] = useState<ScanMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadScans();
    const interval = setInterval(loadScans, 10000); // Refresh every 10s
    return () => clearInterval(interval);
  }, []);

  const loadScans = async () => {
    try {
      const data = await listScans();
      setScans(data.scans);
      setError(null);
    } catch (err: any) {
      setError('Backend unreachable. Start the API server to see scan history.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="module-page" style={{ paddingBottom: '60px' }}>
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
            <History size={20} color="var(--purple-light)" />
          </div>
          <div>
            <h2 className="module-title">//SCAN_HISTORY//</h2>
            <p className="module-desc">[ ALL_PAST_SCANS ] Previous DeepAgents swarm scans and reports</p>
          </div>
        </div>
      </div>

      {/* ── Error State ── */}
      {error && (
        <div className="card" style={{
          background: 'rgba(255,49,49,0.05)',
          border: '1px solid rgba(255,49,49,0.2)',
          padding: '20px',
          marginBottom: '20px',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <AlertTriangle size={18} style={{ color: 'var(--fire-red)' }} />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--fire-red)' }}>
              {error}
            </span>
          </div>
        </div>
      )}

      {/* ── Loading State ── */}
      {loading && (
        <div style={{ textAlign: 'center', padding: '60px 0' }}>
          <div style={{
            width: 32, height: 32, borderRadius: '50%',
            border: '2px solid var(--purple-light)', borderTopColor: 'transparent',
            animation: 'spin 1s linear infinite',
            margin: '0 auto 16px',
          }} />
          <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-dim)' }}>
            LOADING SCAN HISTORY...
          </p>
          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        </div>
      )}

      {/* ── Empty State ── */}
      {!loading && !error && scans.length === 0 && (
        <div style={{ textAlign: 'center', padding: '80px 0' }}>
          <Shield size={48} style={{ color: 'var(--purple-light)', opacity: 0.3, margin: '0 auto 20px' }} />
          <h3 style={{ fontFamily: 'var(--font-display)', color: '#fff', marginBottom: '8px' }}>No Scans Yet</h3>
          <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-dim)' }}>
            Start a scan from the Overview page to see results here.
          </p>
        </div>
      )}

      {/* ── Scan List ── */}
      {scans.map((scan, idx) => {
        const config = STATUS_CONFIG[scan.status] || STATUS_CONFIG.error;
        const StatusIcon = config.icon;
        const vulnCount = scan.report?.summary?.total_vulns ?? '—';
        const critCount = scan.report?.summary?.critical ?? 0;

        return (
          <motion.div
            key={scan.scan_id}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.05 }}
            className="card"
            style={{
              marginBottom: '12px',
              padding: '18px 22px',
              cursor: 'pointer',
              transition: 'border-color 0.2s',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              {/* Status icon */}
              <div style={{
                width: 36, height: 36, borderRadius: '8px',
                background: `${config.color}15`,
                border: `1px solid ${config.color}33`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <StatusIcon size={18} style={{ color: config.color }} />
              </div>

              {/* Info */}
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
                  <span style={{ fontFamily: 'var(--font-sans)', fontWeight: 700, color: '#fff', fontSize: '0.95rem' }}>
                    {scan.target_url}
                  </span>
                  <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: '0.6rem', fontWeight: 700,
                    padding: '2px 8px', borderRadius: '4px',
                    background: `${config.color}15`, color: config.color, border: `1px solid ${config.color}33`,
                  }}>
                    {config.label}
                  </span>
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: 'var(--text-dim)', display: 'flex', gap: '16px' }}>
                  <span>ID: {scan.scan_id}</span>
                  <span>Started: {new Date(scan.started_at).toLocaleString()}</span>
                  {scan.report?.scan_time && <span>Duration: {scan.report.scan_time}</span>}
                </div>
              </div>

              {/* Vuln count */}
              <div style={{ textAlign: 'center', minWidth: '70px' }}>
                <div style={{
                  fontFamily: 'var(--font-mono)', fontSize: '1.4rem', fontWeight: 900,
                  color: critCount > 0 ? 'var(--fire-red)' : typeof vulnCount === 'number' && vulnCount > 0 ? '#ff8c00' : 'var(--neon-green)',
                }}>
                  {vulnCount}
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.55rem', color: 'var(--text-dim)', letterSpacing: '1px' }}>
                  VULNS
                </div>
              </div>
            </div>

            {/* Error display */}
            {scan.error && (
              <div style={{
                marginTop: '10px', padding: '8px 12px',
                background: 'rgba(255,49,49,0.08)', borderRadius: '6px',
                fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--fire-red)',
              }}>
                Error: {scan.error}
              </div>
            )}
          </motion.div>
        );
      })}
    </div>
  );
}
