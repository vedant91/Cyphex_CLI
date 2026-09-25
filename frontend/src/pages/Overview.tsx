import { useState, useRef } from 'react';
import { HeroSection } from '../components/HeroSection';
import { RiskChart } from '../components/charts/RiskChart';
import { VulnerabilityChart } from '../components/charts/VulnerabilityChart';
import { AgentTable } from '../components/AgentTable';
import { RemediationCard } from '../components/RemediationCard';
import { usePipelineContext } from '../contexts/PipelineContext';
import { Radar, IconContainer, getDiscoveryIcon } from '../components/ui/RadarEffect';
import { motion, AnimatePresence } from 'framer-motion';
import { useNavigate } from 'react-router-dom';
import { Wifi, WifiOff } from 'lucide-react';

// Optimized positions for discovered items on the radar to ensure zero overlap
const POSITIONS = [
  { top: "15%", left: "20%" },
  { top: "25%", left: "80%" },
  { top: "75%", left: "15%" },
  { top: "10%", left: "55%" },
  { top: "85%", left: "70%" },
  { top: "60%", left: "12%" },
  { top: "40%", left: "88%" },
  { top: "50%", left: "30%" },
  { top: "30%", left: "65%" },
  { top: "70%", left: "50%" },
];

export function Overview() {
  const { agents, metrics, logs, isRunning, startPipeline, report, currentStage, backendConnected } = usePipelineContext();
  const [hasDeployedLocal, setHasDeployedLocal] = useState(false);
  const dashboardRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  const hasDeployed = isRunning || logs.length > 1 || hasDeployedLocal;

  const handleDeploy = (url: string) => {
    setHasDeployedLocal(true);
    startPipeline(url);
    setTimeout(() => {
      dashboardRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, 100);
  };

  return (
    <div className="min-h-screen bg-black">
      <HeroSection onDeploy={handleDeploy} isRunning={isRunning} />
      
      <AnimatePresence>
        {hasDeployed && (
          <motion.div 
            initial={{ opacity: 0, y: 50 }}
            animate={{ opacity: 1, y: 0 }}
            className="dashboard-content p-12"
            ref={dashboardRef}
          >
            {/* ── Connection & Stage Status Bar ── */}
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              marginBottom: '24px', padding: '12px 20px',
              background: 'rgba(124,58,237,0.05)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '10px',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                {backendConnected ? (
                  <Wifi size={14} style={{ color: 'var(--neon-green)' }} />
                ) : (
                  <WifiOff size={14} style={{ color: 'var(--fire-red)' }} />
                )}
                <span style={{
                  fontFamily: 'var(--font-mono)', fontSize: '0.65rem',
                  color: backendConnected ? 'var(--neon-green)' : 'var(--fire-red)',
                  letterSpacing: '1px',
                }}>
                  {backendConnected ? 'LIVE · Oracle Connected' : 'SIMULATION · Backend Offline'}
                </span>
              </div>

              {isRunning && (
                <div style={{
                  fontFamily: 'var(--font-mono)', fontSize: '0.65rem',
                  color: 'var(--neon-blue)', letterSpacing: '1px',
                }}>
                  PHASE {currentStage}/5 · SWARM ACTIVE
                </div>
              )}

              {report && !isRunning && (
                <button
                  onClick={() => navigate('/report')}
                  style={{
                    fontFamily: 'var(--font-mono)', fontSize: '0.65rem',
                    color: 'var(--neon-green)', letterSpacing: '1px',
                    background: 'rgba(57,255,20,0.1)',
                    border: '1px solid rgba(57,255,20,0.2)',
                    borderRadius: '6px',
                    padding: '6px 14px',
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                  }}
                  onMouseEnter={e => { e.currentTarget.style.background = 'rgba(57,255,20,0.2)'; }}
                  onMouseLeave={e => { e.currentTarget.style.background = 'rgba(57,255,20,0.1)'; }}
                >
                  VIEW FULL REPORT →
                </button>
              )}
            </div>

            {/* Top Grid: Metrics & Radar Centerpiece */}
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-12 mb-12">
              
              {/* Left Column: Metrics */}
              <div className="lg:col-span-1 flex flex-col gap-6">
                <div className="card bg-glow-green h-full">
                  <div className="card-header flex justify-between mb-4">
                    <span className="card-title glow-green">//DATA_STREAM: RISK_BALANCE//</span>
                  </div>
                  <div className="flex flex-col flex-1 justify-center">
                    <div className="mono glow-green text-4xl font-black mb-1">
                      {metrics.riskScore}<span className="text-sm opacity-50"> / 100</span>
                    </div>
                    <div className="mono text-[10px] text-slate-500 uppercase tracking-widest mb-6">
                      SYSTEM_RISK_INDEX [{metrics.riskScore > 60 ? 'CRITICAL' : metrics.riskScore > 30 ? 'ELEVATED' : 'LOW'}]
                    </div>
                    <div className="h-32">
                      <RiskChart data={metrics.riskHistory} />
                    </div>
                  </div>
                </div>

                <div className="card bg-glow-purple h-full">
                  <div className="card-header flex justify-between mb-4">
                    <span className="card-title glow-purple">//VULN_SPECTRUM//</span>
                    <div className="mono text-[10px] px-2 py-1 bg-red-500/10 text-red-500 border border-red-500/20">
                      TOTAL: {metrics.totalVulns}
                    </div>
                  </div>
                  <div className="flex-1">
                    <VulnerabilityChart data={metrics.vulnCategories} />
                  </div>
                </div>
              </div>

              {/* Centerpiece: Radar */}
              <div className="lg:col-span-2 relative flex items-center justify-center p-4">
                <div className="absolute inset-0 bg-radial-glow opacity-20 pointer-events-none" />
                <Radar className="scale-90 md:scale-100">
                  {metrics.discoveredItems.map((item, idx) => {
                    const Icon = getDiscoveryIcon(item.icon);
                    return (
                      <IconContainer 
                        key={item.id}
                        icon={Icon}
                        text={item.label}
                        position={POSITIONS[idx % POSITIONS.length]}
                      />
                    );
                  })}
                  
                  {/* Target Node in center */}
                  <div className="relative">
                    <div className="absolute inset-0 blur-xl bg-purple-500/20 rounded-full animate-pulse" />
                    <div className="relative z-10 w-24 h-24 rounded-full border-2 border-purple-500/50 bg-black flex items-center justify-center shadow-[0_0_30px_rgba(139,92,246,0.5)]">
                      <div className="text-center">
                        <div className="mono text-[10px] text-purple-400 font-bold leading-tight">TARGET</div>
                        <div className="mono text-[8px] text-purple-400/60 leading-tight">
                          {isRunning ? 'SCANNING' : report ? 'COMPLETE' : 'NODE_X64'}
                        </div>
                      </div>
                    </div>
                  </div>
                </Radar>
                
                {/* HUD Elements */}
                <div className="absolute top-0 left-0 p-4 mono text-[10px] text-cyan-400 opacity-60">
                  <div>DEEPAGENTS: {agents.filter(a => a.status === 'done').length}/{agents.length}</div>
                  <div>VULNS: {metrics.totalVulns}</div>
                </div>
                <div className="absolute bottom-0 right-0 p-4 mono text-[10px] text-cyan-400 opacity-60 text-right">
                  <div>CMDS_EXEC: {report?.summary?.commands_executed || '—'}</div>
                  <div>PHASE: {currentStage}/5</div>
                </div>
              </div>

              {/* Right Column: Remediation */}
              <div className="lg:col-span-1">
                <RemediationCard riskScore={metrics.riskScore} />
              </div>
            </div>

            {/* Bottom Row: Logs (Full width) */}
            <div className="w-full">
              <AgentTable agents={agents} logs={logs} />
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <style>{`
        .bg-radial-glow {
          background: radial-gradient(circle at center, var(--neon-purple) 0%, transparent 70%);
        }
      `}</style>
    </div>
  );
}
