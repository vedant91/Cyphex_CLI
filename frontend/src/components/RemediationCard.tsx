import { FileText, ShieldCheck, Zap } from 'lucide-react';
import './RemediationCard.css';

interface Props {
  riskScore: number;
}

export function RemediationCard({ riskScore }: Props) {
  const securityScore = 100 - riskScore;
  
  return (
    <div className="card remediation-card">
      <div className="card-header">
        <span className="card-title mono">//PROTOCOL: SELF-PATCH_STRATEGY//</span>
      </div>
      
      <div className="strategy-status">
        <div className="status-label mono">POSTURE AFTER SELF-PATCH</div>
        <div className="progress-meter">
          <div 
            className="progress-fill bg-glow-green" 
            style={{ width: `${securityScore}%` }}
          ></div>
        </div>
        <div className="status-meta mono">
          <span>PRIORITY: HIGH</span>
          <span className="glow-green">POSTURE: {securityScore}</span>
        </div>
      </div>

      <div className="btn-grid">
        <button className="hacker-btn mono" onClick={() => alert('Generating Threat Deck Report...')}>
          <FileText size={16} /> //REPORT: THREAT_DECK//
        </button>
        <button className="hacker-btn mono accent-purple" onClick={() => alert('Tuning patch engine...')}>
          <Zap size={16} /> //TUNE: PATCH_ENGINE//
        </button>
        <button className="hacker-btn mono accent-blue" onClick={() => alert('Deploying self-patches...')}>
          <ShieldCheck size={16} /> //DEPLOY: SELF-PATCH//
        </button>
      </div>
    </div>
  );
}
