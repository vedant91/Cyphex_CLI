import { useEffect, useRef, useMemo } from 'react';
import { Target, Bug, Globe, Activity, Terminal, Lock, FileWarning, Eye, Box, Shield, Zap } from 'lucide-react';
import type { Agent, LogEntry } from '../types';
import './AgentTable.css';

interface Props {
  agents: Agent[];
  logs: LogEntry[];
}

export function AgentTable({ agents, logs }: Props) {
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logs]);

  const getAgentIcon = (name: string) => {
    const n = name.toLowerCase();
    if (n.includes('recon'))     return <Activity size={16} className="glow-blue" />;
    if (n.includes('crawler'))   return <Globe size={16} className="glow-green" />;
    if (n.includes('injection')) return <Target size={16} className="glow-purple" />;
    if (n.includes('xss'))       return <Bug size={16} className="glow-red" />;
    if (n.includes('auth'))      return <Lock size={16} className="glow-blue" />;
    if (n.includes('lfi'))       return <FileWarning size={16} className="glow-purple" />;
    if (n.includes('logic'))     return <Eye size={16} className="glow-green" />;
    if (n.includes('supply'))    return <Box size={16} className="glow-red" />;
    if (n.includes('analysis'))  return <Shield size={16} className="glow-green" />;
    if (n.includes('patch'))     return <Zap size={16} className="glow-purple" />;
    return <Activity size={16} className="glow-blue" />;
  };

  const getStatusClass = (status: string) => {
    switch (status) {
      case 'running': return 'status-running';
      case 'done': return 'status-done';
      case 'error': return 'status-error';
      default: return 'status-idle';
    }
  };

  const getLogLineClass = (type?: string) => {
    switch (type) {
      case 'error': return 'log-error';
      case 'success': return 'log-success';
      default: return '';
    }
  };

  const terminalLogs = useMemo(() => {
    return logs.slice().slice(-80); // Keep last 80 for performance
  }, [logs]);

  return (
    <div className="card agent-card">
      <div className="card-header">
        <span className="card-title mono">//LOG: DEEPAGENTS_SWARM_TRACE//</span>
        <div className="terminal-header mono">
          [ DEEPAGENTS: {agents.filter(a => a.status === 'done').length}/{agents.length} ] [ LOGS: {logs.length} ]
        </div>
      </div>
      
      <div className="terminal-container scrollbar-hidden">
        <table className="agent-table mono">
          <thead>
            <tr>
              <th>DEEPAGENT</th>
              <th>HYPOTHESIS</th>
              <th>STATUS</th>
            </tr>
          </thead>
          <tbody>
            {agents.map((agent) => (
              <tr key={agent.id}>
                <td className="agent-unit">
                  <div className="glitch-wrapper">
                    {getAgentIcon(agent.name)}
                    <span className="unit-name">{agent.name}</span>
                  </div>
                </td>
                <td className="agent-vector" style={{ maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {agent.task}
                </td>
                <td>
                  <span className={`status-badge ${getStatusClass(agent.status)}`}>
                    [{agent.status.toUpperCase()}]
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        <div className="terminal-console mono">
          <div className="console-header">
            <Terminal size={14} /> //ORACLE_LIVE_FEED//
          </div>
          <div className="console-body scrollbar-hidden" ref={logRef}>
            {terminalLogs.map((log) => (
              <div key={log.id} className={`console-line ${log.type || ''} ${getLogLineClass(log.type)}`}>
                <span className="line-time">[{new Date(log.timestamp).toLocaleTimeString()}]</span>
                <span className="line-source" style={{
                  color: log.type === 'error' ? 'var(--fire-red)' : log.type === 'success' ? 'var(--neon-green)' : undefined
                }}>[{log.agent}]</span>
                <span className="line-msg" style={{
                  color: log.type === 'error' ? 'var(--fire-red)' : log.type === 'success' ? 'var(--neon-green)' : undefined,
                  wordBreak: 'break-all',
                }}>{log.message}</span>
                {log.data && (
                  <span className="line-data"> | DATA: {JSON.stringify(log.data)}</span>
                )}
              </div>
            ))}
            {terminalLogs.length === 0 && (
              <div className="console-line idle">
                <span className="line-msg">AWAITING DEEPAGENTS DEPLOYMENT...</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
