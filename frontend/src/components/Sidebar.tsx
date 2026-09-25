import { useState } from 'react';
import { NavLink } from 'react-router-dom';
import {
  Shield, Home, Target, Bug, CheckCircle, Activity,
  Globe, Heart, ChevronLeft, ChevronRight, Lock,
  FileWarning, Eye, Box, Zap, History, Upload
} from 'lucide-react';
import { usePipelineContext } from '../contexts/PipelineContext';
import './Sidebar.css';

const items = [
  { name: 'Overview',      path: '/',              icon: Home,        glowClass: 'glow-blue'   },
  { name: 'Sandbox',       path: '/sandbox',       icon: Upload,      glowClass: 'glow-purple' },
  { name: 'Recon',         path: '/recon',         icon: Activity,    glowClass: 'glow-blue'   },
  { name: 'Surface Map',   path: '/crawler',       icon: Globe,       glowClass: 'glow-green'  },
  { name: 'Injection',     path: '/injection',     icon: Target,      glowClass: 'glow-purple' },
  { name: 'XSS',           path: '/xss',           icon: Bug,         glowClass: 'glow-red'    },
  { name: 'Auth',          path: '/auth',          icon: Lock,        glowClass: 'glow-blue'   },
  { name: 'LFI',           path: '/lfi',           icon: FileWarning, glowClass: 'glow-purple' },
  { name: 'Logic',         path: '/logic',         icon: Eye,         glowClass: 'glow-green'  },
  { name: 'Supply Chain',  path: '/supply-chain',  icon: Box,         glowClass: 'glow-red'    },
  { name: 'Council',       path: '/analysis',      icon: CheckCircle, glowClass: 'glow-green'  },
  { name: 'Self-Patch',    path: '/cure-planner',  icon: Heart,       glowClass: 'glow-purple' },
  { name: 'Report',        path: '/report',        icon: Zap,         glowClass: 'glow-blue'   },
  { name: 'Scan History',  path: '/history',       icon: History,     glowClass: 'glow-purple' },
];

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const { backendConnected } = usePipelineContext();

  return (
    <aside className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      {/* Logo */}
      <div className="logo-area">
        <Shield className={`logo-icon glow-blue`} size={22} strokeWidth={1.5} />
        {!collapsed && <span className="logo-text mono">CYPHEX</span>}
      </div>

      {/* Connection status */}
      {!collapsed && (
        <div className="nav-section-label mono" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{
            width: 6, height: 6, borderRadius: '50%',
            background: backendConnected ? '#39ff14' : '#ff3131',
            boxShadow: backendConnected ? '0 0 6px #39ff14' : '0 0 6px #ff3131',
            display: 'inline-block',
          }} />
          {backendConnected ? 'SWARM ONLINE' : 'SIMULATION'}
        </div>
      )}

      {/* Nav */}
      <nav className="nav">
        {items.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            >
              <Icon size={18} className={`nav-icon`} strokeWidth={1.5} />
              {!collapsed && <span className="nav-text mono">{item.name}</span>}
            </NavLink>
          );
        })}
      </nav>

      {/* Collapse */}
      <button className="collapse-btn" onClick={() => setCollapsed(!collapsed)}>
        {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
        {!collapsed && <span className="mono" style={{ fontSize: '0.65rem', letterSpacing: '1px' }}>COLLAPSE</span>}
      </button>
    </aside>
  );
}
