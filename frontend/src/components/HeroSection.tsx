import { useState, useRef } from 'react';
import { motion } from 'framer-motion';
import { ArrowRight, Upload, Box } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import BackgroundScene from './ui/aurora-section-hero';
import { GridPulse } from './ui/grid-pulse';

interface Props {
  onDeploy: (url: string) => void;
  isRunning: boolean;
}

export function HeroSection({ onDeploy, isRunning }: Props) {
  const [mode, setMode] = useState<'sandbox' | 'github'>('github');
  const [url, setUrl] = useState('');
  const navigate = useNavigate();

  const handleDeploy = () => {
    if (mode === 'github') {
      onDeploy(url.trim() || 'https://github.com');
    } else {
      // Navigate to the dedicated sandbox (upload ZIP) page
      navigate('/sandbox');
    }
  };

  return (
    <section style={{
      position: 'relative',
      width: '100%',
      height: '100vh',
      minHeight: '700px',
      overflow: 'hidden',
      background: '#070010',
      display: 'flex',
      flexDirection: 'column',
    }}>

      {/* ── Aurora 3D beam background ── */}
      <div style={{ position: 'absolute', inset: 0, zIndex: 0 }}>
        <BackgroundScene beamCount={70} />
      </div>

      {/* ── Purple/Magenta radial gradient overlay (top-right) ── */}
      <div style={{
        position: 'absolute', inset: 0, zIndex: 1, pointerEvents: 'none',
        background: 'radial-gradient(ellipse 80% 80% at 100% -5%, rgba(140,0,255,0.65) 0%, rgba(180,0,130,0.35) 35%, transparent 65%)',
      }} />

      {/* ── Noise texture overlay ── */}
      <div style={{
        position: 'absolute', inset: 0, zIndex: 1, pointerEvents: 'none', opacity: 0.04,
        backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='1'/%3E%3C/svg%3E")`,
        backgroundRepeat: 'repeat',
        backgroundSize: '200px 200px',
      }} />

      {/* ── Bottom vignette ── */}
      <div style={{
        position: 'absolute', bottom: 0, left: 0, right: 0, height: '35%', zIndex: 2, pointerEvents: 'none',
        background: 'linear-gradient(to top, rgba(7,0,16,1) 0%, transparent 100%)',
      }} />

      {/* ── Interactive purple grid — lights up under the cursor ── */}
      <GridPulse style={{ zIndex: 3 }} />

      {/* ══════════════════════════════════════════ NAVBAR ══════════════ */}
      <nav style={{
        position: 'relative', zIndex: 20,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '22px 48px',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        backdropFilter: 'blur(8px)',
        background: 'rgba(7,0,16,0.3)',
      }}>
        {/* Logo removed — spacer keeps the nav balanced */}
        <div style={{ width: 30 }} />

        {/* Nav links */}
        <div style={{ display: 'flex', gap: '40px' }}>
          {[
            { name: 'Analysis', path: '/analysis' },
            { name: 'Cure Plan', path: '/cure-planner' },
            { name: 'Report', path: '/report' },
            { name: 'History', path: '/history' },
          ].map((item) => (
            <span key={item.name} onClick={() => navigate(item.path)} style={{
              fontFamily: "'Space Grotesk', 'Outfit', sans-serif",
              fontSize: '0.9rem', color: 'rgba(255,255,255,0.7)',
              textDecoration: 'none', letterSpacing: '0.2px',
              transition: 'color 0.2s',
              cursor: 'pointer',
            }}
              onMouseEnter={e => (e.currentTarget.style.color = '#fff')}
              onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.7)')}
            >{item.name}</span>
          ))}
        </div>

        {/* Contact Us */}
        <a href="mailto:Punyasurana23@gmail.com" style={{
          fontFamily: "'Space Grotesk', 'Outfit', sans-serif",
          fontSize: '0.85rem', fontWeight: 600,
          color: '#fff', background: 'transparent',
          border: '1px solid rgba(168,85,247,0.6)',
          borderRadius: '999px',
          padding: '9px 24px',
          cursor: 'pointer',
          textDecoration: 'none',
          transition: 'all 0.25s',
          letterSpacing: '0.3px',
          display: 'inline-block',
        }}
          onMouseEnter={e => { e.currentTarget.style.background = 'rgba(124,58,237,0.25)'; e.currentTarget.style.borderColor = '#a855f7'; }}
          onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.borderColor = 'rgba(168,85,247,0.6)'; }}
        >Contact Us</a>
      </nav>

      {/* ══════════════════════════════════════════ HERO BODY ══════════ */}
      <div style={{
        position: 'relative', zIndex: 10,
        flex: 1,
        display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
        padding: '0 32px',
        textAlign: 'center',
      }}>
        {/* ── Tagline top-right of center ── */}
        <motion.p
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.6, delay: 0.4 }}
          style={{
            position: 'absolute',
            top: '8%', right: '8%',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '0.75rem',
            color: 'rgba(255,255,255,0.5)',
            letterSpacing: '2px',
          }}
        >Oracle-Guided Exploitation Swarm ·</motion.p>

        {/* ── Title (huge display) ── */}
        <div style={{ position: 'relative', width: '100%', maxWidth: '1100px' }}>
          <motion.h1
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, delay: 0.1 }}
            style={{
              fontFamily: "'Orbitron', sans-serif",
              fontSize: 'clamp(3.5rem, 8vw, 7.5rem)',
              fontWeight: 900,
              color: '#fff',
              lineHeight: 0.95,
              letterSpacing: '2px',
              userSelect: 'none',
              margin: 0,
            }}
          >
            CYPHEX
          </motion.h1>

          {/* ── 3D Rotating Lock ── */}
          <motion.div
            initial={{ opacity: 0, scale: 0.5 }}
            animate={{ opacity: 1, scale: 0.8 }}
            transition={{ duration: 0.8, delay: 0.3, type: 'spring', stiffness: 100 }}
            style={{
              position: 'absolute',
              top: '55%', left: '50%',
              transform: 'translate(-50%, -50%)',
              zIndex: 5,
            }}
          >
            <LockElement isRunning={isRunning} />
          </motion.div>
        </div>

        {/* ══ Control Panel — separated from title with clear gap ══ */}
        <motion.div
          initial={{ opacity: 0, y: 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.65 }}
          style={{
            marginTop: '210px', // Slided down heavily to prevent overlapping the lock rings
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: '24px',
            position: 'relative',
            zIndex: 20, // ensure UI sits above lock rings
            background: 'rgba(7, 0, 16, 0.25)', // slight glass plate to hold controls
            backdropFilter: 'blur(12px)',
            border: '1px solid rgba(255,255,255,0.05)',
            padding: '28px 36px',
            borderRadius: '20px',
            boxShadow: '0 20px 40px rgba(0,0,0,0.4)',
          }}
        >
          {/* Mode tabs row */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            background: 'rgba(255,255,255,0.04)',
            border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: '10px',
            padding: '5px',
          }}>
            {(['github', 'sandbox'] as const).map(m => (
              <button
                key={m}
                onClick={() => setMode(m)}
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '0.72rem', fontWeight: 700,
                  padding: '9px 22px',
                  borderRadius: '7px',
                  border: 'none',
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                  letterSpacing: '1.5px',
                  background: mode === m ? 'linear-gradient(135deg,#7c3aed,#a855f7)' : 'transparent',
                  color: mode === m ? '#fff' : 'rgba(255,255,255,0.4)',
                  boxShadow: mode === m ? '0 0 18px rgba(124,58,237,0.5)' : 'none',
                }}
              >
                {m === 'sandbox' ? 'SANDBOX' : 'GITHUB'}
              </button>
            ))}

          </div>

          {/* GitHub repo link — shown only in GITHUB mode */}
          {mode === 'github' && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              style={{
                display: 'flex',
                alignItems: 'center',
                background: 'rgba(0,0,0,0.45)',
                border: '1px solid rgba(168,85,247,0.3)',
                borderRadius: '10px',
                overflow: 'hidden',
                width: '380px',
              }}
            >
              <span style={{
                fontFamily: "'JetBrains Mono', monospace",
                color: '#a855f7', fontWeight: 700,
                padding: '0 14px',
                fontSize: '0.9rem',
                borderRight: '1px solid rgba(168,85,247,0.2)',
              }}>{'>'}</span>
              <input
                type="text"
                value={url}
                onChange={e => setUrl(e.target.value)}
                placeholder={mode === 'github' ? 'https://github.com/org/repo' : 'https://target.com'}
                style={{
                  flex: 1,
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '0.85rem',
                  background: 'transparent',
                  border: 'none', outline: 'none',
                  color: '#fff',
                  padding: '13px 14px',
                  letterSpacing: '0.3px',
                }}
              />
            </motion.div>
          )}
          {/* Upload ZIP — shown only in SANDBOX mode */}
          {mode === 'sandbox' && (
            <motion.button
              onClick={() => navigate('/sandbox')}
              disabled={isRunning}
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              style={{
                display: 'flex', alignItems: 'center', gap: '8px',
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '0.8rem', fontWeight: 700, letterSpacing: '1px',
                padding: '13px 24px', borderRadius: '10px',
                border: '1px solid rgba(168,85,247,0.35)',
                background: 'rgba(0,0,0,0.45)',
                color: 'rgba(168,85,247,0.9)',
                cursor: isRunning ? 'not-allowed' : 'pointer',
              }}
              onMouseEnter={e => { e.currentTarget.style.background = 'rgba(124,58,237,0.18)'; e.currentTarget.style.borderColor = '#a855f7'; }}
              onMouseLeave={e => { e.currentTarget.style.background = 'rgba(0,0,0,0.45)'; e.currentTarget.style.borderColor = 'rgba(168,85,247,0.35)'; }}
            >
              <Upload size={16} /> UPLOAD ZIP
            </motion.button>
          )}

          {/* CTA buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
            <motion.button
              onClick={handleDeploy}
              disabled={isRunning}
              whileHover={!isRunning ? { scale: 1.04, boxShadow: '0 0 50px rgba(124,58,237,0.65)' } : {}}
              whileTap={!isRunning ? { scale: 0.97 } : {}}
              style={{
                fontFamily: "'Space Grotesk', 'Outfit', sans-serif",
                fontSize: '0.95rem', fontWeight: 700,
                color: '#fff',
                background: isRunning
                  ? 'rgba(124,58,237,0.35)'
                  : 'linear-gradient(135deg, #7c3aed 0%, #a855f7 100%)',
                border: 'none',
                borderRadius: '999px',
                padding: '14px 32px',
                cursor: isRunning ? 'not-allowed' : 'pointer',
                boxShadow: '0 0 32px rgba(124,58,237,0.4)',
                display: 'flex', alignItems: 'center', gap: '9px',
                letterSpacing: '0.2px',
                transition: 'all 0.3s',
              }}
            >
              {isRunning ? 'DeepAgents Running...' : 'Deploy DeepAgents'}
              {!isRunning && <ArrowRight size={17} />}
            </motion.button>
          </div>
        </motion.div>
      </div>

      {/* ══════════════════════════════════════════ BOTTOM STATS ══════ */}
      <div style={{
        position: 'relative', zIndex: 20,
        display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between',
        padding: '20px 48px 28px',
      }}>
        {/* Left: Stats */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.9 }}
          style={{ display: 'flex', gap: '48px' }}
        >
          {[
            { value: '12', label: 'Apps Tested' },
            { value: '15', label: 'Vulns Patched' },
          ].map(stat => (
            <div key={stat.label}>
              <div style={{
                fontFamily: "'Space Grotesk', 'Outfit', sans-serif",
                fontSize: '2.2rem', fontWeight: 900, color: '#fff', lineHeight: 1.1,
              }}>{stat.value}</div>
              <div style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '0.7rem', color: 'rgba(255,255,255,0.45)',
                letterSpacing: '2px', textTransform: 'uppercase', marginTop: '2px',
              }}>{stat.label}</div>
            </div>
          ))}
          <div style={{ maxWidth: '180px' }}>
            <p style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: '0.7rem', color: 'rgba(255,255,255,0.4)',
              lineHeight: 1.7, letterSpacing: '0.5px',
            }}>13 oracle-guided DeepAgents that exploit, then self-patch</p>
          </div>
        </motion.div>

        {/* Right: Status pill */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.1 }}
          style={{ display: 'flex', gap: '12px', alignItems: 'center' }}
        >
          <div style={{
            display: 'flex', alignItems: 'center', gap: '8px',
            background: 'rgba(255,255,255,0.05)',
            border: '1px solid rgba(255,255,255,0.1)',
            borderRadius: '999px',
            padding: '7px 16px',
          }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#39ff14', boxShadow: '0 0 8px #39ff14', display: 'inline-block' }} />
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.65rem', color: 'rgba(255,255,255,0.5)', letterSpacing: '2px' }}>
              {isRunning ? 'SWARM ACTIVE' : 'DEEPAGENTS ONLINE'}
            </span>
          </div>
        </motion.div>
      </div>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700;900&display=swap');
        @keyframes lockFloat {
          0%, 100% { transform: translateY(0px) rotateY(0deg); }
          25% { transform: translateY(-12px) rotateY(8deg); }
          75% { transform: translateY(6px) rotateY(-8deg); }
        }
        @keyframes lockGlow {
          0%, 100% { filter: drop-shadow(0 0 20px rgba(140,0,255,0.6)) drop-shadow(0 0 60px rgba(180,0,130,0.3)); }
          50% { filter: drop-shadow(0 0 40px rgba(140,0,255,0.9)) drop-shadow(0 0 100px rgba(180,0,130,0.5)); }
        }
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @keyframes scanRing {
          0% { transform: scale(1); opacity: 0.6; }
          100% { transform: scale(2.2); opacity: 0; }
        }
      `}</style>
    </section>
  );
}

/* ─── 3D Lock SVG Element ──────────────────────────────────────── */
function LockElement({ isRunning }: { isRunning: boolean }) {
  return (
    <div style={{
      position: 'relative',
      width: '220px', height: '280px',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      animation: 'lockFloat 6s ease-in-out infinite',
    }}>
      {/* Scan rings */}
      {[0, 1, 2].map(i => (
        <div key={i} style={{
          position: 'absolute',
          width: '160px', height: '160px',
          borderRadius: '50%',
          border: `1px solid rgba(168,85,247,${0.35 - i * 0.1})`,
          top: '50%', left: '50%',
          marginTop: '-80px', marginLeft: '-80px',
          animation: `scanRing 3s ease-out ${i * 1}s infinite`,
          pointerEvents: 'none',
        }} />
      ))}

      {/* Wireframe browser frame */}
      <div style={{
        position: 'absolute',
        width: '180px', height: '140px',
        border: '1.5px solid rgba(255,255,255,0.18)',
        borderRadius: '10px',
        top: '60px', left: '20px',
        background: 'rgba(255,255,255,0.03)',
        display: 'flex', flexDirection: 'column',
      }}>
        <div style={{
          height: '22px',
          display: 'flex', alignItems: 'center', gap: '5px',
          padding: '0 10px',
          borderBottom: '1px solid rgba(255,255,255,0.1)',
        }}>
          {[0, 1, 2].map(i => (
            <div key={i} style={{ width: 6, height: 6, borderRadius: '50%', background: 'rgba(255,255,255,0.25)' }} />
          ))}
        </div>
      </div>

      {/* ── Main Lock SVG ── */}
      <svg
        viewBox="0 0 120 150"
        width="130"
        height="163"
        style={{
          position: 'relative', zIndex: 2,
          animation: 'lockGlow 4s ease-in-out infinite',
          filter: 'drop-shadow(0 0 30px rgba(140,0,255,0.7))',
        }}
      >
        <defs>
          <linearGradient id="lockBodyGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#d4e0f7" />
            <stop offset="50%" stopColor="#c0c8e0" />
            <stop offset="100%" stopColor="#8898bb" />
          </linearGradient>
          <linearGradient id="lockShackleGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#e8f0cc" />
            <stop offset="50%" stopColor="#c8d890" />
            <stop offset="100%" stopColor="#9aaa60" />
          </linearGradient>
          <linearGradient id="lockHighlight" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="rgba(255,255,255,0.4)" />
            <stop offset="100%" stopColor="rgba(255,255,255,0)" />
          </linearGradient>
          <filter id="lockShadow">
            <feDropShadow dx="0" dy="8" stdDeviation="8" floodColor="rgba(0,0,0,0.6)" />
          </filter>
        </defs>

        {/* Shackle (arch) */}
        <path
          d="M 30 65 C 30 30, 90 30, 90 65"
          fill="none"
          stroke="url(#lockShackleGrad)"
          strokeWidth="14"
          strokeLinecap="round"
          filter="url(#lockShadow)"
        />
        {/* Shackle highlight */}
        <path
          d="M 30 65 C 30 30, 90 30, 90 65"
          fill="none"
          stroke="rgba(255,255,255,0.3)"
          strokeWidth="3"
          strokeLinecap="round"
        />

        {/* Lock body rounded rect */}
        <rect x="14" y="60" width="92" height="76" rx="12" ry="12"
          fill="url(#lockBodyGrad)" filter="url(#lockShadow)" />
        {/* Body highlight overlay */}
        <rect x="14" y="60" width="92" height="35" rx="12" ry="12"
          fill="url(#lockHighlight)" />
        {/* Body edge */}
        <rect x="14" y="60" width="92" height="76" rx="12" ry="12"
          fill="none" stroke="rgba(255,255,255,0.2)" strokeWidth="1" />

        {/* Keyhole */}
        <circle cx="60" cy="100" r="10" fill="rgba(50,50,80,0.8)" />
        <rect x="55" y="100" width="10" height="18" rx="3" fill="rgba(50,50,80,0.8)" />

        {/* Small shield badge on body */}
        <g transform="translate(75, 92)">
          <path d="M 10 0 L 20 5 L 20 15 C 20 20, 10 24, 10 24 C 10 24, 0 20, 0 15 L 0 5 Z"
            fill="rgba(124,58,237,0.8)" stroke="rgba(168,85,247,0.6)" strokeWidth="1" />
          <path d="M 6 13 L 9 16 L 14 10" stroke="#fff" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" fill="none" />
        </g>
      </svg>

      {/* Code label floating top-right */}
      <div style={{
        position: 'absolute',
        top: '10px', right: '-10px',
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: '0.7rem',
        color: 'rgba(255,255,255,0.5)',
        letterSpacing: '2px',
      }}>&lt;/&gt;</div>

      {/* Sparkle decorations */}
      {[
        { top: '5%', left: '-5%', size: 10 },
        { top: '15%', left: '5%', size: 7 },
      ].map((s, i) => (
        <div key={i} style={{
          position: 'absolute',
          top: s.top, left: s.left,
          color: 'rgba(255,255,255,0.6)',
          fontSize: s.size + 'px',
          animation: `lockGlow ${2 + i}s ease-in-out infinite`,
        }}>✦</div>
      ))}

      {/* Running scan indicator */}
      {isRunning && (
        <div style={{
          position: 'absolute',
          bottom: '-30px',
          left: '50%',
          transform: 'translateX(-50%)',
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '0.6rem',
          color: '#39ff14',
          letterSpacing: '3px',
          textShadow: '0 0 10px #39ff14',
          whiteSpace: 'nowrap',
          animation: 'lockGlow 1s alternate infinite',
        }}>[ SWARM ENGAGED ]</div>
      )}
    </div>
  );
}
