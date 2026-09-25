import { useState, useEffect, useRef, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Upload, Box, Terminal, Play, Square, Trash2,
  CheckCircle, Loader2, AlertCircle, Server,
  FolderArchive, ChevronRight, Zap
} from 'lucide-react';
import { uploadSandbox, connectSandboxWebSocket } from '../lib/api';
import { usePipelineContext } from '../contexts/PipelineContext';
import './SandboxPage.css';

interface SandboxInfo {
  sandbox_id: string;
  port: number;
  url: string;
  status: string;
  app_file?: string;
  started_at?: string;
}

interface TerminalLine {
  id: string;
  type: 'info' | 'command' | 'output' | 'error' | 'success' | 'system';
  text: string;
  timestamp: string;
}

export function SandboxPage() {
  const { startPipeline, isRunning, logs } = usePipelineContext();

  // Upload state
  const [uploadProgress, setUploadProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);

  // Sandbox state
  const [sandbox, setSandbox] = useState<SandboxInfo | null>(null);
  const [terminalLines, setTerminalLines] = useState<TerminalLine[]>([]);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  const terminalRef = useRef<HTMLDivElement>(null);
  const sandboxWsRef = useRef<WebSocket | null>(null);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalLines, logs]);

  const addTerminalLine = useCallback(
    (type: TerminalLine['type'], text: string) => {
      setTerminalLines((prev) => [
        ...prev,
        {
          id: `${Date.now()}-${Math.random()}`,
          type,
          text,
          timestamp: new Date().toISOString(),
        },
      ]);
    },
    [],
  );

  // Connect sandbox WS after deployment
  useEffect(() => {
    if (!sandbox) return;
    const ws = connectSandboxWebSocket(
      sandbox.sandbox_id,
      (event: any) => {
        if (event.type === 'terminal_log') {
          addTerminalLine('command', `$ ${event.command}`);
          if (event.stdout?.trim()) {
            addTerminalLine(event.success ? 'output' : 'error', event.stdout);
          }
        }
      },
      () => {
        addTerminalLine('system', '[ WebSocket disconnected ]');
      },
    );
    sandboxWsRef.current = ws;
    return () => {
      ws.close();
    };
  }, [sandbox, addTerminalLine]);

  // Also stream pipeline logs into the terminal
  useEffect(() => {
    if (!isRunning && logs.length <= 1) return;
    const last = logs[logs.length - 1];
    if (!last) return;
    const isCmd = last.message.startsWith('$');
    addTerminalLine(
      isCmd ? 'command' : last.type === 'error' ? 'error' : last.type === 'success' ? 'success' : 'info',
      `[${last.agent}] ${last.message}`,
    );
  }, [logs, isRunning, addTerminalLine]);

  // ── Upload handler ────────────────────────────────────────

  const handleFiles = async (rawFiles: FileList | File[]) => {
    setUploadError(null);
    setUploadProgress(0);
    setTerminalLines([]);

    // Convert FileList to a proper array (FileList items can be null)
    const files: File[] = Array.from(rawFiles).filter((f): f is File => f != null);
    if (files.length === 0) {
      setUploadError('No files selected.');
      return;
    }

    let file: File;
    if (files.length === 1 && files[0].name.endsWith('.zip')) {
      // Single ZIP file — upload directly
      file = files[0];
      addTerminalLine('system', `⬆ Uploading ZIP: ${file.name} (${(file.size / 1024 / 1024).toFixed(1)} MB)`);
    } else {
      // Folder upload — zip all files client-side
      addTerminalLine('system', `📦 Packaging ${files.length} files into ZIP...`);
      try {
        file = await zipFolderFiles(files);
        addTerminalLine('success', `✓ Package created: ${file.name} (${(file.size / 1024 / 1024).toFixed(1)} MB)`);
      } catch (err: any) {
        setUploadError(`Failed to package folder: ${err.message}`);
        addTerminalLine('error', `✗ Failed to package folder: ${err.message}`);
        return;
      }
    }

    setIsUploading(true);
    addTerminalLine('system', '⬆ Uploading to CYPHEX backend...');

    try {
      const result = await uploadSandbox(file, (pct) => {
        setUploadProgress(pct);
      });

      if (result.error) {
        throw new Error(result.error);
      }

      setSandbox(result);
      addTerminalLine('success', `✓ Sandbox deployed: ${result.sandbox_id}`);
      addTerminalLine('success', `✓ Server running at ${result.url}`);
      addTerminalLine('info', `  App file: ${result.app_file || 'auto-detected'}`);
      addTerminalLine('info', `  Port: ${result.port}`);
      addTerminalLine('system', '─── Ready for the DeepAgents swarm ───');
    } catch (err: any) {
      setUploadError(err.message);
      addTerminalLine('error', `✗ Upload failed: ${err.message}`);
    } finally {
      setIsUploading(false);
    }
  };

  // ── Start scanning ────────────────────────────────────────

  const handleStartScan = () => {
    if (!sandbox) return;
    addTerminalLine('system', '');
    addTerminalLine('system', '═══════════════════════════════════════════');
    addTerminalLine('system', '  🚀 INITIATING CYPHEX MULTI-AGENT SCAN');
    addTerminalLine('system', `  TARGET: ${sandbox.url}`);
    addTerminalLine('system', '═══════════════════════════════════════════');
    addTerminalLine('system', '');
    startPipeline(sandbox.url);
  };

  // ── Drag & drop ───────────────────────────────────────────

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  };
  const handleDragLeave = () => setDragOver(false);
  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const items = e.dataTransfer.files;
    if (items.length > 0) handleFiles(items);
  };

  return (
    <div className="sandbox-page">
      {/* ── Header ── */}
      <div className="sandbox-header">
        <div className="sandbox-title-row">
          <Box size={22} className="glow-purple" />
          <h1 className="sandbox-title mono">SANDBOX_DEPLOY</h1>
        </div>
        <p className="sandbox-subtitle">
          Upload a vulnerable application (ZIP or folder) → deploy it locally → run CYPHEX agents against it
        </p>
      </div>

      <div className="sandbox-layout">
        {/* ══════ LEFT: Upload Panel ══════ */}
        <div className="sandbox-upload-panel">
          <AnimatePresence mode="wait">
            {!sandbox ? (
              <motion.div
                key="upload"
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -16 }}
                className="upload-zone-wrapper"
              >
                {/* Drop zone */}
                <div
                  className={`upload-dropzone ${dragOver ? 'drag-over' : ''} ${isUploading ? 'uploading' : ''}`}
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  onClick={() => !isUploading && fileInputRef.current?.click()}
                >
                  {isUploading ? (
                    <div className="upload-progress-container">
                      <Loader2 size={40} className="spin glow-purple" />
                      <div className="upload-progress-text mono">
                        UPLOADING · {uploadProgress}%
                      </div>
                      <div className="upload-progress-bar">
                        <div
                          className="upload-progress-fill"
                          style={{ width: `${uploadProgress}%` }}
                        />
                      </div>
                    </div>
                  ) : (
                    <>
                      <div className="upload-icon-container">
                        <Upload size={36} strokeWidth={1.5} />
                      </div>
                      <div className="upload-text mono">
                        DROP ZIP HERE
                      </div>
                      <div className="upload-subtext">
                        or click to browse · max 500 MB
                      </div>
                    </>
                  )}
                </div>

                {/* Hidden file inputs */}
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".zip,.tar,.tar.gz,.tgz"
                  style={{ display: 'none' }}
                  onChange={(e) => {
                    if (e.target.files?.length) handleFiles(e.target.files);
                    e.target.value = '';
                  }}
                />
                <input
                  ref={folderInputRef}
                  type="file"
                  {...({ webkitdirectory: 'true', directory: 'true' } as any)}
                  style={{ display: 'none' }}
                  onChange={(e) => {
                    if (e.target.files?.length) handleFiles(e.target.files);
                    e.target.value = '';
                  }}
                />

                {/* OR button row */}
                <div className="upload-btn-row">
                  <button
                    className="upload-btn"
                    onClick={(e) => {
                      e.stopPropagation();
                      fileInputRef.current?.click();
                    }}
                    disabled={isUploading}
                  >
                    <FolderArchive size={16} />
                    <span>ZIP File</span>
                  </button>
                  <span className="upload-divider-text mono">OR</span>
                  <button
                    className="upload-btn"
                    onClick={(e) => {
                      e.stopPropagation();
                      folderInputRef.current?.click();
                    }}
                    disabled={isUploading}
                  >
                    <Upload size={16} />
                    <span>Folder</span>
                  </button>
                </div>

                {/* Error message */}
                {uploadError && (
                  <motion.div
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="upload-error"
                  >
                    <AlertCircle size={14} />
                    <span>{uploadError}</span>
                  </motion.div>
                )}
              </motion.div>
            ) : (
              /* ── Sandbox status card ── */
              <motion.div
                key="status"
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                className="sandbox-status-card"
              >
                <div className="sandbox-status-header">
                  <Server size={18} className="glow-green" />
                  <span className="mono sandbox-status-title">SANDBOX_ACTIVE</span>
                  <span className={`sandbox-badge ${sandbox.status === 'running' ? 'badge-running' : 'badge-starting'}`}>
                    {sandbox.status === 'running' ? '● RUNNING' : '◐ STARTING'}
                  </span>
                </div>

                <div className="sandbox-info-grid">
                  <div className="sandbox-info-item">
                    <span className="info-label mono">ID</span>
                    <span className="info-value mono">{sandbox.sandbox_id}</span>
                  </div>
                  <div className="sandbox-info-item">
                    <span className="info-label mono">PORT</span>
                    <span className="info-value mono">{sandbox.port}</span>
                  </div>
                  <div className="sandbox-info-item">
                    <span className="info-label mono">URL</span>
                    <a
                      href={sandbox.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="info-value info-link mono"
                    >
                      {sandbox.url} ↗
                    </a>
                  </div>
                  <div className="sandbox-info-item">
                    <span className="info-label mono">ENTRY</span>
                    <span className="info-value mono">{sandbox.app_file || '—'}</span>
                  </div>
                </div>

                {/* Action buttons */}
                <div className="sandbox-action-row">
                  <motion.button
                    className="sandbox-scan-btn"
                    onClick={handleStartScan}
                    disabled={isRunning}
                    whileHover={!isRunning ? { scale: 1.03 } : {}}
                    whileTap={!isRunning ? { scale: 0.97 } : {}}
                  >
                    {isRunning ? (
                      <>
                        <Loader2 size={16} className="spin" />
                        <span>SCANNING...</span>
                      </>
                    ) : (
                      <>
                        <Zap size={16} />
                        <span>RUN CYPHEX SCAN</span>
                      </>
                    )}
                  </motion.button>

                  <button
                    className="sandbox-reset-btn"
                    onClick={() => {
                      setSandbox(null);
                      setTerminalLines([]);
                      setUploadProgress(0);
                      if (sandboxWsRef.current) sandboxWsRef.current.close();
                    }}
                    disabled={isRunning}
                  >
                    <Trash2 size={14} />
                    <span>RESET</span>
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* ══════ RIGHT: Terminal ══════ */}
        <div className="sandbox-terminal-panel">
          <div className="terminal-chrome">
            <div className="terminal-dots">
              <span className="dot dot-red" />
              <span className="dot dot-yellow" />
              <span className="dot dot-green" />
            </div>
            <div className="terminal-title mono">
              <Terminal size={12} />
              <span>CYPHEX_TERMINAL</span>
              {sandbox && (
                <span className="terminal-target">— {sandbox.url}</span>
              )}
            </div>
            <div className="terminal-scanner-badge mono">
              {isRunning ? (
                <span className="badge-live">● LIVE</span>
              ) : sandbox ? (
                <span className="badge-ready">● READY</span>
              ) : (
                <span className="badge-idle">○ IDLE</span>
              )}
            </div>
          </div>

          <div className="terminal-body" ref={terminalRef}>
            {/* Static welcome message */}
            {terminalLines.length === 0 && !isRunning && (
              <div className="terminal-welcome">
                <pre className="tw-banner">{`
   ██████╗ ██╗   ██╗ ██████╗  ██╗  ██╗ ███████╗ ██╗  ██╗
  ██╔════╝ ╚██╗ ██╔╝ ██╔══██╗ ██║  ██║ ██╔════╝ ╚██╗██╔╝
  ██║       ╚████╔╝  ██████╔╝ ███████║ █████╗    ╚███╔╝
  ██║        ╚██╔╝   ██╔═══╝  ██╔══██║ ██╔══╝    ██╔██╗
  ╚██████╗    ██║    ██║      ██║  ██║ ███████╗ ██╔╝ ██╗
   ╚═════╝    ╚═╝    ╚═╝      ╚═╝  ╚═╝ ╚══════╝ ╚═╝  ╚═╝`}</pre>
                <div className="tw-line tw-dim">&nbsp;</div>
                <div className="tw-line tw-subtitle">Multi-Agent Exploitation Pipeline v2.0</div>
                <div className="tw-line tw-dim">  ──────────────────────────────────────────</div>
                <div className="tw-line tw-muted">&nbsp;</div>
                <div className="tw-line tw-muted">  Upload a sandbox ZIP or folder to begin...</div>
                <div className="tw-line tw-muted">  The terminal will show live curl attacks,</div>
                <div className="tw-line tw-muted">  agent commands, and exploitation output.</div>
              </div>
            )}

            {/* Terminal lines */}
            {terminalLines.map((line) => (
              <div key={line.id} className={`tl tl-${line.type}`}>
                <span className="tl-time">
                  [{new Date(line.timestamp).toLocaleTimeString()}]
                </span>
                <span className="tl-text">{line.text}</span>
              </div>
            ))}

            {isRunning && (
              <div className="terminal-cursor-line">
                <span className="blinking-cursor">▋</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * Client-side utility: zip a list of File objects (from folder upload)
 * into a single Blob so the backend receives one ZIP.
 */
async function zipFolderFiles(files: File[]): Promise<File> {
  const parts: { name: string; data: Uint8Array }[] = [];
  for (const f of files) {
    // webkitRelativePath gives "folderName/sub/file.js", fall back to name
    const relativePath = (f as any).webkitRelativePath || f.name;
    const buf = await f.arrayBuffer();
    parts.push({ name: relativePath, data: new Uint8Array(buf) });
  }

  // Minimal ZIP file builder (store-only, no compression for speed)
  const zip = buildZipBlob(parts);
  // Use the top-level folder name from the first file's relative path
  const firstPath: string = (files[0] as any).webkitRelativePath || '';
  const folderName = firstPath.includes('/') ? firstPath.split('/')[0] : 'sandbox';
  return new File([zip], `${folderName}.zip`, { type: 'application/zip' });
}

function buildZipBlob(entries: { name: string; data: Uint8Array }[]): Blob {
  const encoder = new TextEncoder();
  const centralDir: Uint8Array[] = [];
  const localParts: Uint8Array[] = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBytes = encoder.encode(entry.name);
    const crc = crc32(entry.data);
    const size = entry.data.length;

    // Local file header (30 bytes + name + data)
    const local = new Uint8Array(30 + nameBytes.length + size);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true); // signature
    lv.setUint16(4, 20, true);         // version needed
    lv.setUint16(6, 0, true);          // flags
    lv.setUint16(8, 0, true);          // compression (store)
    lv.setUint16(10, 0, true);         // mod time
    lv.setUint16(12, 0, true);         // mod date
    lv.setUint32(14, crc, true);       // CRC-32
    lv.setUint32(18, size, true);      // compressed size
    lv.setUint32(22, size, true);      // uncompressed size
    lv.setUint16(26, nameBytes.length, true); // name length
    lv.setUint16(28, 0, true);         // extra field length
    local.set(nameBytes, 30);
    local.set(entry.data, 30 + nameBytes.length);

    // Central directory entry (46 bytes + name)
    const cd = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(cd.buffer);
    cv.setUint32(0, 0x02014b50, true); // signature
    cv.setUint16(4, 20, true);         // version made by
    cv.setUint16(6, 20, true);         // version needed
    cv.setUint16(8, 0, true);
    cv.setUint16(10, 0, true);
    cv.setUint16(12, 0, true);
    cv.setUint16(14, 0, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, size, true);
    cv.setUint32(24, size, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint16(30, 0, true);
    cv.setUint16(32, 0, true);
    cv.setUint16(34, 0, true);
    cv.setUint16(36, 0, true);
    cv.setUint32(38, 0, true);
    cv.setUint32(42, offset, true);    // local header offset
    cd.set(nameBytes, 46);

    localParts.push(local);
    centralDir.push(cd);
    offset += local.length;
  }

  // End of central directory
  const cdSize = centralDir.reduce((a, b) => a + b.length, 0);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(4, 0, true);
  ev.setUint16(6, 0, true);
  ev.setUint16(8, entries.length, true);
  ev.setUint16(10, entries.length, true);
  ev.setUint32(12, cdSize, true);
  ev.setUint32(16, offset, true);
  ev.setUint16(20, 0, true);

  return new Blob([...localParts, ...centralDir, eocd] as BlobPart[], { type: 'application/zip' });
}

function crc32(data: Uint8Array): number {
  let crc = 0xFFFFFFFF;
  const table = getCRC32Table();
  for (let i = 0; i < data.length; i++) {
    crc = (crc >>> 8) ^ table[(crc ^ data[i]) & 0xFF];
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

let _crc32Table: Uint32Array | null = null;
function getCRC32Table(): Uint32Array {
  if (_crc32Table) return _crc32Table;
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
      c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  _crc32Table = table;
  return table;
}
