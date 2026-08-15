/**
 * CYPHEX — API Client
 *
 * REST + WebSocket client for the Python backend.
 * Backend runs on http://localhost:8000
 */

import type { ScanMeta, ScanReport, WSEvent } from '../types';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000';
const WS_BASE = import.meta.env.VITE_WS_BASE || 'ws://localhost:8000';

// The backend requires this shared key on every request (see
// backend/backend/auth.py). vite.config.ts reads/generates the same
// ~/.cyphex/api_key the backend uses and injects it here at build time —
// no manual copy-paste needed for the common local dev-server case.
const API_KEY = import.meta.env.VITE_API_KEY || '';

function authHeaders(extra?: Record<string, string>): Record<string, string> {
  return { ...(API_KEY ? { 'X-API-Key': API_KEY } : {}), ...extra };
}

function withApiKey(url: string): string {
  if (!API_KEY) return url;
  return `${url}${url.includes('?') ? '&' : '?'}api_key=${encodeURIComponent(API_KEY)}`;
}

// ── REST API ───────────────────────────────────────────────────

export async function startScan(
  targetUrl: string,
  cerebrasKey?: string,
): Promise<{ scan_id: string; status: string; target_url: string; started_at: string }> {
  const res = await fetch(`${API_BASE}/api/scan`, {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({
      target_url: targetUrl,
      cerebras_key: cerebrasKey || '',
      timeout: 1800,
    }),
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export async function getScan(scanId: string): Promise<ScanMeta> {
  const res = await fetch(`${API_BASE}/api/scan/${scanId}`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export async function listScans(): Promise<{ scans: ScanMeta[] }> {
  const res = await fetch(`${API_BASE}/api/scans`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

/**
 * Upload a sandbox ZIP file (or folder-as-ZIP) to the backend.
 * No size limit on the frontend — the backend handles up to 500 MB.
 */
export async function uploadSandbox(
  file: File,
  onProgress?: (pct: number) => void,
): Promise<{ sandbox_id: string; port: number; url: string; status: string; error?: string }> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${API_BASE}/api/sandbox/upload`);
    if (API_KEY) xhr.setRequestHeader('X-API-Key', API_KEY);

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && onProgress) {
        onProgress(Math.round((e.loaded / e.total) * 100));
      }
    };

    xhr.onload = () => {
      try {
        const data = JSON.parse(xhr.responseText);
        if (xhr.status >= 200 && xhr.status < 300) {
          if (data.error) {
            reject(new Error(data.error));
          } else {
            resolve(data);
          }
        } else {
          reject(new Error(data.error || `Upload failed: ${xhr.status}`));
        }
      } catch {
        reject(new Error(`Upload failed: ${xhr.status} ${xhr.statusText}`));
      }
    };

    xhr.onerror = () => reject(new Error('Network error during upload'));
    xhr.ontimeout = () => reject(new Error('Upload timed out'));
    xhr.timeout = 600_000; // 10 minute timeout for large files

    const formData = new FormData();
    formData.append('file', file);
    xhr.send(formData);
  });
}

// ── WebSocket ──────────────────────────────────────────────────

export function connectScanWebSocket(
  scanId: string,
  onEvent: (event: WSEvent) => void,
  onClose?: () => void,
  onError?: (error: Event) => void,
): WebSocket {
  const ws = new WebSocket(withApiKey(`${WS_BASE}/ws/${scanId}`));

  ws.onopen = () => {
    console.log(`[WS] Connected to scan ${scanId}`);
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data) as WSEvent;
      onEvent(data);
    } catch (e) {
      console.warn('[WS] Failed to parse event:', event.data);
    }
  };

  ws.onclose = () => {
    console.log(`[WS] Disconnected from scan ${scanId}`);
    onClose?.();
  };

  ws.onerror = (error) => {
    console.error('[WS] Error:', error);
    onError?.(error);
  };

  return ws;
}

/**
 * Connect a WebSocket that streams terminal logs for a specific sandbox.
 * Used by the sandbox terminal view on the frontend.
 */
export function connectSandboxWebSocket(
  sandboxId: string,
  onEvent: (event: any) => void,
  onClose?: () => void,
): WebSocket {
  const ws = new WebSocket(withApiKey(`${WS_BASE}/ws/sandbox/${sandboxId}`));

  ws.onopen = () => {
    console.log(`[WS] Connected to sandbox ${sandboxId}`);
  };

  ws.onmessage = (event) => {
    try {
      onEvent(JSON.parse(event.data));
    } catch {
      console.warn('[WS] Failed to parse sandbox event:', event.data);
    }
  };

  ws.onclose = () => {
    console.log(`[WS] Disconnected from sandbox ${sandboxId}`);
    onClose?.();
  };

  ws.onerror = (error) => {
    console.error('[WS Sandbox] Error:', error);
  };

  return ws;
}
