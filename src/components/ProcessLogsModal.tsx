import React, { useState, useEffect } from 'react';
import {
  X,
  Terminal,
  RefreshCw,
  Server,
  Activity,
  AlertCircle,
  CheckCircle2,
  Copy,
  Check,
  ShieldCheck,
  Play,
  RotateCw,
} from 'lucide-react';
import { AnyTlsConfig, ConfigProcessDetails } from '../types';
import { api } from '../lib/api';
import { getPublicPort } from '../lib/formatters';

interface ProcessLogsModalProps {
  isOpen: boolean;
  onClose: () => void;
  config: AnyTlsConfig | null;
  serverIp: string;
}

export const ProcessLogsModal: React.FC<ProcessLogsModalProps> = ({
  isOpen,
  onClose,
  config,
  serverIp,
}) => {
  const [details, setDetails] = useState<ConfigProcessDetails | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [restarting, setRestarting] = useState<boolean>(false);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fetchProcessInfo = async () => {
    if (!config) return;
    setLoading(true);
    setError(null);
    try {
      const data = await api.getConfigProcess(config.id);
      setDetails(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load process details');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen && config) {
      fetchProcessInfo();
      const timer = setInterval(fetchProcessInfo, 5000);
      return () => clearInterval(timer);
    }
  }, [isOpen, config?.id]);

  if (!isOpen || !config) return null;

  const handleRestart = async () => {
    setRestarting(true);
    try {
      await api.restartConfigProcess(config.id);
      await fetchProcessInfo();
    } catch (err: any) {
      setError(err.message || 'Failed to restart process');
    } finally {
      setRestarting(false);
    }
  };

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(key);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const isRunning = details?.status === 'running' || Boolean(details?.pid);
  const listenPort = details?.listenPort || config.listenPort || config.port;
  const publicPort = details?.publicPort || getPublicPort(config);
  const publicHost = details?.publicHost || serverIp || '127.0.0.1';
  /**
   * The port the Railway TCP proxy must forward to — this is the shared
   * GATEWAY_PORT (sent as `details.gatewayPort`), NOT the per-config
   * internal listenPort.
   */
  const GATEWAY_HINT_PORT = (details as any)?.gatewayPort || listenPort;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm overflow-y-auto">
      <div className="relative w-full max-w-2xl rounded-2xl border border-white/10 bg-[#141414] shadow-2xl overflow-hidden my-8">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-white/5 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-white/5 text-amber-500 border border-white/5">
              <Terminal className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-medium text-white tracking-wide">
                  AnyTLS Tunnel Process: {config.remark}
                </h2>
                <span
                  className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-[10px] font-mono border ${
                    isRunning
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                      : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                  }`}
                >
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${
                      isRunning ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
                    }`}
                  />
                  {isRunning ? `Running (PID: ${details?.pid})` : 'Stopped / Standby'}
                </span>
              </div>
              <p className="text-xs text-white/40">
                Internal 127.0.0.1:{listenPort} • Public {publicHost}:{publicPort}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1 text-white/40 hover:bg-white/5 hover:text-white transition"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-5 text-sm">
          {/* Status Metric Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2.5">
            <div className="rounded-xl border border-white/5 bg-[#0a0a0a] p-3">
              <div className="text-[11px] text-white/40">Tunnel State</div>
              <div
                className={`text-sm font-semibold mt-1 ${
                  isRunning ? 'text-emerald-400' : 'text-amber-400'
                }`}
              >
                {isRunning ? 'Active Tunnel' : 'Not Running'}
              </div>
            </div>

            <div className="rounded-xl border border-white/5 bg-[#0a0a0a] p-3">
              <div className="text-[11px] text-white/40">Process PID</div>
              <div className="text-sm font-mono text-white mt-1">
                {details?.pid ? details.pid : '—'}
              </div>
            </div>

            <div className="rounded-xl border border-white/5 bg-[#0a0a0a] p-3">
              <div className="text-[11px] text-white/40">Listening Port</div>
              <div className="text-sm font-mono text-amber-400 mt-1">
                {details?.isGateway ? '0.0.0.0' : '127.0.0.1'}:{listenPort}
              </div>
            </div>

            <div className="rounded-xl border border-white/5 bg-[#0a0a0a] p-3">
              <div className="text-[11px] text-white/40">Public Endpoint</div>
              <div className="text-sm font-mono text-emerald-400 mt-1 truncate" title={`${publicHost}:${publicPort}`}>
                {publicHost}:{publicPort}
              </div>
            </div>

            <div className="rounded-xl border border-white/5 bg-[#0a0a0a] p-3">
              <div className="text-[11px] text-white/40">Binary Status</div>
              <div className="text-sm font-medium mt-1 truncate">
                {details?.binaryExists ? (
                  <span className="text-emerald-400">Installed</span>
                ) : (
                  <span className="text-amber-400">Not Found</span>
                )}
              </div>
            </div>
          </div>

          {/* Binary Missing Warning if applicable */}
          {details && !details.binaryExists && (
            <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-3.5 text-xs text-amber-400 space-y-1">
              <div className="font-semibold flex items-center gap-1.5">
                <AlertCircle className="h-4 w-4" />
                anytls-server binary not found
              </div>
              <p className="text-white/60">
                {details.binaryDownloadState === 'downloading'
                  ? 'The panel is downloading the anytls-go release right now — refresh in a few seconds.'
                  : 'The panel downloads the official anytls-go binary on first use. Click "Restart Tunnel" (or re-run the install step) to trigger the download again.'}
              </p>
              {details.binaryDownloadError && (
                <p className="font-mono text-[11px] text-red-400 break-all">
                  {details.binaryDownloadError}
                </p>
              )}
            </div>
          )}

          {/* Spawn Command Box */}
          <div className="rounded-xl border border-white/5 bg-[#090909] p-3.5 space-y-2">
            <div className="text-xs text-white/40 font-medium flex items-center justify-between">
              <span>Underlying Execution Command:</span>
              <button
                onClick={handleRestart}
                disabled={restarting}
                className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/5 px-2.5 py-1 text-xs text-amber-400 hover:bg-white/10 transition disabled:opacity-50"
              >
                <RotateCw className={`h-3 w-3 ${restarting ? 'animate-spin' : ''}`} />
                <span>Restart Tunnel</span>
              </button>
            </div>
            <div className="font-mono text-xs text-emerald-400 bg-black/60 p-2.5 rounded-lg border border-white/5 overflow-x-auto select-all">
              {details?.binaryPath || 'anytls-server'} -l {details?.isGateway ? '0.0.0.0' : '127.0.0.1'}:{listenPort} -p {'•'.repeat(Math.min(config.password.length, 12))}
            </div>

            {/* Kernel Socket LISTEN Verification */}
            <div className="border-t border-white/5 pt-2 flex flex-col gap-1">
              <div className="flex items-center justify-between text-xs">
                <span className="text-white/40">Kernel TCP Socket (LISTEN Check):</span>
                <span
                  className={`font-mono text-xs font-medium flex items-center gap-1.5 ${
                    details?.isListening ? 'text-emerald-400' : 'text-amber-400'
                  }`}
                >
                  <span
                    className={`h-1.5 w-1.5 rounded-full ${
                      details?.isListening ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
                    }`}
                  />
                  {details?.isListening
                    ? `LISTEN (127.0.0.1:${listenPort})`
                    : 'Port not yet in LISTEN mode'}
                </span>
              </div>
              {details?.listenDetails && (
                <div className="font-mono text-[11px] text-white/50 bg-black/50 px-2 py-1 rounded overflow-x-auto">
                  {details.listenDetails}
                </div>
              )}
            </div>
          </div>

          {/* Live Process Console Logs */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-amber-500" />
                <h4 className="text-xs font-medium text-white/80">
                  Live Process Logs (Stdout & Stderr):
                </h4>
              </div>
              <button
                onClick={fetchProcessInfo}
                disabled={loading}
                className="text-[11px] text-white/40 hover:text-white flex items-center gap-1 transition"
              >
                <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} />
                <span>Refresh</span>
              </button>
            </div>

            <div className="rounded-xl border border-white/10 bg-[#050505] p-3 h-44 overflow-y-auto font-mono text-xs text-white/70 space-y-1">
              {details?.logs && details.logs.length > 0 ? (
                details.logs.map((line, idx) => (
                  <div key={idx} className="leading-relaxed">
                    <span className="text-white/30 mr-2">{idx + 1}</span>
                    <span
                      className={
                        line.toLowerCase().includes('error') || line.toLowerCase().includes('failed')
                          ? 'text-red-400'
                          : line.toLowerCase().includes('started') || line.toLowerCase().includes('pid')
                          ? 'text-emerald-400'
                          : 'text-white/80'
                      }
                    >
                      {line}
                    </span>
                  </div>
                ))
              ) : (
                <div className="text-white/30 italic py-6 text-center">
                  No log output yet. When clients connect or when the process starts, output will appear here.
                </div>
              )}
            </div>
          </div>

          {/* Deployment diagnostics */}
          <div className="rounded-xl border border-white/5 bg-[#0a0a0a] p-3.5 space-y-2">
            <h4 className="text-xs font-medium text-white/80">
              Deployment Checklist {details?.isGateway ? '(Public Gateway)' : '(Standby Tunnel)'}
            </h4>
            <div className="space-y-1.5 font-mono text-xs">
              {/* Gateway port reminder */}
              <div className="flex items-center justify-between bg-black/40 p-2 rounded border border-white/5">
                <div className="truncate">
                  <span className="text-white/40 font-sans mr-2">1. TCP Proxy target port:</span>
                  <span className="text-amber-400">{GATEWAY_HINT_PORT}</span>
                </div>
                <button
                  onClick={() => copyToClipboard(String(GATEWAY_HINT_PORT), 'port')}
                  className="text-white/40 hover:text-white ml-2 shrink-0"
                >
                  {copiedCmd === 'port' ? (
                    <Check className="h-3 w-3 text-emerald-400" />
                  ) : (
                    <Copy className="h-3 w-3" />
                  )}
                </button>
              </div>

              {/* Public address */}
              <div className="flex items-center justify-between bg-black/40 p-2 rounded border border-white/5">
                <div className="truncate">
                  <span className="text-white/40 font-sans mr-2">2. Client address:</span>
                  <span className="text-amber-400">
                    {publicHost}:{publicPort}
                  </span>
                </div>
                <button
                  onClick={() => copyToClipboard(`${publicHost}:${publicPort}`, 'addr')}
                  className="text-white/40 hover:text-white ml-2 shrink-0"
                >
                  {copiedCmd === 'addr' ? (
                    <Check className="h-3 w-3 text-emerald-400" />
                  ) : (
                    <Copy className="h-3 w-3" />
                  )}
                </button>
              </div>

              {/* Link */}
              <div className="flex items-center justify-between bg-black/40 p-2 rounded border border-white/5">
                <div className="truncate">
                  <span className="text-white/40 font-sans mr-2">3. Connection link:</span>
                  <span className="text-amber-400">
                    anytls://{config.password}@{publicHost}:{publicPort}
                  </span>
                </div>
                <button
                  onClick={() =>
                    copyToClipboard(
                      `anytls://${config.password}@${publicHost}:${publicPort}#${config.remark}`,
                      'link'
                    )
                  }
                  className="text-white/40 hover:text-white ml-2 shrink-0"
                >
                  {copiedCmd === 'link' ? (
                    <Check className="h-3 w-3 text-emerald-400" />
                  ) : (
                    <Copy className="h-3 w-3" />
                  )}
                </button>
              </div>
            </div>

            <p className="text-[11px] text-white/40 leading-relaxed pt-1">
              Railway allows a single TCP proxy per service, so only the configuration marked{' '}
              <span className="text-amber-400">Public</span> is reachable from the internet. Use
              &ldquo;Make Public&rdquo; on another configuration to switch the exposed tunnel.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end border-t border-white/5 bg-white/[0.01] px-6 py-3">
          <button
            onClick={onClose}
            className="rounded-xl border border-white/5 bg-white/5 px-5 py-2 text-xs font-medium text-white/70 transition hover:bg-white/10 hover:text-white"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
