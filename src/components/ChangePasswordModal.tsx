import React, { useState, useEffect } from 'react';
import { X, Key, Check, AlertCircle, Globe, Lock } from 'lucide-react';
import { api } from '../lib/api';
import { PublicEndpoint } from '../types';

interface ChangePasswordModalProps {
  isOpen: boolean;
  serverIp?: string;
  publicEndpoint?: PublicEndpoint | null;
  isStandalone?: boolean;
  onRailway?: boolean;
  onClose: () => void;
  onSuccess?: () => void;
}

/**
 * Panel settings.
 *
 * On a container platform the web port is owned by the platform ($PORT is
 * injected by Railway), so this modal no longer restarts the panel on a new
 * port. Instead it manages the admin password and, optionally, a manual
 * override for the public AnyTLS host/port.
 */
export const ChangePasswordModal: React.FC<ChangePasswordModalProps> = ({
  isOpen,
  serverIp = '',
  publicEndpoint = null,
  onRailway = false,
  onClose,
  onSuccess,
}) => {
  const detectedHost = publicEndpoint?.host || serverIp || '';
  const detectedPort = publicEndpoint?.port ? String(publicEndpoint.port) : '';

  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [useManualEndpoint, setUseManualEndpoint] = useState(false);
  const [host, setHost] = useState(detectedHost);
  const [port, setPort] = useState(detectedPort);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  useEffect(() => {
    if (!isOpen) return;
    setCurrentPassword('');
    setNewPassword('');
    setConfirmPassword('');
    setError('');
    setSuccessMsg('');
    setHost(publicEndpoint?.manualHost || detectedHost);
    setPort(
      publicEndpoint?.manualPort ? String(publicEndpoint.manualPort) : detectedPort
    );
    setUseManualEndpoint(publicEndpoint?.source === 'manual');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen, publicEndpoint?.host, publicEndpoint?.port, publicEndpoint?.source]);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');

    if (!currentPassword) {
      setError('Please enter your current password to authorize changes');
      return;
    }

    const isChangingPassword = Boolean(newPassword.trim());
    if (isChangingPassword) {
      if (newPassword !== confirmPassword) {
        setError('New passwords do not match');
        return;
      }
      if (newPassword.length < 6) {
        setError('New password must be at least 6 characters');
        return;
      }
    }

    let parsedPort: number | undefined;
    if (useManualEndpoint) {
      if (!host.trim()) {
        setError('Public host cannot be empty when a manual endpoint is enabled');
        return;
      }
      parsedPort = parseInt(port, 10);
      if (isNaN(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
        setError('Public port must be a number between 1 and 65535');
        return;
      }
    } else if (!isChangingPassword) {
      setError('No changes detected. Enter a new password or set a manual endpoint.');
      return;
    }

    setIsLoading(true);
    try {
      const res = await api.updateSettings({
        currentPassword,
        newPassword: isChangingPassword ? newPassword : undefined,
        // Clearing the override is expressed by sending empty values.
        host: useManualEndpoint ? host.trim() : '',
        port: useManualEndpoint ? parsedPort : undefined,
      });

      setSuccessMsg(res.message || 'Settings updated successfully');
      if (onSuccess) onSuccess();
      setTimeout(() => onClose(), 1500);
    } catch (err: any) {
      setError(err.message || 'Failed to update settings');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm">
      <div className="relative w-full max-w-md rounded-2xl border border-white/10 bg-[#151515] shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-white/5 px-6 py-4">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-white/5 text-amber-500 border border-white/5">
              <Key className="h-4 w-4" />
            </div>
            <div>
              <h2 className="text-base font-medium text-white tracking-wide">Panel Settings</h2>
              <p className="text-xs text-white/40">Admin password & public endpoint</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1 text-white/40 hover:bg-white/5 hover:text-white transition"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4 text-sm">
          {error && (
            <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-3 text-xs text-red-400 flex items-center gap-2">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {successMsg && (
            <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/10 p-3 text-xs text-emerald-400 flex items-center gap-2">
              <Check className="h-4 w-4 shrink-0" />
              <span className="font-semibold">{successMsg}</span>
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-white/60 mb-1">
              Current Password <span className="text-amber-500">*</span>
            </label>
            <input
              type="password"
              required
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              placeholder="Enter current password to authorize changes"
              className="w-full rounded-xl border border-white/10 bg-[#0d0d0d] px-3.5 py-2.5 text-white focus:border-amber-500 focus:outline-none"
            />
          </div>

          <div className="pt-2 border-t border-white/5">
            <label className="block text-xs font-medium text-white/60 mb-1">
              New Admin Password{' '}
              <span className="text-white/40 text-[11px] font-normal">(leave blank to keep current)</span>
            </label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="At least 6 characters"
              className="w-full rounded-xl border border-white/10 bg-[#0d0d0d] px-3.5 py-2.5 text-white focus:border-amber-500 focus:outline-none"
            />
          </div>

          {newPassword && (
            <div>
              <label className="block text-xs font-medium text-white/60 mb-1">
                Confirm New Password <span className="text-amber-500">*</span>
              </label>
              <input
                type="password"
                required={Boolean(newPassword)}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Repeat new password"
                className="w-full rounded-xl border border-white/10 bg-[#0d0d0d] px-3.5 py-2.5 text-white focus:border-amber-500 focus:outline-none"
              />
            </div>
          )}

          {/* Public endpoint */}
          <div className="pt-3 border-t border-white/5 space-y-3">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="flex items-center gap-1.5 text-xs font-medium text-white/70">
                  <Globe className="h-3.5 w-3.5 text-amber-500" />
                  <span>Public AnyTLS endpoint</span>
                </div>
                <p className="text-[11px] text-white/40 mt-1 leading-relaxed">
                  {onRailway
                    ? 'Detected automatically from the Railway TCP proxy. Override it only if you use a custom domain.'
                    : 'Detected automatically. Override it if this server sits behind NAT or a custom domain.'}
                </p>
              </div>
              <label className="flex shrink-0 cursor-pointer items-center gap-1.5 text-[11px] text-white/60">
                <input
                  type="checkbox"
                  checked={useManualEndpoint}
                  onChange={(e) => setUseManualEndpoint(e.target.checked)}
                  className="h-3.5 w-3.5 accent-amber-500"
                />
                Manual
              </label>
            </div>

            {useManualEndpoint ? (
              <div className="grid grid-cols-3 gap-2">
                <div className="col-span-2">
                  <label className="block text-[11px] text-white/50 mb-1">Host</label>
                  <input
                    type="text"
                    value={host}
                    onChange={(e) => setHost(e.target.value)}
                    placeholder="shuttle.proxy.rlwy.net"
                    className="w-full rounded-xl border border-white/10 bg-[#0d0d0d] px-3 py-2 text-white font-mono text-xs focus:border-amber-500 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-[11px] text-white/50 mb-1">Port</label>
                  <input
                    type="number"
                    min="1"
                    max="65535"
                    value={port}
                    onChange={(e) => setPort(e.target.value)}
                    placeholder="15140"
                    className="w-full rounded-xl border border-white/10 bg-[#0d0d0d] px-3 py-2 text-white font-mono text-xs focus:border-amber-500 focus:outline-none"
                  />
                </div>
              </div>
            ) : (
              <div className="rounded-xl border border-white/5 bg-[#0d0d0d] px-3.5 py-2.5 font-mono text-xs text-amber-400">
                {detectedHost ? `${detectedHost}:${detectedPort || '—'}` : 'Detecting…'}
              </div>
            )}

            {/* The web port is owned by the platform in a container. */}
            <div className="flex items-start gap-2 rounded-xl border border-amber-500/15 bg-amber-500/5 p-3 text-[11px] text-amber-400/90">
              <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <span>
                {onRailway
                  ? 'The web panel port is managed by Railway and cannot be changed from here. Set it in the service Settings → Networking tab.'
                  : 'The web panel port is defined by the PORT environment variable and cannot be changed from here.'}
              </span>
            </div>
          </div>

          <div className="flex items-center justify-end gap-3 pt-4 border-t border-white/5">
            <button
              type="button"
              onClick={onClose}
              className="rounded-xl border border-white/5 bg-white/5 px-4 py-2 text-xs font-medium text-white/70 hover:bg-white/10 hover:text-white transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading}
              className="rounded-xl bg-amber-500 hover:bg-amber-400 text-black px-5 py-2 text-xs font-bold transition disabled:opacity-50"
            >
              {isLoading ? 'Saving...' : 'Save Settings'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};