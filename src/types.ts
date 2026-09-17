export interface PublicEndpoint {
  host: string;
  port: number;
  source?: 'manual' | 'railway-tcp' | 'railway-domain' | 'auto';
  manualHost?: string;
  manualPort?: number;
  autoIp?: string;
  panelDomain?: string | null;
  tcpDomain?: string | null;
  tcpPort?: number | null;
  gatewayPort?: number;
  tcpProxyConfigured?: boolean;
}

export interface AnyTlsConfig {
  id: string;
  remark: string;
  port: number;
  password: string;
  sni: string;
  trafficLimitGB: number; // 0 = unlimited
  trafficUsedBytes: number;
  expireDays: number; // 0 = unlimited
  expireAt: string | null; // ISO date string or null
  createdAt: string;
  status: 'active' | 'disabled' | 'expired';
  insecure: boolean;
  notes?: string;
  processRunning?: boolean;
  processPid?: number;
  /** True when this config owns the shared external gateway listener. */
  isGateway?: boolean;
  /** Internal port the tunnel listens on (always the gateway port on Railway). */
  listenPort?: number;
  /** Public port clients must use. */
  externalPort?: number;
}

export interface ConfigProcessDetails {
  binaryPath: string | null;
  binaryExists: boolean;
  binaryDownloadState?: 'idle' | 'downloading' | 'ready' | 'failed';
  binaryDownloadError?: string | null;
  status: 'running' | 'stopped' | 'failed';
  pid?: number;
  port: number;
  listenPort?: number;
  isGateway?: boolean;
  publicHost?: string;
  publicPort?: number;
  isListening?: boolean;
  listenDetails?: string;
  startedAt?: string;
  logs: string[];
}

export interface ServerStatus {
  cpuUsage: number;
  memoryUsedMB: number;
  memoryTotalMB: number;
  uptimeSeconds: number;
  processUptimeSeconds?: number;
  serverIp: string;
  panelPort: number;
  publicEndpoint?: PublicEndpoint;
  gatewayPort?: number;
  gatewayConfigId?: string | null;
  gatewayRunning?: boolean;
  anytlsInstalled: boolean;
  anytlsVersion: string;
  activeConfigsCount: number;
  totalConfigsCount: number;
  osInfo: string;
  isStandalone?: boolean;
  onRailway?: boolean;
  trafficAccounting?: boolean;
  binaryDownloadState?: 'idle' | 'downloading' | 'ready' | 'failed';
}

export interface AdminUser {
  username: string;
  isLoggedIn: boolean;
  token?: string;
}

export interface RenewOptions {
  addDays: number;
  addTrafficGB: number;
  resetTraffic: boolean;
}