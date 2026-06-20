export interface Device {
  id: number;
  ip_address: string;
  mac_address: string;
  vendor: string | null;
  hostname: string | null;
  device_tag: string | null;
  is_trusted?: number;
  is_blocked?: number;
  first_seen: string;
  last_seen: string;
  status: string;
}

export interface DeviceTagResponse {
  device_ip: string;
  device_tag: string;
  success: boolean;
}

export interface DeviceTrustResponse {
  device_ip: string;
  is_trusted: boolean;
  success: boolean;
}

export interface DeviceBlockResponse {
  device_ip: string;
  is_blocked: boolean;
  success: boolean;
}

export interface SystemInfoResponse {
  platform: "windows" | "linux" | "darwin" | string;
  network_block_supported: boolean;
  hostname: string;
}

export interface DevicesResponse {
  count: number;
  devices: Device[];
}

export interface SecurityAlert {
  id: number;
  timestamp: string;
  severity: string;
  alert_type: string;
  device_ip: string;
  description: string;
  is_acknowledged: number;
}

export interface SecurityAlertsResponse {
  count: number;
  alerts: SecurityAlert[];
}

export interface InboundAttempt {
  source_ip: string;
  source_port: number;
  destination_port: number;
  severity: string;
  timestamp: string;
  description: string;
}

export interface InboundAttemptsResponse {
  device_ip: string;
  count: number;
  inbound_attempts: InboundAttempt[];
}

export interface DnsQuery {
  id: number;
  timestamp: string;
  source_ip: string;
  domain: string;
  query_type: string;
  response_ip: string | null;
  is_suspicious: number;
  reason: string | null;
}

export interface DnsResponse {
  count: number;
  queries: DnsQuery[];
}

export interface OpenPort {
  id: number;
  device_ip: string;
  port: number;
  service_name: string | null;
  is_dangerous: number;
  risk_reason: string | null;
  scanned_at: string;
}

export interface PortsResponse {
  device_ip: string;
  count: number;
  ports: OpenPort[];
}

export interface PortInstructionsResponse {
  port: number;
  service: string;
  dangerous_reason: string;
  platform: "windows" | "linux" | "pi";
  description: string;
  steps: string[];
}

export interface DangerousPortsResponse {
  count: number;
  dangerous_ports: OpenPort[];
}

export interface VaultCredential {
  id: number;
  device_name: string;
  device_ip: string | null;
  username: string;
  strength_score: number;
  is_compromised: number;
  last_checked: string | null;
  created_at: string;
}

export interface VaultListResponse {
  count: number;
  credentials: VaultCredential[];
}

export interface VaultAddResponse {
  id: number;
  strength_score: number;
}
