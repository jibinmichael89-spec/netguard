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
  os_guess: string | null;
  os_confidence: "High" | "Medium" | "Low" | null;
  device_category: string | null;
  fingerprint_source: string | null;
  last_fingerprint_at: string | null;
  risk_score: number | null;
  risk_level: "Critical" | "High" | "Medium" | "Low" | "None" | null;
  risk_factors: Array<{ weight: number; reason: string; port?: number }> | null;
  risk_calculated_at: string | null;
  owner?: string | null;
  profile?: string | null;
  criticality?: string | null;
  is_approved?: number;
  approval_status?: "pending" | "approved" | "rejected" | string;
  notes?: string | null;
  site_id?: string | null;
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

export interface RiskSummaryResponse {
  total_devices: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  none_count: number;
  highest_risk_devices: Array<{
    ip_address: string;
    hostname: string | null;
    risk_score: number;
    risk_level: "Critical" | "High" | "Medium" | "Low" | "None";
  }>;
}

export interface CveReferenceExample {
  cve_id: string;
  description: string;
  published: string | null;
  severity: string | null;
}

export interface CveReferenceResponse {
  port: number;
  examples: CveReferenceExample[];
  no_data: boolean;
}

export interface SecurityAlert {
  id: number;
  timestamp: string;
  severity: string;
  alert_type: string;
  device_ip: string;
  description: string;
  is_acknowledged: number;
  is_false_positive?: number;
  snoozed_until?: string | null;
  acknowledged_at?: string | null;
  recommended_action?: string | null;
}

export interface DeviceTimelineEvent {
  timestamp: string;
  event_type: string;
  severity: string;
  summary: string;
  details: Record<string, unknown>;
}

export interface DeviceTimelineResponse {
  device_ip: string;
  count: number;
  events: DeviceTimelineEvent[];
}

export interface PendingDevicesResponse {
  count: number;
  devices: Device[];
}

export interface SecurityReportSummary {
  generated_at: string;
  online_devices: number;
  pending_approval: number;
  alerts_last_7_days: number;
  critical_devices: number;
  threat_intel_domains: number;
  policy_violations_last_7_days: number;
}

export interface SecurityAlertsResponse {
  count: number;
  alerts: SecurityAlert[];
}

export type DetectorStatus =
  | "active"
  | "idle"
  | "stopped"
  | "stale"
  | "inactive"
  | "standby";

export type MonitoringOverallStatus = "watching" | "degraded" | "offline";

export interface MonitoringDetector {
  id: string;
  name: string;
  description: string;
  optional: boolean;
  status: DetectorStatus;
  service_running: boolean | null;
  last_activity: string | null;
  age_seconds: number | null;
}

export interface MonitoringStatusResponse {
  timestamp: string;
  overall_status: MonitoringOverallStatus;
  last_device_scan: string | null;
  online_device_count: number;
  detectors: MonitoringDetector[];
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

export interface DnsDeviceInfo {
  id: number;
  ip_address: string;
  mac_address: string;
  hostname: string | null;
  vendor: string | null;
  device_tag: string | null;
  device_category: string | null;
  status: string;
  is_blocked?: number;
  risk_level: string | null;
  known: boolean;
}

export interface DnsDeviceSummary {
  source_ip: string;
  query_count: number;
  suspicious_count: number;
  last_query_at: string;
  latest_domain: string | null;
  device: DnsDeviceInfo | null;
}

export interface DnsDevicesResponse {
  count: number;
  devices: DnsDeviceSummary[];
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
  device: DnsDeviceInfo | null;
}

export interface DnsResponse {
  count: number;
  queries: DnsQuery[];
}

export type PortRiskLevel = "Critical" | "High" | "Medium" | "Low" | "Safe";

export interface OpenPort {
  id: number;
  device_ip: string;
  port: number;
  service_name: string | null;
  is_dangerous: number;
  risk_reason: string | null;
  scanned_at: string;
  port_risk_weight: number;
  port_risk_level: PortRiskLevel;
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

export interface NotificationConfigResponse {
  config: Record<string, string>;
}

export interface ThreatIntelStatusResponse {
  domain_count: number;
  last_updated: string | null;
}

export interface PolicyDefinition {
  id: string;
  name: string;
  severity: string;
  description: string;
  enabled?: boolean;
}

export interface PoliciesResponse {
  count: number;
  policies: PolicyDefinition[];
}

export interface RouterSettingsResponse {
  router_type: string | null;
  router_url: string | null;
  router_user: string | null;
  router_password: string | null;
  router_token: string | null;
  configured: boolean;
  supported_types: string[];
  env_overrides: string[];
  env_keys: string[];
}

export interface RouterConfigUpdate {
  router_type?: string;
  router_url?: string;
  router_user?: string;
  router_password?: string;
  router_token?: string;
}

export interface MspSite {
  site_id: string;
  site_name: string | null;
  last_heartbeat: string | null;
  online_devices: number | null;
  alerts_24h: number | null;
  agent_version: string | null;
  status: string | null;
}

export interface MspSitesResponse {
  count: number;
  sites: MspSite[];
}
