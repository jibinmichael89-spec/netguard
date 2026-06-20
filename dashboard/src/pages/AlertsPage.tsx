import { useCallback, useEffect, useMemo, useState } from "react";
import { CheckCircle2 } from "lucide-react";
import { apiFetch } from "../api";
import type { DevicesResponse, SecurityAlertsResponse } from "../types";
import { formatTimestamp } from "../utils/format";
import SeverityBadge from "../components/SeverityBadge";
import LoadingSpinner from "../components/LoadingSpinner";
import ScannerOffline from "../components/ScannerOffline";
import InboundActivitySection from "../components/InboundActivitySection";

type AlertsTab = "security" | "inbound";

const TAB_OPTIONS: { id: AlertsTab; label: string }[] = [
  { id: "security", label: "Security Alerts" },
  { id: "inbound", label: "Inbound Activity" },
];

export default function AlertsPage() {
  const [activeTab, setActiveTab] = useState<AlertsTab>("security");
  const [alerts, setAlerts] = useState<SecurityAlertsResponse["alerts"]>([]);
  const [devices, setDevices] = useState<DevicesResponse["devices"]>([]);
  const [blockedIps, setBlockedIps] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);

  const fetchAlerts = useCallback(async () => {
    try {
      const [alertsRes, devicesRes] = await Promise.all([
        apiFetch<SecurityAlertsResponse>("/alerts/security"),
        apiFetch<DevicesResponse>("/devices?include_blocked=true"),
      ]);
      setAlerts(alertsRes.alerts);
      setDevices(devicesRes.devices);
      setBlockedIps(
        new Set(
          devicesRes.devices
            .filter((device) => (device.is_blocked ?? 0) === 1)
            .map((device) => device.ip_address),
        ),
      );
      setOffline(false);
    } catch {
      setOffline(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const visibleAlerts = useMemo(
    () =>
      alerts.filter(
        (alert) =>
          !blockedIps.has(alert.device_ip) &&
          alert.alert_type !== "inbound_connection",
      ),
    [alerts, blockedIps],
  );

  const inboundDeviceCount = useMemo(() => {
    const deviceIps = new Set<string>();
    for (const alert of alerts) {
      if (
        alert.alert_type === "inbound_connection" &&
        !blockedIps.has(alert.device_ip)
      ) {
        deviceIps.add(alert.device_ip);
      }
    }
    return deviceIps.size;
  }, [alerts, blockedIps]);

  const tabCounts: Record<AlertsTab, number> = {
    security: visibleAlerts.length,
    inbound: inboundDeviceCount,
  };

  if (loading) {
    return <LoadingSpinner label="Loading security alerts..." fullPage />;
  }

  if (offline) {
    return (
      <ScannerOffline
        onRetry={() => {
          setLoading(true);
          fetchAlerts();
        }}
      />
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white">Alerts</h2>
        <p className="mt-1 text-sm text-gray-400">
          {activeTab === "security"
            ? "ARP spoofing, rogue DHCP, and other threat detections"
            : "Unexpected incoming connections to your devices"}
        </p>
      </div>

      <div
        className="flex flex-wrap gap-2"
        role="tablist"
        aria-label="Alert categories"
      >
        {TAB_OPTIONS.map(({ id, label }) => {
          const active = activeTab === id;
          return (
            <button
              key={id}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={() => setActiveTab(id)}
              className={`rounded-full border px-4 py-2 text-sm font-medium transition ${
                active
                  ? id === "inbound"
                    ? "border-ng-alert/50 bg-ng-alert/15 text-ng-alert"
                    : "border-ng-accent/50 bg-ng-accent/15 text-ng-accent"
                  : "border-ng-border bg-ng-elevated text-gray-400 hover:border-gray-500 hover:text-gray-200"
              }`}
            >
              {label} ({tabCounts[id]})
            </button>
          );
        })}
      </div>

      {activeTab === "security" ? (
        visibleAlerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-4 rounded-xl border border-ng-border bg-ng-card py-16 text-center">
            <CheckCircle2 className="h-12 w-12 text-ng-safe" />
            <p className="text-lg font-medium text-ng-safe">
              No security alerts — network is clean
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {visibleAlerts.map((alert) => (
              <div
                key={alert.id}
                className="rounded-xl border border-ng-border bg-ng-card p-4 sm:p-5"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={alert.severity} />
                    <span className="rounded bg-ng-elevated px-2 py-0.5 text-xs font-mono uppercase text-gray-400">
                      {alert.alert_type}
                    </span>
                  </div>
                  <time className="text-xs text-gray-500">
                    {formatTimestamp(alert.timestamp)}
                  </time>
                </div>
                <p className="mt-3 font-mono text-sm text-ng-accent">
                  {alert.device_ip}
                </p>
                <p className="mt-1 text-sm text-gray-300">{alert.description}</p>
              </div>
            ))}
          </div>
        )
      ) : (
        <InboundActivitySection
          devices={devices}
          blockedIps={blockedIps}
          securityAlerts={alerts}
        />
      )}
    </div>
  );
}
