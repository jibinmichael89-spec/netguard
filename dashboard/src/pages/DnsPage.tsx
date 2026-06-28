import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ChevronRight } from "lucide-react";
import { apiFetch } from "../api";
import type { DnsDeviceInfo, DnsDeviceSummary, DnsDevicesResponse } from "../types";
import { DNS_REFRESH_MS } from "../config";
import { categorizeDomain } from "../utils/categorize";
import { formatTimestamp } from "../utils/format";
import { useSystemDetection } from "../hooks/useSystemDetection";
import LoadingSpinner from "../components/LoadingSpinner";
import ScannerOffline from "../components/ScannerOffline";

type DnsFilter = "all" | "critical" | "warnings";

const FILTER_OPTIONS: { id: DnsFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "critical", label: "Critical" },
  { id: "warnings", label: "Warnings" },
];

function DeviceDnsCell({
  sourceIp,
  device,
}: {
  sourceIp: string;
  device: DnsDeviceInfo | null;
}) {
  if (!device) {
    return (
      <div className="space-y-0.5">
        <span className="font-mono text-ng-accent">{sourceIp}</span>
        <p className="text-xs text-gray-500">Device not in inventory yet</p>
      </div>
    );
  }

  const displayName = device.hostname || device.device_tag || sourceIp;

  return (
    <div className="space-y-0.5">
      <span className="font-medium text-white">{displayName}</span>
      <p className="font-mono text-xs text-ng-accent">{sourceIp}</p>
      <p className="text-xs text-gray-400">
        {device.mac_address}
        {device.vendor ? ` · ${device.vendor}` : ""}
      </p>
      {(device.device_tag || device.device_category) && (
        <p className="text-xs text-gray-500">
          {[device.device_category, device.device_tag].filter(Boolean).join(" · ")}
        </p>
      )}
      {(device.is_blocked ?? 0) === 1 && (
        <span className="inline-block rounded bg-ng-alert/20 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-ng-alert">
          Blocked
        </span>
      )}
    </div>
  );
}

export default function DnsPage() {
  const { systemType } = useSystemDetection();
  const [devices, setDevices] = useState<DnsDeviceSummary[]>([]);
  const [filter, setFilter] = useState<DnsFilter>("all");
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);

  const fetchDns = useCallback(async (isInitial = false) => {
    if (isInitial) setLoading(true);
    try {
      const data = await apiFetch<DnsDevicesResponse>("/dns/devices");
      setDevices(data.devices);
      setOffline(false);
    } catch {
      setOffline(true);
    } finally {
      if (isInitial) setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDns(true);
    const interval = setInterval(() => fetchDns(false), DNS_REFRESH_MS);
    return () => clearInterval(interval);
  }, [fetchDns]);

  const allDevices = useMemo(() => devices, [devices]);

  const suspiciousDeviceCount = useMemo(
    () => devices.filter((entry) => entry.suspicious_count > 0).length,
    [devices],
  );

  const filterCounts: Record<DnsFilter, number> = useMemo(
    () => ({
      all: allDevices.length,
      critical: suspiciousDeviceCount,
      warnings: suspiciousDeviceCount,
    }),
    [allDevices.length, suspiciousDeviceCount],
  );

  const visibleDevices = useMemo(() => {
    if (filter === "all") {
      return devices;
    }
    return devices.filter((entry) => entry.suspicious_count > 0);
  }, [devices, filter]);

  if (loading) {
    return <LoadingSpinner label="Loading DNS activity..." fullPage />;
  }

  if (offline) {
    return (
      <ScannerOffline
        onRetry={() => {
          setLoading(true);
          fetchDns(true);
        }}
      />
    );
  }

  if (devices.length === 0) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-2xl font-bold text-white">DNS Activity</h2>
          <p className="mt-1 text-sm text-gray-400">
            No DNS lookups recorded yet. On Pi, enable DNS relay and set router DHCP
            DNS to this Pi, then browse from another device.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white">DNS Activity</h2>
        <p className="mt-1 text-sm text-gray-400">
          One row per device — click a device for full DNS history in its timeline
        </p>
        {systemType === "pi" && (
          <p className="mt-2 text-xs text-amber-300/90">
            Only router and Pi? Set Linksys DHCP DNS to this Pi&apos;s IP after enabling{" "}
            <code className="text-amber-200">NETGUARD_DNS_RELAY=1</code>.
          </p>
        )}
      </div>

      <div className="flex flex-wrap gap-2">
        {FILTER_OPTIONS.map(({ id, label }) => {
          const active = filter === id;
          return (
            <button
              key={id}
              type="button"
              onClick={() => setFilter(id)}
              className={`rounded-full border px-4 py-2 text-sm font-medium transition ${
                active
                  ? "border-ng-accent/50 bg-ng-accent/15 text-ng-accent"
                  : "border-ng-border bg-ng-elevated text-gray-400 hover:border-gray-500 hover:text-gray-200"
              }`}
            >
              {label} ({filterCounts[id]})
            </button>
          );
        })}
      </div>

      <div className="overflow-hidden rounded-xl border border-ng-border bg-ng-card">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[900px] text-left text-sm">
            <thead>
              <tr className="border-b border-ng-border text-xs uppercase tracking-wider text-gray-500">
                <th className="px-4 py-3 font-medium">Last activity</th>
                <th className="px-4 py-3 font-medium">Device</th>
                <th className="px-4 py-3 font-medium">Queries</th>
                <th className="px-4 py-3 font-medium">Latest domain</th>
                <th className="px-4 py-3 font-medium" />
              </tr>
            </thead>
            <tbody className="divide-y divide-ng-border">
              {visibleDevices.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                    No devices match this filter.
                  </td>
                </tr>
              ) : (
                visibleDevices.map((entry) => {
                  const hasSuspicious = entry.suspicious_count > 0;
                  const warningView = filter === "warnings" && hasSuspicious;

                  return (
                    <tr
                      key={entry.source_ip}
                      className={
                        hasSuspicious
                          ? warningView
                            ? "bg-ng-warning/10 hover:bg-ng-warning/15"
                            : "bg-ng-alert/10 hover:bg-ng-alert/15"
                          : "hover:bg-ng-elevated/50"
                      }
                    >
                      <td className="px-4 py-3 text-gray-400">
                        {formatTimestamp(entry.last_query_at)}
                      </td>
                      <td className="px-4 py-3">
                        <DeviceDnsCell
                          sourceIp={entry.source_ip}
                          device={entry.device}
                        />
                      </td>
                      <td className="px-4 py-3 text-gray-300">
                        {entry.query_count}
                        {entry.suspicious_count > 0 && (
                          <span className="ml-2 text-xs text-ng-alert">
                            ({entry.suspicious_count} flagged)
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {entry.latest_domain ? (
                          <div>
                            <span className="text-gray-300">{entry.latest_domain}</span>
                            <p className="mt-0.5 text-xs text-gray-500">
                              {categorizeDomain(entry.latest_domain)}
                            </p>
                          </div>
                        ) : (
                          <span className="text-gray-500">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Link
                          to={`/device/${entry.source_ip}`}
                          className="inline-flex items-center gap-1 text-sm font-medium text-ng-accent hover:underline"
                        >
                          Full history
                          <ChevronRight className="h-4 w-4" />
                        </Link>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
