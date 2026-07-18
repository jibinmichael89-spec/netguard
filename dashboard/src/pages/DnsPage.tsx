import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ChevronRight, RefreshCw } from "lucide-react";
import { apiFetch } from "../api";
import type {
  DnsDeviceInfo,
  DnsDeviceSummary,
  DnsDevicesResponse,
  ThreatIntelStatusResponse,
} from "../types";
import { DNS_REFRESH_MS } from "../config";
import { categorizeDomain } from "../utils/categorize";
import { formatTimestamp } from "../utils/format";
import { useSystemDetection } from "../hooks/useSystemDetection";
import LoadingSpinner from "../components/LoadingSpinner";
import ScannerOffline from "../components/ScannerOffline";

type DnsFilter = "all" | "critical" | "warnings" | "no-dns";

const FILTER_OPTIONS: { id: DnsFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "critical", label: "Critical" },
  { id: "warnings", label: "Warnings" },
  { id: "no-dns", label: "No DNS yet" },
];

function DeviceDnsCell({
  sourceIp,
  device,
  hasDns,
}: {
  sourceIp: string;
  device: DnsDeviceInfo | null;
  hasDns: boolean;
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
      {!hasDns && (
        <span className="inline-block rounded bg-ng-warning/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-ng-warning">
          No DNS yet
        </span>
      )}
    </div>
  );
}

export default function DnsPage() {
  const { systemType } = useSystemDetection();
  const [devices, setDevices] = useState<DnsDeviceSummary[]>([]);
  const [withDnsCount, setWithDnsCount] = useState(0);
  const [withoutDnsCount, setWithoutDnsCount] = useState(0);
  const [filter, setFilter] = useState<DnsFilter>("all");
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);
  const [threatIntel, setThreatIntel] = useState<ThreatIntelStatusResponse | null>(null);
  const [updatingIntel, setUpdatingIntel] = useState(false);
  const [intelMessage, setIntelMessage] = useState<string>();
  const [intelError, setIntelError] = useState<string>();

  const fetchDns = useCallback(async (isInitial = false) => {
    if (isInitial) setLoading(true);
    try {
      const data = await apiFetch<DnsDevicesResponse>("/dns/devices");
      setDevices(data.devices);
      setWithDnsCount(data.with_dns_count ?? data.devices.filter((d) => d.query_count > 0).length);
      setWithoutDnsCount(
        data.without_dns_count ?? data.devices.filter((d) => d.query_count === 0).length,
      );
      setOffline(false);
    } catch {
      setOffline(true);
    } finally {
      if (isInitial) setLoading(false);
    }
  }, []);

  const fetchThreatIntel = useCallback(async () => {
    try {
      const status = await apiFetch<ThreatIntelStatusResponse>("/threat-intel/status");
      setThreatIntel(status);
    } catch {
      setThreatIntel({ domain_count: 0, last_updated: null });
    }
  }, []);

  const updateThreatIntel = async () => {
    setUpdatingIntel(true);
    setIntelError(undefined);
    setIntelMessage(undefined);
    try {
      const result = await apiFetch<{ domain_count: number }>("/threat-intel/update", {
        method: "POST",
      });
      setIntelMessage(`Threat feed updated: ${result.domain_count.toLocaleString()} domains`);
      await fetchThreatIntel();
    } catch (error) {
      setIntelError(error instanceof Error ? error.message : "Failed to update threat feed");
    } finally {
      setUpdatingIntel(false);
    }
  };

  useEffect(() => {
    fetchDns(true);
    void fetchThreatIntel();
    const interval = setInterval(() => fetchDns(false), DNS_REFRESH_MS);
    return () => clearInterval(interval);
  }, [fetchDns, fetchThreatIntel]);

  const suspiciousDeviceCount = useMemo(
    () => devices.filter((entry) => entry.suspicious_count > 0).length,
    [devices],
  );

  const filterCounts: Record<DnsFilter, number> = useMemo(
    () => ({
      all: devices.length,
      critical: suspiciousDeviceCount,
      warnings: suspiciousDeviceCount,
      "no-dns": withoutDnsCount,
    }),
    [devices.length, suspiciousDeviceCount, withoutDnsCount],
  );

  const visibleDevices = useMemo(() => {
    if (filter === "all") return devices;
    if (filter === "no-dns") return devices.filter((entry) => entry.query_count === 0);
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

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white">DNS Activity</h2>
          <p className="mt-1 text-sm text-gray-400">
            {withDnsCount} monitored · {withoutDnsCount} online with no DNS yet — click a device
            for full history
          </p>
          {systemType === "pi" && withoutDnsCount > 0 && (
            <p className="mt-2 text-xs text-amber-300/90">
              Devices marked &quot;No DNS yet&quot; are online but not using this Pi as DNS.
              Set your router DHCP DNS to the Pi IP (enable{" "}
              <code className="text-amber-200">NETGUARD_DNS_RELAY=1</code>).
            </p>
          )}
        </div>
        <div className="flex flex-col items-end gap-2">
          <button
            type="button"
            onClick={() => void updateThreatIntel()}
            disabled={updatingIntel}
            className="inline-flex items-center gap-2 rounded-lg border border-ng-border px-3 py-2 text-sm text-gray-300 hover:text-white disabled:opacity-50"
            title="Refresh the threat-intel domain list used for DNS warnings"
          >
            <RefreshCw className={`h-4 w-4 ${updatingIntel ? "animate-spin" : ""}`} />
            Update DNS warnings
          </button>
          {threatIntel && (
            <p className="text-xs text-gray-500">
              Feed: {threatIntel.domain_count.toLocaleString()} domains
              {threatIntel.last_updated
                ? ` · updated ${formatTimestamp(threatIntel.last_updated)}`
                : " · never updated"}
            </p>
          )}
        </div>
      </div>

      {(intelMessage || intelError) && (
        <div
          className={`rounded-lg border px-4 py-3 text-sm ${
            intelError
              ? "border-red-500/30 bg-red-500/10 text-red-300"
              : "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
          }`}
        >
          {intelError ?? intelMessage}
        </div>
      )}

      {devices.length === 0 ? (
        <div className="rounded-xl border border-ng-border bg-ng-card px-4 py-8 text-center text-gray-500">
          No online devices yet. Wait for ARP scan, or enable DNS relay on Pi and browse from another
          device.
        </div>
      ) : (
        <>
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
                      const hasDns = entry.query_count > 0;
                      const warningView = filter === "warnings" && hasSuspicious;

                      return (
                        <tr
                          key={entry.source_ip}
                          className={
                            hasSuspicious
                              ? warningView
                                ? "bg-ng-warning/10 hover:bg-ng-warning/15"
                                : "bg-ng-alert/10 hover:bg-ng-alert/15"
                              : !hasDns
                                ? "bg-ng-elevated/30 hover:bg-ng-elevated/50"
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
                              hasDns={hasDns}
                            />
                          </td>
                          <td className="px-4 py-3 text-gray-300">
                            {hasDns ? (
                              <>
                                {entry.query_count}
                                {entry.suspicious_count > 0 && (
                                  <span className="ml-2 text-xs text-ng-alert">
                                    ({entry.suspicious_count} flagged)
                                  </span>
                                )}
                              </>
                            ) : (
                              <span className="text-xs text-gray-500">Not using NetGuard DNS</span>
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
        </>
      )}
    </div>
  );
}
