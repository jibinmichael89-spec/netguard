import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { apiFetch } from "../api";
import type { DnsDeviceInfo, DnsQuery } from "../types";
import { DNS_REFRESH_MS } from "../config";
import { categorizeDomain } from "../utils/categorize";
import { formatTimestamp } from "../utils/format";
import BackLink from "../components/BackLink";
import LoadingSpinner from "../components/LoadingSpinner";
import ScannerOffline from "../components/ScannerOffline";

type DnsFilter = "all" | "critical" | "warnings";

const FILTER_OPTIONS: { id: DnsFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "critical", label: "Critical" },
  { id: "warnings", label: "Warnings" },
];

interface DnsDeviceDetailResponse {
  source_ip: string;
  count: number;
  suspicious_count: number;
  device: DnsDeviceInfo | null;
  queries: DnsQuery[];
}

export default function DnsDeviceDetailPage() {
  const { ip } = useParams<{ ip: string }>();
  const [queries, setQueries] = useState<DnsQuery[]>([]);
  const [device, setDevice] = useState<DnsDeviceInfo | null>(null);
  const [suspiciousCount, setSuspiciousCount] = useState(0);
  const [filter, setFilter] = useState<DnsFilter>("all");
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);

  const fetchDnsHistory = useCallback(async (isInitial = false) => {
    if (!ip) return;
    if (isInitial) setLoading(true);
    try {
      const data = await apiFetch<DnsDeviceDetailResponse>(
        `/dns/device/${encodeURIComponent(ip)}?limit=500`,
      );
      setQueries(data.queries);
      setDevice(data.device);
      setSuspiciousCount(data.suspicious_count);
      setOffline(false);
    } catch {
      setOffline(true);
    } finally {
      if (isInitial) setLoading(false);
    }
  }, [ip]);

  useEffect(() => {
    void fetchDnsHistory(true);
    const interval = setInterval(() => void fetchDnsHistory(false), DNS_REFRESH_MS);
    return () => clearInterval(interval);
  }, [fetchDnsHistory]);

  const filterCounts = useMemo(
    () => ({
      all: queries.length,
      critical: suspiciousCount,
      warnings: suspiciousCount,
    }),
    [queries.length, suspiciousCount],
  );

  const visibleQueries = useMemo(() => {
    if (filter === "all") return queries;
    return queries.filter((q) => q.is_suspicious === 1);
  }, [queries, filter]);

  if (loading) {
    return <LoadingSpinner label="Loading DNS history..." fullPage />;
  }

  if (offline) {
    return (
      <ScannerOffline
        onRetry={() => {
          setLoading(true);
          void fetchDnsHistory(true);
        }}
      />
    );
  }

  const displayName =
    device?.hostname || device?.device_tag || ip || "Unknown device";

  return (
    <div className="space-y-6">
      <div>
        <div className="mb-4">
          <BackLink fallbackTo="/dns" label="Back" />
        </div>
        <h2 className="text-2xl font-bold text-white">DNS history</h2>
        <p className="mt-1 text-sm text-gray-400">
          DNS lookups only for this device — not the full device dashboard
        </p>
      </div>

      <div className="rounded-xl border border-ng-border bg-ng-card p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h3 className="text-lg font-semibold text-white">{displayName}</h3>
            <p className="mt-1 font-mono text-sm text-ng-accent">{ip}</p>
            {device && (
              <p className="mt-1 text-xs text-gray-500">
                {[device.mac_address, device.vendor, device.device_category]
                  .filter(Boolean)
                  .join(" · ")}
              </p>
            )}
          </div>
          <div className="text-right text-sm text-gray-400">
            <p>
              <span className="font-semibold text-white">{queries.length}</span> queries
            </p>
            {suspiciousCount > 0 && (
              <p className="text-ng-alert">{suspiciousCount} flagged</p>
            )}
          </div>
        </div>
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
          <table className="w-full min-w-[800px] text-left text-sm">
            <thead>
              <tr className="border-b border-ng-border text-xs uppercase tracking-wider text-gray-500">
                <th className="px-4 py-3 font-medium">Time</th>
                <th className="px-4 py-3 font-medium">Domain</th>
                <th className="px-4 py-3 font-medium">Category</th>
                <th className="px-4 py-3 font-medium">Type</th>
                <th className="px-4 py-3 font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ng-border">
              {visibleQueries.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                    {queries.length === 0
                      ? "No DNS queries recorded for this device yet."
                      : "No queries match this filter."}
                  </td>
                </tr>
              ) : (
                visibleQueries.map((query) => {
                  const flagged = query.is_suspicious === 1;
                  const warningView = filter === "warnings" && flagged;
                  return (
                    <tr
                      key={query.id}
                      className={
                        flagged
                          ? warningView
                            ? "bg-ng-warning/10"
                            : "bg-ng-alert/10"
                          : "hover:bg-ng-elevated/50"
                      }
                    >
                      <td className="px-4 py-3 whitespace-nowrap text-gray-400">
                        {formatTimestamp(query.timestamp)}
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-gray-200">{query.domain}</span>
                        {query.reason && (
                          <p className="mt-0.5 text-xs text-ng-alert">{query.reason}</p>
                        )}
                      </td>
                      <td className="px-4 py-3 text-gray-400">
                        {categorizeDomain(query.domain)}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-gray-500">
                        {query.query_type}
                      </td>
                      <td className="px-4 py-3">
                        {flagged ? (
                          <span className="rounded bg-ng-alert/20 px-2 py-0.5 text-xs font-semibold text-ng-alert">
                            Flagged
                          </span>
                        ) : (
                          <span className="text-xs text-gray-500">OK</span>
                        )}
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
