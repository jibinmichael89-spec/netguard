import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { apiFetch } from "../api";
import type { DnsQuery, DnsResponse } from "../types";
import { DNS_REFRESH_MS } from "../config";
import { categorizeDomain } from "../utils/categorize";
import { formatTimestamp } from "../utils/format";
import LoadingSpinner from "../components/LoadingSpinner";
import ScannerOffline from "../components/ScannerOffline";

type DnsFilter = "all" | "critical" | "warnings";

const FILTER_OPTIONS: { id: DnsFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "critical", label: "Critical" },
  { id: "warnings", label: "Warnings" },
];

function filterQueries(queries: DnsQuery[], filter: DnsFilter): DnsQuery[] {
  if (filter === "all") {
    return queries;
  }
  return queries.filter((query) => query.is_suspicious === 1);
}

function DeviceDnsCell({ query }: { query: DnsQuery }) {
  const device = query.device;

  if (!device) {
    return (
      <div className="space-y-0.5">
        <Link
          to={`/device/${query.source_ip}`}
          className="font-mono text-ng-accent hover:underline"
        >
          {query.source_ip}
        </Link>
        <p className="text-xs text-gray-500">Device not in inventory yet</p>
      </div>
    );
  }

  const displayName = device.hostname || device.device_tag || query.source_ip;

  return (
    <div className="space-y-0.5">
      <Link
        to={`/device/${query.source_ip}`}
        className="font-medium text-white hover:text-ng-accent"
      >
        {displayName}
      </Link>
      <p className="font-mono text-xs text-ng-accent">{query.source_ip}</p>
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
  const [queries, setQueries] = useState<DnsResponse["queries"]>([]);
  const [filter, setFilter] = useState<DnsFilter>("all");
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);

  const fetchDns = useCallback(async (isInitial = false) => {
    if (isInitial) setLoading(true);
    try {
      const data = await apiFetch<DnsResponse>("/dns");
      setQueries(data.queries);
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

  const suspiciousCount = useMemo(
    () => queries.filter((query) => query.is_suspicious === 1).length,
    [queries],
  );

  const filterCounts: Record<DnsFilter, number> = useMemo(
    () => ({
      all: queries.length,
      critical: suspiciousCount,
      warnings: suspiciousCount,
    }),
    [queries.length, suspiciousCount],
  );

  const filteredQueries = useMemo(
    () => filterQueries(queries, filter),
    [queries, filter],
  );

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

  if (queries.length === 0) {
    return (
      <div className="space-y-6">
        <div>
          <h2 className="text-2xl font-bold text-white">DNS Activity</h2>
          <p className="mt-1 text-sm text-gray-400">
            No DNS lookups recorded yet. Browse a few websites on this PC, then
            wait for the next scan cycle (about 30 seconds). On Windows, DNS
            shows lookups from this computer.
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
          Recent DNS queries across your network — refreshes every 10s
        </p>
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
                <th className="px-4 py-3 font-medium">Time</th>
                <th className="px-4 py-3 font-medium">Device</th>
                <th className="px-4 py-3 font-medium">Domain</th>
                <th className="px-4 py-3 font-medium">Category</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ng-border">
              {filteredQueries.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-gray-500">
                    {queries.length === 0
                      ? "No DNS queries captured yet."
                      : "No queries match this filter."}
                  </td>
                </tr>
              ) : (
                filteredQueries.map((query) => {
                  const suspicious = query.is_suspicious === 1;
                  const warningView = filter === "warnings" && suspicious;

                  return (
                    <tr
                      key={query.id}
                      className={
                        suspicious
                          ? warningView
                            ? "bg-ng-warning/10 hover:bg-ng-warning/15"
                            : "bg-ng-alert/10 hover:bg-ng-alert/15"
                          : "hover:bg-ng-elevated/50"
                      }
                    >
                      <td className="px-4 py-3 text-gray-400">
                        {formatTimestamp(query.timestamp)}
                      </td>
                      <td className="px-4 py-3">
                        <DeviceDnsCell query={query} />
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={
                            suspicious
                              ? warningView
                                ? "font-medium text-ng-warning"
                                : "font-medium text-ng-alert"
                              : "text-gray-300"
                          }
                        >
                          {query.domain}
                        </span>
                        {suspicious && query.reason && (
                          <p
                            className={`mt-0.5 text-xs ${
                              warningView ? "text-ng-warning/80" : "text-ng-alert/80"
                            }`}
                          >
                            {query.reason}
                          </p>
                        )}
                      </td>
                      <td className="px-4 py-3 text-gray-400">
                        {categorizeDomain(query.domain)}
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
