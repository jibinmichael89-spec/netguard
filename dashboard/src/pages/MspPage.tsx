import { useCallback, useEffect, useState } from "react";
import { Building2, RefreshCw } from "lucide-react";
import { apiFetch } from "../api";
import type { MspSitesResponse } from "../types";
import { formatTimestamp } from "../utils/format";

export default function MspPage() {
  const [sites, setSites] = useState<MspSitesResponse["sites"]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();

  const load = useCallback(async () => {
    setLoading(true);
    setError(undefined);
    try {
      const data = await apiFetch<MspSitesResponse>("/msp/sites");
      setSites(data.sites);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load MSP sites");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="flex items-center gap-2 text-2xl font-bold text-white">
            <Building2 className="h-7 w-7 text-ng-accent" />
            MSP Sites
          </h2>
          <p className="text-sm text-gray-500">
            Multi-site overview — agents POST heartbeats to this collector
          </p>
        </div>
        <button
          type="button"
          onClick={() => void load()}
          className="flex items-center gap-2 rounded-lg border border-ng-border px-4 py-2 text-sm text-gray-300 hover:text-white"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {loading ? (
        <p className="text-gray-400">Loading sites…</p>
      ) : sites.length === 0 ? (
        <div className="rounded-xl border border-ng-border bg-ng-card p-8 text-center">
          <p className="text-gray-400">No sites have reported yet.</p>
          <p className="mt-2 text-xs text-gray-500">
            Register a site via POST /msp/sites/register and set NETGUARD_MSP_COLLECTOR_URL on each Pi.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-ng-border">
          <table className="w-full text-sm">
            <thead className="bg-ng-elevated text-left text-gray-500">
              <tr>
                <th className="px-4 py-3">Site</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Online devices</th>
                <th className="px-4 py-3">Alerts (24h)</th>
                <th className="px-4 py-3">Agent</th>
                <th className="px-4 py-3">Last heartbeat</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ng-border">
              {sites.map((site) => (
                <tr key={site.site_id} className="hover:bg-ng-elevated/50">
                  <td className="px-4 py-3">
                    <p className="font-medium text-white">{site.site_name || site.site_id}</p>
                    <p className="text-xs text-gray-500">{site.site_id}</p>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`rounded-full px-2 py-0.5 text-xs ${
                        site.status === "online"
                          ? "bg-emerald-500/20 text-emerald-400"
                          : "bg-gray-500/20 text-gray-400"
                      }`}
                    >
                      {site.status || "unknown"}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-white">{site.online_devices ?? "—"}</td>
                  <td className="px-4 py-3 text-white">{site.alerts_24h ?? "—"}</td>
                  <td className="px-4 py-3 text-gray-400">{site.agent_version || "—"}</td>
                  <td className="px-4 py-3 text-gray-400">
                    {site.last_heartbeat ? formatTimestamp(site.last_heartbeat) : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
