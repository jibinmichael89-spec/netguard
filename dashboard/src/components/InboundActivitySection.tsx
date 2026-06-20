import { useCallback, useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronUp, ShieldAlert } from "lucide-react";
import { apiFetch } from "../api";
import type {
  Device,
  InboundAttempt,
  InboundAttemptsResponse,
  SecurityAlert,
} from "../types";
import { formatTimestamp } from "../utils/format";
import SeverityBadge from "./SeverityBadge";
import LoadingSpinner from "./LoadingSpinner";

interface DeviceInboundSummary {
  device_ip: string;
  hostname: string | null;
  uniqueSourceCount: number;
  latestTimestamp: string;
  attempts: InboundAttempt[];
}

interface InboundActivitySectionProps {
  devices: Device[];
  blockedIps: Set<string>;
  securityAlerts: SecurityAlert[];
}

function buildSummaries(
  responses: InboundAttemptsResponse[],
  deviceByIp: Map<string, Device>,
): DeviceInboundSummary[] {
  return responses
    .filter((response) => response.inbound_attempts.length > 0)
    .map((response) => {
      const uniqueSources = new Set(
        response.inbound_attempts.map((attempt) => attempt.source_ip),
      );
      const latestTimestamp = response.inbound_attempts.reduce((latest, attempt) => {
        return attempt.timestamp > latest ? attempt.timestamp : latest;
      }, response.inbound_attempts[0].timestamp);

      return {
        device_ip: response.device_ip,
        hostname: deviceByIp.get(response.device_ip)?.hostname ?? null,
        uniqueSourceCount: uniqueSources.size,
        latestTimestamp,
        attempts: response.inbound_attempts,
      };
    })
    .sort(
      (a, b) =>
        new Date(b.latestTimestamp).getTime() -
        new Date(a.latestTimestamp).getTime(),
    );
}

export default function InboundActivitySection({
  devices,
  blockedIps,
  securityAlerts,
}: InboundActivitySectionProps) {
  const [summaries, setSummaries] = useState<DeviceInboundSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [expandedDeviceIp, setExpandedDeviceIp] = useState<string | null>(null);

  const deviceByIp = useMemo(
    () => new Map(devices.map((device) => [device.ip_address, device])),
    [devices],
  );

  const inboundDeviceIps = useMemo(() => {
    const ips = new Set<string>();
    for (const alert of securityAlerts) {
      if (
        alert.alert_type === "inbound_connection" &&
        !blockedIps.has(alert.device_ip)
      ) {
        ips.add(alert.device_ip);
      }
    }
    return [...ips];
  }, [securityAlerts, blockedIps]);

  const fetchInboundData = useCallback(async () => {
    setLoading(true);
    setFetchError(null);

    if (inboundDeviceIps.length === 0) {
      setSummaries([]);
      setLoading(false);
      return;
    }

    const results = await Promise.allSettled(
      inboundDeviceIps.map((deviceIp) =>
        apiFetch<InboundAttemptsResponse>(
          `/inbound/${encodeURIComponent(deviceIp)}`,
        ),
      ),
    );

    const responses = results
      .filter(
        (result): result is PromiseFulfilledResult<InboundAttemptsResponse> =>
          result.status === "fulfilled",
      )
      .map((result) => result.value);

    const failedCount = results.length - responses.length;

    if (responses.length === 0) {
      setSummaries([]);
      setFetchError(
        failedCount > 0
          ? "Unable to load inbound connection data."
          : null,
      );
      setLoading(false);
      return;
    }

    setSummaries(buildSummaries(responses, deviceByIp));
    if (failedCount > 0) {
      setFetchError(
        `Some inbound data could not be loaded (${failedCount} device${failedCount === 1 ? "" : "s"}).`,
      );
    }
    setLoading(false);
  }, [inboundDeviceIps, deviceByIp]);

  useEffect(() => {
    fetchInboundData();
  }, [fetchInboundData]);

  const toggleExpanded = (deviceIp: string) => {
    setExpandedDeviceIp((current) => (current === deviceIp ? null : deviceIp));
  };

  return (
    <section className="space-y-4">
      <div className="rounded-xl border border-ng-border bg-ng-card">
        {loading ? (
          <div className="px-4 py-10">
            <LoadingSpinner label="Loading inbound activity..." />
          </div>
        ) : summaries.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-3 px-4 py-12 text-center">
            <ShieldAlert className="h-10 w-10 text-gray-500" />
            <p className="text-sm text-gray-400">
              {fetchError ?? "No inbound connection attempts detected."}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-ng-border">
            {fetchError && (
              <p className="border-b border-ng-warning/30 bg-ng-warning/10 px-4 py-2 text-sm text-ng-warning">
                {fetchError}
              </p>
            )}

            {summaries.map((summary) => {
              const isExpanded = expandedDeviceIp === summary.device_ip;

              return (
                <div key={summary.device_ip}>
                  <button
                    type="button"
                    onClick={() => toggleExpanded(summary.device_ip)}
                    className="flex w-full flex-col gap-3 px-4 py-4 text-left transition hover:bg-ng-elevated/40 sm:flex-row sm:items-center sm:justify-between"
                    aria-expanded={isExpanded}
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-sm font-semibold text-ng-accent">
                          {summary.device_ip}
                        </span>
                        {summary.hostname && (
                          <span className="truncate text-sm text-gray-400">
                            {summary.hostname}
                          </span>
                        )}
                      </div>
                      <p className="mt-1 text-xs text-gray-500">
                        {summary.uniqueSourceCount} unique source
                        {summary.uniqueSourceCount === 1 ? "" : "s"} ·{" "}
                        {summary.attempts.length} attempt
                        {summary.attempts.length === 1 ? "" : "s"}
                      </p>
                    </div>

                    <div className="flex items-center gap-3">
                      <time className="text-xs text-gray-500">
                        Latest: {formatTimestamp(summary.latestTimestamp)}
                      </time>
                      {isExpanded ? (
                        <ChevronUp className="h-4 w-4 shrink-0 text-gray-400" />
                      ) : (
                        <ChevronDown className="h-4 w-4 shrink-0 text-gray-400" />
                      )}
                    </div>
                  </button>

                  {isExpanded && (
                    <div className="border-t border-ng-border bg-ng-elevated/30 px-4 py-4">
                      <div className="mb-3 flex items-center justify-between gap-3">
                        <p className="text-xs uppercase tracking-wider text-gray-500">
                          Attempt Details
                        </p>
                        <button
                          type="button"
                          onClick={() => setExpandedDeviceIp(null)}
                          className="text-xs text-gray-400 transition hover:text-white"
                        >
                          Close
                        </button>
                      </div>

                      <div className="overflow-x-auto">
                        <table className="w-full min-w-[640px] text-left text-sm">
                          <thead>
                            <tr className="border-b border-ng-border text-xs uppercase tracking-wider text-gray-500">
                              <th className="px-2 py-2 font-medium">Source IP</th>
                              <th className="px-2 py-2 font-medium">Source Port</th>
                              <th className="px-2 py-2 font-medium">Dest Port</th>
                              <th className="px-2 py-2 font-medium">Severity</th>
                              <th className="px-2 py-2 font-medium">Time</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-ng-border">
                            {summary.attempts.map((attempt, index) => (
                              <tr key={`${attempt.source_ip}-${attempt.source_port}-${attempt.destination_port}-${index}`}>
                                <td className="px-2 py-2 font-mono text-gray-200">
                                  {attempt.source_ip}
                                </td>
                                <td className="px-2 py-2 font-mono text-gray-300">
                                  {attempt.source_port}
                                </td>
                                <td className="px-2 py-2 font-mono text-gray-300">
                                  {attempt.destination_port}
                                </td>
                                <td className="px-2 py-2">
                                  <SeverityBadge severity={attempt.severity} />
                                </td>
                                <td className="px-2 py-2 text-gray-400">
                                  {formatTimestamp(attempt.timestamp)}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </section>
  );
}
