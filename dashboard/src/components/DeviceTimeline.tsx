import { useCallback, useEffect, useState } from "react";
import { ApiError, apiFetch } from "../api";
import type { DeviceTimelineResponse } from "../types";
import { formatTimestamp } from "../utils/format";
import SeverityBadge from "./SeverityBadge";
import LoadingSpinner from "./LoadingSpinner";

interface DeviceTimelineProps {
  deviceIp: string;
}

export default function DeviceTimeline({ deviceIp }: DeviceTimelineProps) {
  const [events, setEvents] = useState<DeviceTimelineResponse["events"]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch<DeviceTimelineResponse>(
        `/devices/${encodeURIComponent(deviceIp)}/timeline`,
      );
      setEvents(res.events);
    } catch (err) {
      setEvents([]);
      setError(
        err instanceof ApiError
          ? err.message
          : "Failed to load activity timeline",
      );
    } finally {
      setLoading(false);
    }
  }, [deviceIp]);

  useEffect(() => {
    setEvents([]);
    setError(null);
    void load();
  }, [load]);

  return (
    <section className="rounded-xl border border-ng-border bg-ng-card p-5">
      <div className="mb-4 flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Activity Timeline</h3>
        {error && (
          <button
            type="button"
            onClick={() => void load()}
            className="text-sm font-medium text-ng-accent hover:underline"
          >
            Retry
          </button>
        )}
      </div>
      {loading ? (
        <LoadingSpinner label="Loading timeline..." />
      ) : error ? (
        <p className="text-sm text-ng-alert">{error}</p>
      ) : events.length === 0 ? (
        <p className="text-sm text-gray-400">No timeline events yet.</p>
      ) : (
        <div className="space-y-3">
          {events.map((event, index) => (
            <div
              key={`${event.timestamp}-${event.event_type}-${index}`}
              className="flex flex-col gap-2 border-l-2 border-ng-border pl-4 sm:flex-row sm:items-start sm:justify-between"
            >
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={event.severity} />
                  <span className="text-xs uppercase tracking-wide text-gray-500">
                    {event.event_type}
                  </span>
                </div>
                <p className="mt-1 text-sm text-gray-200">{event.summary}</p>
              </div>
              <time className="shrink-0 text-xs text-gray-500">
                {formatTimestamp(event.timestamp)}
              </time>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
