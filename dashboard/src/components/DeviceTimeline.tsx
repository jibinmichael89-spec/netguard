import { useState } from "react";
import { apiFetch } from "../api";
import type { DeviceTimelineResponse } from "../types";
import { formatTimestamp } from "../utils/format";
import SeverityBadge from "./SeverityBadge";
import LoadingSpinner from "./LoadingSpinner";

interface DeviceTimelineProps {
  deviceIp: string;
}

export default function DeviceTimeline({ deviceIp }: DeviceTimelineProps) {
  const [events, setEvents] = useState<DeviceTimelineResponse["events"]>([]);
  const [loading, setLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);

  const load = async () => {
    if (loaded) return;
    setLoading(true);
    try {
      const res = await apiFetch<DeviceTimelineResponse>(
        `/devices/${encodeURIComponent(deviceIp)}/timeline`,
      );
      setEvents(res.events);
      setLoaded(true);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="rounded-xl border border-ng-border bg-ng-card p-5">
      <div className="mb-4 flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Activity Timeline</h3>
        {!loaded && (
          <button
            type="button"
            onClick={load}
            className="text-sm font-medium text-ng-accent hover:underline"
          >
            Load timeline
          </button>
        )}
      </div>
      {loading ? (
        <LoadingSpinner label="Loading timeline..." />
      ) : events.length === 0 ? (
        <p className="text-sm text-gray-400">
          {loaded ? "No timeline events yet." : "Click load to fetch device activity."}
        </p>
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
