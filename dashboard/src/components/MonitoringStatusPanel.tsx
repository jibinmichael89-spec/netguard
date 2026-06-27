import {
  Activity,
  Radar,
  Shield,
  ShieldCheck,
  ShieldOff,
} from "lucide-react";
import type {
  MonitoringDetector,
  MonitoringOverallStatus,
  MonitoringStatusResponse,
} from "../types";
import { formatRelativeTime, formatTimestamp } from "../utils/format";

interface MonitoringStatusPanelProps {
  status: MonitoringStatusResponse;
}

const OVERALL_META: Record<
  MonitoringOverallStatus,
  { label: string; detail: string; className: string; icon: typeof ShieldCheck }
> = {
  watching: {
    label: "Actively monitoring",
    detail: "Core scanners are running and your network is being watched.",
    className: "text-ng-safe border-ng-safe/30 bg-ng-safe/10",
    icon: ShieldCheck,
  },
  degraded: {
    label: "Partially active",
    detail:
      "Some core services are stopped or unavailable. Check systemd or scanner processes.",
    className: "text-ng-warning border-ng-warning/30 bg-ng-warning/10",
    icon: Shield,
  },
  offline: {
    label: "Monitoring offline",
    detail: "Core scanners have not reported recently. Start the ARP scanner and API.",
    className: "text-ng-alert border-ng-alert/30 bg-ng-alert/10",
    icon: ShieldOff,
  },
};

const DETECTOR_STATUS_META: Record<
  MonitoringDetector["status"],
  { label: string; dotClass: string; textClass: string }
> = {
  active: {
    label: "Active",
    dotClass: "bg-ng-safe",
    textClass: "text-ng-safe",
  },
  idle: {
    label: "Running — no events",
    dotClass: "bg-ng-safe",
    textClass: "text-ng-safe",
  },
  stopped: {
    label: "Service stopped",
    dotClass: "bg-ng-alert",
    textClass: "text-ng-alert",
  },
  stale: {
    label: "Delayed",
    dotClass: "bg-ng-warning",
    textClass: "text-ng-warning",
  },
  inactive: {
    label: "Inactive",
    dotClass: "bg-ng-alert",
    textClass: "text-ng-alert",
  },
  standby: {
    label: "Standby",
    dotClass: "bg-gray-500",
    textClass: "text-gray-400",
  },
};

function detectorActivityLine(detector: MonitoringDetector): string {
  if (detector.status === "stopped") {
    return "Start the service to resume monitoring";
  }
  if (detector.status === "idle") {
    return detector.last_activity
      ? `Running — last event ${formatRelativeTime(detector.last_activity)}`
      : "Running — no events recorded yet";
  }
  if (detector.last_activity) {
    return `Last activity ${formatRelativeTime(detector.last_activity)}`;
  }
  return "No activity recorded yet";
}

export default function MonitoringStatusPanel({
  status,
}: MonitoringStatusPanelProps) {
  const overall = OVERALL_META[status.overall_status];
  const OverallIcon = overall.icon;

  return (
    <section className="rounded-xl border border-ng-border bg-ng-card p-5 sm:p-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-ng-accent" />
            <h3 className="text-lg font-semibold text-white">Monitoring Status</h3>
          </div>
          <p className="text-sm text-gray-400">
            NetGuard keeps watching even when there are zero alerts.
          </p>
        </div>

        <div
          className={`inline-flex items-center gap-2 self-start rounded-full border px-3 py-1.5 text-sm font-medium ${overall.className}`}
        >
          <OverallIcon className="h-4 w-4" />
          {overall.label}
        </div>
      </div>

      <p className="mt-3 text-sm text-gray-400">{overall.detail}</p>

      <div className="mt-5 grid gap-3 sm:grid-cols-2">
        <div className="rounded-lg border border-ng-border bg-ng-elevated px-4 py-3">
          <p className="text-xs font-medium uppercase tracking-wide text-gray-500">
            Last device scan
          </p>
          <p className="mt-1 text-sm font-semibold text-white">
            {formatTimestamp(status.last_device_scan)}
          </p>
          <p className="mt-0.5 text-xs text-gray-500">
            {formatRelativeTime(status.last_device_scan)}
          </p>
        </div>
        <div className="rounded-lg border border-ng-border bg-ng-elevated px-4 py-3">
          <p className="text-xs font-medium uppercase tracking-wide text-gray-500">
            Online devices
          </p>
          <p className="mt-1 text-sm font-semibold text-white">
            {status.online_device_count}
          </p>
          <p className="mt-0.5 text-xs text-gray-500">
            Currently visible on your LAN
          </p>
        </div>
      </div>

      <div className="mt-5">
        <div className="mb-3 flex items-center gap-2">
          <Radar className="h-4 w-4 text-ng-accent/80" />
          <h4 className="text-sm font-semibold text-gray-200">Detectors</h4>
        </div>
        <div className="space-y-2">
          {status.detectors.map((detector) => {
            const meta = DETECTOR_STATUS_META[detector.status];
            return (
              <div
                key={detector.id}
                className="flex flex-col gap-2 rounded-lg border border-ng-border bg-ng-elevated px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-white">{detector.name}</span>
                    {detector.optional && (
                      <span className="rounded bg-ng-card px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-gray-500">
                        Optional
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 text-sm text-gray-400">
                    {detector.description}
                  </p>
                </div>
                <div className="flex shrink-0 flex-col items-start sm:items-end">
                  <div className="flex items-center gap-2">
                    <span
                      className={`h-2.5 w-2.5 rounded-full ${meta.dotClass}`}
                      aria-hidden
                    />
                    <span className={`text-sm font-medium ${meta.textClass}`}>
                      {meta.label}
                    </span>
                  </div>
                  <p className="mt-0.5 text-xs text-gray-500">
                    {detectorActivityLine(detector)}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
