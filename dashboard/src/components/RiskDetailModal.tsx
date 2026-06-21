import { useEffect, useState } from "react";
import { ChevronDown, ChevronRight, Info, X } from "lucide-react";
import { apiFetch } from "../api";
import type {
  CveReferenceExample,
  CveReferenceResponse,
  Device,
  PortRiskLevel,
} from "../types";

export const DEVICE_RISK_BADGE_STYLES: Record<
  Exclude<NonNullable<Device["risk_level"]>, never>,
  string
> = {
  Critical: "border bg-red-600/20 text-red-400 border-red-600/40",
  High: "border bg-ng-alert/20 text-ng-alert border-ng-alert/40",
  Medium: "border bg-ng-warning/20 text-ng-warning border-ng-warning/40",
  Low: "border bg-ng-safe/15 text-ng-safe border-ng-safe/30",
  None: "text-xs text-gray-500",
};

export const PORT_RISK_BADGE_STYLES: Record<PortRiskLevel, string> = {
  Critical: "border bg-red-600/20 text-red-400 border-red-600/40",
  High: "border bg-ng-alert/20 text-ng-alert border-ng-alert/40",
  Medium: "border bg-ng-warning/20 text-ng-warning border-ng-warning/40",
  Low: "border bg-ng-safe/15 text-ng-safe border-ng-safe/30 text-xs",
  Safe: "text-xs text-gray-500",
};

function publishedYear(published: string | null): string {
  if (!published || published.length < 4) {
    return "—";
  }
  return published.slice(0, 4);
}

function FactorHistoricalContext({ port }: { port: number }) {
  const [expanded, setExpanded] = useState(false);
  const [examples, setExamples] = useState<CveReferenceExample[] | null>(null);

  useEffect(() => {
    let cancelled = false;

    apiFetch<CveReferenceResponse>(`/reference/cve/${port}`)
      .then((data) => {
        if (cancelled || data.no_data || data.examples.length === 0) {
          return;
        }
        setExamples(data.examples);
      })
      .catch(() => {
        /* reference data is optional — omit section on failure */
      });

    return () => {
      cancelled = true;
    };
  }, [port]);

  if (!examples || examples.length === 0) {
    return null;
  }

  return (
    <div className="mt-2 border-t border-ng-border/40 pt-2">
      <button
        type="button"
        onClick={() => setExpanded((current) => !current)}
        className="inline-flex items-center gap-1 text-xs text-gray-500 transition hover:text-gray-300"
        aria-expanded={expanded}
      >
        {expanded ? (
          <ChevronDown className="h-3.5 w-3.5 shrink-0" aria-hidden />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 shrink-0" aria-hidden />
        )}
        Historical context
      </button>

      {expanded && (
        <div className="mt-2 space-y-2">
          <p className="flex items-start gap-1.5 text-[11px] leading-relaxed text-gray-500">
            <Info className="mt-0.5 h-3 w-3 shrink-0 text-gray-600" aria-hidden />
            General reference examples for this type of exposure — not a
            confirmed finding on this specific device.
          </p>
          <ul className="space-y-1.5">
            {examples.map((example) => (
              <li
                key={example.cve_id}
                className="rounded border border-ng-border/50 bg-ng-bg/40 px-2 py-1.5 text-xs text-gray-400"
              >
                <span className="font-mono text-[11px] text-gray-300">
                  {example.cve_id}
                </span>
                <span className="mx-1.5 text-gray-600">·</span>
                <span>{example.description}</span>
                <span className="mx-1.5 text-gray-600">·</span>
                <span className="text-gray-500">
                  {publishedYear(example.published)}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export function RiskBadge({
  level,
  onClick,
}: {
  level: Device["risk_level"];
  onClick: () => void;
}) {
  if (level === null) {
    return <span className="text-gray-500">—</span>;
  }

  const isNone = level === "None";
  const className = isNone
    ? DEVICE_RISK_BADGE_STYLES.None
    : `rounded-full px-2.5 py-1 text-xs font-semibold transition hover:brightness-110 ${DEVICE_RISK_BADGE_STYLES[level]}`;

  return (
    <button
      type="button"
      onClick={onClick}
      className={className}
      aria-label={`View risk details: ${level}`}
    >
      {level}
    </button>
  );
}

export function PortRiskBadge({ level }: { level: PortRiskLevel }) {
  const isSafe = level === "Safe";
  const className = isSafe
    ? PORT_RISK_BADGE_STYLES.Safe
    : `inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${PORT_RISK_BADGE_STYLES[level]}`;

  return <span className={className}>{level}</span>;
}

export default function RiskDetailModal({
  device,
  onClose,
}: {
  device: Device | null;
  onClose: () => void;
}) {
  if (!device) {
    return null;
  }

  const factors = device.risk_factors ?? [];
  const hasFactors = factors.length > 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div
        className="w-full max-w-md rounded-xl border border-ng-border bg-ng-card p-6 shadow-xl"
        role="dialog"
        aria-labelledby="risk-detail-modal-title"
      >
        <div className="mb-4 flex items-center justify-between">
          <h3
            id="risk-detail-modal-title"
            className="text-lg font-semibold text-white"
          >
            Risk Assessment — {device.ip_address}
          </h3>
          <button
            type="button"
            onClick={onClose}
            className="text-gray-500 transition hover:text-white"
            aria-label="Close"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="mb-4 flex items-baseline gap-3">
          <span
            className={`text-2xl font-bold ${
              device.risk_level === "Critical"
                ? "text-red-400"
                : device.risk_level === "High"
                  ? "text-ng-alert"
                  : device.risk_level === "Medium"
                    ? "text-ng-warning"
                    : device.risk_level === "Low"
                      ? "text-ng-safe"
                      : "text-gray-400"
            }`}
          >
            {device.risk_level ?? "Not assessed"}
          </span>
          {device.risk_score !== null && (
            <span className="text-sm text-gray-400">
              Score: {device.risk_score}
            </span>
          )}
        </div>

        {hasFactors ? (
          <ul className="mb-6 max-h-80 space-y-2 overflow-y-auto">
            {factors.map((factor, index) => (
              <li
                key={`${factor.weight}-${factor.port ?? "x"}-${index}`}
                className="rounded-lg border border-ng-border bg-ng-elevated px-3 py-2 text-sm text-gray-300"
              >
                {factor.weight > 0 && (
                  <span className="mr-2 font-mono font-semibold text-ng-warning">
                    +{factor.weight}
                  </span>
                )}
                {factor.reason}
                {factor.port !== undefined && (
                  <FactorHistoricalContext port={factor.port} />
                )}
              </li>
            ))}
          </ul>
        ) : (
          <p className="mb-6 text-sm text-gray-400">
            No risk data available yet - this device needs more activity to be
            assessed
          </p>
        )}

        <div className="flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg border border-ng-border px-4 py-2 text-sm font-medium text-gray-300 transition hover:bg-ng-elevated"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
