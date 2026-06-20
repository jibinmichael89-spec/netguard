interface SeverityBadgeProps {
  severity: string;
}

const SEVERITY_STYLES: Record<string, string> = {
  Critical: "bg-ng-alert/20 text-ng-alert border-ng-alert/40 animate-pulse-critical",
  High: "bg-orange-500/20 text-orange-400 border-orange-500/40",
  Medium: "bg-ng-warning/20 text-ng-warning border-ng-warning/40",
  Low: "bg-blue-500/20 text-blue-400 border-blue-500/40",
};

export default function SeverityBadge({ severity }: SeverityBadgeProps) {
  const style =
    SEVERITY_STYLES[severity] ??
    "bg-gray-500/20 text-gray-400 border-gray-500/40";

  return (
    <span
      className={`inline-flex rounded-full border px-2.5 py-0.5 text-xs font-bold uppercase tracking-wide ${style}`}
    >
      {severity}
    </span>
  );
}
