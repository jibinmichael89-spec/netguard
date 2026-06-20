import type { ReactNode } from "react";

interface StatCardProps {
  label: string;
  value: number | string;
  icon: ReactNode;
  accent?: "default" | "safe" | "warning" | "alert" | "accent";
  onClick?: () => void;
  active?: boolean;
}

const ACCENT_STYLES = {
  default: "text-white",
  safe: "text-ng-safe",
  warning: "text-ng-warning",
  alert: "text-ng-alert",
  accent: "text-ng-accent",
};

export default function StatCard({
  label,
  value,
  icon,
  accent = "default",
  onClick,
  active = false,
}: StatCardProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`w-full rounded-xl border bg-ng-card p-5 text-left transition ${
        active
          ? "border-ng-accent bg-ng-accent/10 ring-1 ring-ng-accent/30"
          : "border-ng-border hover:border-ng-accent/30"
      } ${onClick ? "cursor-pointer" : ""}`}
    >
      <div className="mb-3 flex items-center justify-between">
        <span className="text-sm font-medium text-gray-400">{label}</span>
        <span className="text-ng-accent/70">{icon}</span>
      </div>
      <p className={`text-3xl font-bold tracking-tight ${ACCENT_STYLES[accent]}`}>
        {value}
      </p>
    </button>
  );
}
