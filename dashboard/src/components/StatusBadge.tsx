interface StatusBadgeProps {
  status: string;
}

export default function StatusBadge({ status }: StatusBadgeProps) {
  const online = status.toLowerCase() === "online";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-semibold ${
        online
          ? "bg-ng-safe/15 text-ng-safe"
          : "bg-gray-500/15 text-gray-400"
      }`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${online ? "bg-ng-safe" : "bg-gray-500"}`}
      />
      {online ? "Online" : "Offline"}
    </span>
  );
}
