import { HelpCircle } from "lucide-react";
import type { SystemType } from "../hooks/useSystemDetection";
import { getBlockTooltip } from "../utils/blockMessages";

interface BlockHelpTooltipProps {
  systemType: SystemType;
}

export default function BlockHelpTooltip({ systemType }: BlockHelpTooltipProps) {
  const tooltip = getBlockTooltip(systemType);

  return (
    <span className="group relative inline-flex">
      <button
        type="button"
        className="text-gray-500 transition hover:text-gray-300"
        aria-label={tooltip}
      >
        <HelpCircle className="h-3.5 w-3.5" aria-hidden="true" />
      </button>
      <span
        role="tooltip"
        className="pointer-events-none absolute bottom-full left-1/2 z-20 mb-2 w-48 -translate-x-1/2 rounded-lg border border-ng-border bg-ng-elevated px-2.5 py-1.5 text-center text-[11px] leading-snug text-gray-300 opacity-0 shadow-lg transition group-hover:opacity-100 group-focus-within:opacity-100"
      >
        {tooltip}
      </span>
    </span>
  );
}
