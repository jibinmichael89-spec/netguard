import { HelpCircle } from "lucide-react";
import type { BlockPlatform } from "../utils/blockPlatform";
import { getBlockTooltip } from "../utils/blockPlatform";

interface BlockHelpTooltipProps {
  platform: BlockPlatform;
}

export default function BlockHelpTooltip({ platform }: BlockHelpTooltipProps) {
  const tooltip = getBlockTooltip(platform);

  return (
    <span className="group relative inline-flex">
      <button
        type="button"
        className="text-gray-500 transition hover:text-gray-300"
        aria-label={tooltip}
        tabIndex={-1}
      >
        <HelpCircle className="h-3.5 w-3.5" />
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
