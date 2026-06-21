import { useState } from "react";
import { Link } from "react-router-dom";
import {
  Check,
  Computer,
  Cpu,
  Gamepad2,
  Printer,
  Router,
  Search,
  Smartphone,
  Tv,
  type LucideIcon,
} from "lucide-react";
import type { Device } from "../types";
import { NEW_DEVICE_WINDOW_HOURS } from "../config";
import { formatTimestamp, isRecentlyAdded } from "../utils/format";
import { useSystemDetection } from "../hooks/useSystemDetection";
import StatusBadge from "./StatusBadge";
import BlockConfirmDialog from "./BlockConfirmDialog";
import BlockHelpTooltip from "./BlockHelpTooltip";
import RiskDetailModal, { RiskBadge } from "./RiskDetailModal";

const DEVICE_COLUMN_COUNT = 11;

const CATEGORY_ICON_MAP: Record<string, LucideIcon> = {
  Computer: Computer,
  Phone: Smartphone,
  "Smart TV": Tv,
  "Gaming Console": Gamepad2,
  Printer: Printer,
  Router: Router,
  IoT: Cpu,
};

function DeviceCategoryCell({ category }: { category: string | null }) {
  if (!category) {
    return <span className="text-gray-500">—</span>;
  }

  const Icon = CATEGORY_ICON_MAP[category] ?? Cpu;

  return (
    <span className="inline-flex items-center gap-1.5 text-gray-300">
      <Icon className="h-3.5 w-3.5 shrink-0 text-gray-400" aria-hidden />
      <span>{category}</span>
    </span>
  );
}

function VendorCell({
  vendor,
  osGuess,
  osConfidence,
  showUnknownWarning,
}: {
  vendor: string | null;
  osGuess: string | null;
  osConfidence: Device["os_confidence"];
  showUnknownWarning: boolean;
}) {
  const lowConfidence = osConfidence === "Low";

  return (
    <div className="flex flex-col gap-0.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-gray-300">{vendor ?? "Unknown"}</span>
        {showUnknownWarning && (
          <span className="rounded bg-ng-warning/20 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-ng-warning">
            Warning
          </span>
        )}
      </div>
      {osGuess && (
        <span
          className={`text-xs text-gray-500 ${
            lowConfidence ? "opacity-60" : ""
          }`}
        >
          {osGuess}
        </span>
      )}
    </div>
  );
}

interface DeviceTableProps {
  devices: Device[];
  totalCount?: number;
  search: string;
  onSearchChange: (value: string) => void;
  onTagClick: (device: Device) => void;
  onTrustToggle: (device: Device) => void;
  onBlockToggle: (device: Device) => Promise<void>;
  filterActive?: boolean;
  showBlockedDevices?: boolean;
  actionLoadingId?: number | null;
}

export default function DeviceTable({
  devices,
  totalCount,
  search,
  onSearchChange,
  onTagClick,
  onTrustToggle,
  onBlockToggle,
  filterActive = false,
  showBlockedDevices = false,
  actionLoadingId = null,
}: DeviceTableProps) {
  const { systemType } = useSystemDetection();
  const [blockModalDevice, setBlockModalDevice] = useState<Device | null>(null);
  const [blockModalLoading, setBlockModalLoading] = useState(false);
  const [riskModalDevice, setRiskModalDevice] = useState<Device | null>(null);

  const query = search.toLowerCase().trim();
  const filtered = devices.filter((device) => {
    if (!query) return true;
    return (
      device.ip_address.toLowerCase().includes(query) ||
      (device.hostname?.toLowerCase().includes(query) ?? false) ||
      (device.vendor?.toLowerCase().includes(query) ?? false) ||
      (device.device_tag?.toLowerCase().includes(query) ?? false) ||
      (device.device_category?.toLowerCase().includes(query) ?? false) ||
      (device.os_guess?.toLowerCase().includes(query) ?? false) ||
      (device.risk_level?.toLowerCase().includes(query) ?? false)
    );
  });

  const handleBlockConfirm = async () => {
    if (!blockModalDevice) return;
    setBlockModalLoading(true);
    try {
      await onBlockToggle(blockModalDevice);
      setBlockModalDevice(null);
    } finally {
      setBlockModalLoading(false);
    }
  };

  const blockModalIsBlocked = (blockModalDevice?.is_blocked ?? 0) === 1;

  return (
    <>
      <div className="rounded-xl border border-ng-border bg-ng-card">
        <div className="flex flex-col gap-4 border-b border-ng-border p-4 sm:flex-row sm:items-center sm:justify-between">
          <h2 className="text-lg font-semibold text-white">
            Network Devices
            {totalCount !== undefined && (
              <span className="ml-2 text-sm font-normal text-gray-400">
                ({devices.length}
                {filterActive && totalCount !== devices.length
                  ? ` of ${totalCount}`
                  : ""}
                )
              </span>
            )}
          </h2>
          <div className="relative w-full sm:max-w-xs">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
            <input
              type="search"
              placeholder="Search IP, hostname, vendor, tag..."
              value={search}
              onChange={(e) => onSearchChange(e.target.value)}
              className="w-full rounded-lg border border-ng-border bg-ng-elevated py-2 pl-10 pr-4 text-sm text-white placeholder-gray-500 outline-none focus:border-ng-accent/50"
            />
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[1160px] text-left text-sm">
            <thead>
              <tr className="border-b border-ng-border text-xs uppercase tracking-wider text-gray-500">
                <th className="px-4 py-3 font-medium">IP Address</th>
                <th className="px-4 py-3 font-medium">MAC</th>
                <th className="px-4 py-3 font-medium">Vendor</th>
                <th className="px-4 py-3 font-medium">Device Type</th>
                <th className="px-4 py-3 font-medium">Risk</th>
                <th className="px-4 py-3 font-medium">Tag</th>
                <th className="px-4 py-3 font-medium">Trusted</th>
                <th className="px-4 py-3 font-medium">
                  <span className="inline-flex items-center gap-1.5">
                    Block
                    <BlockHelpTooltip systemType={systemType} />
                  </span>
                </th>
                <th className="px-4 py-3 font-medium">Hostname</th>
                <th className="px-4 py-3 font-medium">Connection</th>
                <th className="px-4 py-3 font-medium">First Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ng-border">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={DEVICE_COLUMN_COUNT} className="px-4 py-8 text-center text-gray-500">
                    {query
                      ? "No devices match your search."
                      : filterActive
                        ? "No devices match this filter."
                        : "No devices found."}
                  </td>
                </tr>
              ) : (
                filtered.map((device) => {
                  const isNew = isRecentlyAdded(
                    device.first_seen,
                    NEW_DEVICE_WINDOW_HOURS,
                  );
                  const unknownVendor =
                    !device.vendor || device.vendor === "Unknown";
                  const isTrusted = (device.is_trusted ?? 0) === 1;
                  const isBlocked = (device.is_blocked ?? 0) === 1;

                  return (
                    <tr
                      key={device.id}
                      className={`transition ${
                        isBlocked && showBlockedDevices
                          ? "bg-ng-alert/10 line-through decoration-ng-alert/60 hover:bg-ng-alert/15"
                          : isTrusted
                            ? "bg-ng-safe/5 hover:bg-ng-safe/10"
                            : "hover:bg-ng-elevated/50"
                      }`}
                    >
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <Link
                            to={`/device/${device.ip_address}`}
                            className={`font-mono text-ng-accent hover:underline ${
                              isBlocked && showBlockedDevices ? "line-through" : ""
                            }`}
                          >
                            {device.ip_address}
                          </Link>
                          {isNew && (
                            <span className="rounded bg-ng-accent/20 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-ng-accent">
                              New
                            </span>
                          )}
                          {isBlocked && showBlockedDevices && (
                            <span className="rounded bg-ng-alert/20 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-ng-alert not-italic">
                              Blocked
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-gray-400">
                        {device.mac_address}
                      </td>
                      <td className="px-4 py-3">
                        <VendorCell
                          vendor={device.vendor}
                          osGuess={device.os_guess}
                          osConfidence={device.os_confidence}
                          showUnknownWarning={unknownVendor}
                        />
                      </td>
                      <td className="px-4 py-3">
                        <DeviceCategoryCell category={device.device_category} />
                      </td>
                      <td className="px-4 py-3">
                        <RiskBadge
                          level={device.risk_level}
                          onClick={() => setRiskModalDevice(device)}
                        />
                      </td>
                      <td className="px-4 py-3">
                        <button
                          type="button"
                          onClick={() => onTagClick(device)}
                          className="text-left transition hover:text-ng-accent"
                        >
                          {device.device_tag ? (
                            <span className="rounded bg-ng-accent/15 px-2 py-0.5 text-xs font-medium text-ng-accent">
                              {device.device_tag}
                            </span>
                          ) : (
                            <span className="text-xs italic text-gray-500">
                              Add tag
                            </span>
                          )}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <button
                          type="button"
                          onClick={() => onTrustToggle(device)}
                          disabled={actionLoadingId === device.id}
                          className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs font-medium transition disabled:opacity-50 ${
                            isTrusted
                              ? "border-ng-safe/40 bg-ng-safe/15 text-ng-safe"
                              : "border-ng-border bg-ng-elevated text-gray-400 hover:border-ng-safe/40"
                          }`}
                          aria-pressed={isTrusted}
                        >
                          {isTrusted && <Check className="h-3 w-3" />}
                          {isTrusted ? "Trusted" : "Trust"}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <div className="inline-flex items-center gap-1.5">
                          <button
                            type="button"
                            onClick={() => setBlockModalDevice(device)}
                            disabled={actionLoadingId === device.id}
                            className={`rounded-lg px-3 py-1 text-xs font-semibold transition disabled:opacity-50 ${
                              isBlocked
                                ? "bg-ng-safe/15 text-ng-safe hover:bg-ng-safe/25"
                                : "bg-ng-alert/15 text-ng-alert hover:bg-ng-alert/25"
                            }`}
                          >
                            {actionLoadingId === device.id
                              ? "..."
                              : isBlocked
                                ? "Unblock"
                                : "Block"}
                          </button>
                          <BlockHelpTooltip systemType={systemType} />
                        </div>
                      </td>
                      <td className="px-4 py-3 text-gray-300">
                        {device.hostname ?? "—"}
                      </td>
                      <td className="px-4 py-3">
                        <StatusBadge status={device.status} />
                      </td>
                      <td className="px-4 py-3 text-gray-400">
                        {formatTimestamp(device.first_seen)}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      <RiskDetailModal
        device={riskModalDevice}
        onClose={() => setRiskModalDevice(null)}
      />

      <BlockConfirmDialog
        open={blockModalDevice !== null}
        isBlocked={blockModalIsBlocked}
        systemType={systemType}
        loading={blockModalLoading || actionLoadingId === blockModalDevice?.id}
        onConfirm={handleBlockConfirm}
        onOpenChange={(open) => {
          if (!open && !blockModalLoading) {
            setBlockModalDevice(null);
          }
        }}
      />
    </>
  );
}
