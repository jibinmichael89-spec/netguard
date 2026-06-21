import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Monitor,
  Wifi,
  UserPlus,
  ShieldAlert,
} from "lucide-react";
import { apiFetch } from "../api";
import type {
  Device,
  DeviceBlockResponse,
  DeviceTrustResponse,
  DevicesResponse,
  RiskSummaryResponse,
} from "../types";
import { DASHBOARD_REFRESH_MS, NEW_DEVICE_WINDOW_HOURS } from "../config";
import { isRecentlyAdded } from "../utils/format";
import StatCard from "../components/StatCard";
import DeviceTable from "../components/DeviceTable";
import TagModal from "../components/TagModal";
import LoadingSpinner from "../components/LoadingSpinner";
import ScannerOffline from "../components/ScannerOffline";

type DeviceFilterType = "online" | "new" | "dangerous" | null;

const FILTER_LABELS: Record<Exclude<DeviceFilterType, null>, string> = {
  online: "Online Devices",
  new: "New Devices",
  dangerous: "Security Findings",
};

function filterDevices(
  devices: Device[],
  filterType: DeviceFilterType,
): Device[] {
  if (filterType === null) {
    return devices;
  }
  if (filterType === "online") {
    return devices.filter(
      (device) => device.status.toLowerCase() === "online",
    );
  }
  if (filterType === "new") {
    return devices.filter((device) =>
      isRecentlyAdded(device.first_seen, NEW_DEVICE_WINDOW_HOURS),
    );
  }
  return devices.filter(
    (device) =>
      device.risk_level === "Critical" || device.risk_level === "High",
  );
}

function unblockedDevices(devices: Device[]): Device[] {
  return devices.filter((device) => (device.is_blocked ?? 0) !== 1);
}

export default function DashboardPage() {
  const [devices, setDevices] = useState<DevicesResponse["devices"]>([]);
  const [riskSummary, setRiskSummary] = useState<RiskSummaryResponse | null>(
    null,
  );
  const [filterType, setFilterType] = useState<DeviceFilterType>(null);
  const [showBlockedDevices, setShowBlockedDevices] = useState(false);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string>();
  const [tagModalDevice, setTagModalDevice] = useState<Device | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionLoadingId, setActionLoadingId] = useState<number | null>(null);

  const fetchData = useCallback(async (isInitial = false) => {
    if (isInitial) setLoading(true);
    try {
      const [devicesRes, riskRes] = await Promise.all([
        apiFetch<DevicesResponse>("/devices?include_blocked=true"),
        apiFetch<RiskSummaryResponse>("/risk/summary"),
      ]);
      setDevices(devicesRes.devices);
      setRiskSummary(riskRes);
      setOffline(false);
      setErrorMessage(undefined);
    } catch (error) {
      setOffline(true);
      setErrorMessage(
        error instanceof Error ? error.message : "Failed to load dashboard data",
      );
    } finally {
      if (isInitial) setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData(true);
    const interval = setInterval(() => fetchData(false), DASHBOARD_REFRESH_MS);
    return () => clearInterval(interval);
  }, [fetchData]);

  const activeDevices = useMemo(() => unblockedDevices(devices), [devices]);

  const visibleDevices = useMemo(
    () => (showBlockedDevices ? devices : activeDevices),
    [devices, showBlockedDevices, activeDevices],
  );

  const filteredDevices = useMemo(
    () => filterDevices(visibleDevices, filterType),
    [visibleDevices, filterType],
  );

  const toggleFilter = (type: Exclude<DeviceFilterType, null>) => {
    setFilterType((current) => (current === type ? null : type));
  };

  const handleTrustToggle = async (device: Device) => {
    setActionError(null);
    setActionLoadingId(device.id);
    try {
      await apiFetch<DeviceTrustResponse>(
        `/devices/id/${device.id}/trust`,
        {
          method: "PUT",
          body: JSON.stringify({ is_trusted: (device.is_trusted ?? 0) !== 1 }),
        },
      );
      await fetchData(false);
    } catch (error) {
      setActionError(
        error instanceof Error ? error.message : "Failed to update trust status",
      );
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleBlockToggle = async (device: Device) => {
    setActionError(null);
    setActionLoadingId(device.id);
    try {
      await apiFetch<DeviceBlockResponse>(
        `/devices/id/${device.id}/block`,
        {
          method: "PUT",
          body: JSON.stringify({ is_blocked: (device.is_blocked ?? 0) !== 1 }),
        },
      );
      await fetchData(false);
    } catch (error) {
      setActionError(
        error instanceof Error ? error.message : "Failed to update block status",
      );
    } finally {
      setActionLoadingId(null);
    }
  };

  if (loading) {
    return <LoadingSpinner label="Loading network data..." fullPage />;
  }

  if (offline) {
    const hint =
      errorMessage?.includes("Database not found") ||
      errorMessage?.includes("Start the ARP scanner")
        ? " Start Menu → NetGuard → ARP Scanner, wait 30 seconds, then click Retry."
        : errorMessage?.includes("Service Unavailable")
          ? " Try http://127.0.0.1:8000 (not http://0.0.0.0:8000). Run ARP Scanner first."
          : "";
    return (
      <ScannerOffline
        message={(errorMessage ?? "Unable to reach the NetGuard API.") + hint}
        onRetry={() => fetchData(true)}
      />
    );
  }

  const onlineCount = activeDevices.filter(
    (device) => device.status.toLowerCase() === "online",
  ).length;
  const newCount = activeDevices.filter((device) =>
    isRecentlyAdded(device.first_seen, NEW_DEVICE_WINDOW_HOURS),
  ).length;
  const blockedCount = devices.filter(
    (device) => (device.is_blocked ?? 0) === 1,
  ).length;

  const criticalCount = riskSummary?.critical_count ?? 0;
  const highCount = riskSummary?.high_count ?? 0;
  const mediumCount = riskSummary?.medium_count ?? 0;
  const highRiskHeadline = criticalCount + highCount;
  const riskBreakdownSubtitle = `${criticalCount} Critical, ${highCount} High, ${mediumCount} Medium`;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white">Dashboard</h2>
        <p className="mt-1 text-sm text-gray-400">
          Real-time overview of your home network security
        </p>
      </div>

      {devices.length === 0 && (
        <div className="rounded-lg border border-ng-warning/30 bg-ng-warning/10 px-4 py-3 text-sm text-ng-warning">
          Scanning your network now. Devices, open ports, and DNS activity will
          appear automatically within about a minute.
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Total Devices"
          value={activeDevices.length}
          icon={<Monitor className="h-5 w-5" />}
          accent="accent"
          onClick={() => setFilterType(null)}
          active={filterType === null}
        />
        <StatCard
          label="Online Now"
          value={onlineCount}
          icon={<Wifi className="h-5 w-5" />}
          accent="safe"
          onClick={() => toggleFilter("online")}
          active={filterType === "online"}
        />
        <StatCard
          label="New Devices"
          value={newCount}
          icon={<UserPlus className="h-5 w-5" />}
          accent="warning"
          onClick={() => toggleFilter("new")}
          active={filterType === "new"}
        />
        <StatCard
          label="Security Findings"
          value={highRiskHeadline}
          subtitle={riskBreakdownSubtitle}
          icon={<ShieldAlert className="h-5 w-5" />}
          accent={highRiskHeadline > 0 ? "alert" : "safe"}
          onClick={() => toggleFilter("dangerous")}
          active={filterType === "dangerous"}
        />
      </div>

      {filterType !== null && (
        <div className="flex flex-wrap items-center gap-3">
          <span className="rounded-full bg-ng-accent/15 px-3 py-1 text-sm text-ng-accent">
            Filtered by: {FILTER_LABELS[filterType]} ({filteredDevices.length})
          </span>
          <button
            type="button"
            onClick={() => setFilterType(null)}
            className="text-sm text-gray-400 transition hover:text-white"
          >
            Clear filter
          </button>
        </div>
      )}

      {actionError && (
        <p className="rounded-lg border border-ng-alert/40 bg-ng-alert/10 px-4 py-2 text-sm text-ng-alert">
          {actionError}
        </p>
      )}

      <DeviceTable
        devices={filteredDevices}
        totalCount={visibleDevices.length}
        search={search}
        onSearchChange={setSearch}
        onTagClick={setTagModalDevice}
        onTrustToggle={handleTrustToggle}
        onBlockToggle={handleBlockToggle}
        filterActive={filterType !== null}
        showBlockedDevices={showBlockedDevices}
        actionLoadingId={actionLoadingId}
      />

      <label className="flex items-center gap-2 text-sm text-gray-400">
        <input
          type="checkbox"
          checked={showBlockedDevices}
          onChange={(e) => setShowBlockedDevices(e.target.checked)}
          className="h-4 w-4 rounded border-ng-border bg-ng-elevated accent-[#00D4FF]"
        />
        Show blocked devices
        {showBlockedDevices && blockedCount > 0 && (
          <span className="rounded-full bg-ng-alert/15 px-2 py-0.5 text-xs text-ng-alert">
            {blockedCount} blocked
          </span>
        )}
      </label>

      <TagModal
        isOpen={tagModalDevice !== null}
        deviceIp={tagModalDevice?.ip_address ?? ""}
        currentTag={tagModalDevice?.device_tag ?? null}
        onClose={() => setTagModalDevice(null)}
        onSaved={() => fetchData(false)}
      />
    </div>
  );
}
