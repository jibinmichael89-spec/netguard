import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Check, ShieldBan, ShieldCheck } from "lucide-react";
import { apiFetch, apiFetchWithTimeout } from "../api";
import type {
  Device,
  DeviceBlockResponse,
  DevicesResponse,
  DeviceTrustResponse,
  PortRiskLevel,
  PortsResponse,
} from "../types";
import { PORT_FETCH_TIMEOUT_MS } from "../config";
import { formatTimestamp } from "../utils/format";
import { useSystemDetection, instructionPlatform } from "../hooks/useSystemDetection";
import StatusBadge from "../components/StatusBadge";
import ConfirmModal from "../components/ConfirmModal";
import BlockConfirmDialog from "../components/BlockConfirmDialog";
import BlockHelpTooltip from "../components/BlockHelpTooltip";
import PortInstructionsModal from "../components/PortInstructionsModal";
import RiskDetailModal, { PortRiskBadge, RiskBadge } from "../components/RiskDetailModal";
import DeviceTimeline from "../components/DeviceTimeline";
import LoadingSpinner from "../components/LoadingSpinner";
import ScannerOffline from "../components/ScannerOffline";

function resolvePortRiskLevel(
  port: PortsResponse["ports"][number],
): PortRiskLevel {
  if (port.port_risk_level) {
    return port.port_risk_level;
  }
  return port.is_dangerous === 1 ? "High" : "Safe";
}

export default function DeviceDetailPage() {
  const { ip } = useParams<{ ip: string }>();
  const { systemType } = useSystemDetection();
  const [device, setDevice] = useState<Device | null>(null);
  const [ports, setPorts] = useState<PortsResponse["ports"]>([]);
  const [portsError, setPortsError] = useState(false);
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);
  const [trustModalOpen, setTrustModalOpen] = useState(false);
  const [blockModalOpen, setBlockModalOpen] = useState(false);
  const [riskModalOpen, setRiskModalOpen] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [instructionsPort, setInstructionsPort] = useState<number | null>(null);

  const fetchDevice = useCallback(async () => {
    if (!ip) return;
    setLoading(true);
    setPortsError(false);

    try {
      const devicesRes = await apiFetch<DevicesResponse>(
        "/devices?include_blocked=true",
      );
      const match = devicesRes.devices.find((d) => d.ip_address === ip) ?? null;
      setDevice(match);
      setOffline(false);

      try {
        const portsRes = await apiFetchWithTimeout<PortsResponse>(
          `/ports/${encodeURIComponent(ip)}`,
          PORT_FETCH_TIMEOUT_MS,
        );
        setPorts(portsRes.ports);
      } catch {
        setPorts([]);
        setPortsError(true);
      }
    } catch {
      setOffline(true);
    } finally {
      setLoading(false);
    }
  }, [ip]);

  useEffect(() => {
    fetchDevice();
  }, [fetchDevice]);

  const handleTrustConfirm = async () => {
    if (!device) return;
    setActionLoading(true);
    try {
      await apiFetch<DeviceTrustResponse>(
        `/devices/id/${device.id}/trust`,
        {
          method: "PUT",
          body: JSON.stringify({ is_trusted: (device.is_trusted ?? 0) !== 1 }),
        },
      );
      setTrustModalOpen(false);
      await fetchDevice();
    } finally {
      setActionLoading(false);
    }
  };

  const handleBlockConfirm = async () => {
    if (!device) return;
    setActionLoading(true);
    try {
      await apiFetch<DeviceBlockResponse>(
        `/devices/id/${device.id}/block`,
        {
          method: "PUT",
          body: JSON.stringify({ is_blocked: (device.is_blocked ?? 0) !== 1 }),
        },
      );
      if ((device.is_blocked ?? 0) !== 1) {
        await apiFetch(`/enforcement/block/${encodeURIComponent(device.ip_address)}`, {
          method: "POST",
        });
      }
      setBlockModalOpen(false);
      await fetchDevice();
    } finally {
      setActionLoading(false);
    }
  };

  const handleApprove = async () => {
    if (!device) return;
    setActionLoading(true);
    try {
      await apiFetch(`/devices/${encodeURIComponent(device.ip_address)}/approve`, {
        method: "PUT",
      });
      await fetchDevice();
    } finally {
      setActionLoading(false);
    }
  };

  const handleReject = async () => {
    if (!device) return;
    setActionLoading(true);
    try {
      await apiFetch(`/devices/${encodeURIComponent(device.ip_address)}/reject`, {
        method: "PUT",
      });
      await fetchDevice();
    } finally {
      setActionLoading(false);
    }
  };

  if (loading) {
    return <LoadingSpinner label="Loading device details..." fullPage />;
  }

  if (offline) {
    return <ScannerOffline onRetry={fetchDevice} />;
  }

  if (!device) {
    return (
      <div className="space-y-4 text-center">
        <p className="text-gray-400">Device {ip} not found.</p>
        <Link to="/" className="text-ng-accent hover:underline">
          Back to Dashboard
        </Link>
      </div>
    );
  }

  const isTrusted = (device.is_trusted ?? 0) === 1;
  const isBlocked = (device.is_blocked ?? 0) === 1;
  const isPending = device.approval_status === "pending";

  return (
    <div className="space-y-6">
      <Link
        to="/"
        className="inline-flex items-center gap-1 text-sm text-gray-400 transition hover:text-ng-accent"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to Dashboard
      </Link>

      <div
        className={`rounded-xl border bg-ng-card p-6 ${
          isBlocked
            ? "border-ng-alert/40 bg-ng-alert/5"
            : isTrusted
              ? "border-ng-safe/30 bg-ng-safe/5"
              : "border-ng-border"
        }`}
      >
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="font-mono text-2xl font-bold text-white">
              {device.ip_address}
            </h2>
            <p className="mt-1 text-gray-400">
              {device.hostname ?? "No hostname"}
            </p>
            <div className="mt-2 flex flex-wrap gap-2">
              {device.device_tag && (
                <span className="inline-flex rounded-full bg-ng-accent/15 px-3 py-1 text-xs font-semibold text-ng-accent">
                  {device.device_tag}
                </span>
              )}
              {isTrusted && (
                <span className="inline-flex items-center gap-1 rounded-full bg-ng-safe/15 px-3 py-1 text-xs font-semibold text-ng-safe">
                  <Check className="h-3 w-3" />
                  Trusted
                </span>
              )}
              {isBlocked && (
                <span className="inline-flex items-center gap-1 rounded-full bg-ng-alert/15 px-3 py-1 text-xs font-semibold text-ng-alert">
                  <ShieldBan className="h-3 w-3" />
                  Blocked
                </span>
              )}
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <StatusBadge status={device.status} />
            <RiskBadge
              level={device.risk_level}
              onClick={() => setRiskModalOpen(true)}
            />
          </div>
        </div>

        <div className="mt-6 flex flex-wrap gap-3">
          {isPending && (
            <>
              <button
                type="button"
                disabled={actionLoading}
                onClick={handleApprove}
                className="inline-flex items-center gap-2 rounded-lg bg-ng-safe px-4 py-2 text-sm font-semibold text-ng-bg"
              >
                Approve device
              </button>
              <button
                type="button"
                disabled={actionLoading}
                onClick={handleReject}
                className="inline-flex items-center gap-2 rounded-lg border border-ng-alert/40 px-4 py-2 text-sm font-semibold text-ng-alert"
              >
                Reject & block
              </button>
            </>
          )}
          <button
            type="button"
            onClick={() => setTrustModalOpen(true)}
            className={`inline-flex items-center gap-2 rounded-lg border px-4 py-2 text-sm font-medium transition ${
              isTrusted
                ? "border-ng-safe/40 bg-ng-safe/15 text-ng-safe"
                : "border-ng-border bg-ng-elevated text-gray-300 hover:border-ng-safe/40"
            }`}
          >
            <ShieldCheck className="h-4 w-4" />
            {isTrusted ? "Remove Trusted Status" : "Mark as Trusted"}
          </button>
          <div className="inline-flex items-center gap-2">
            <button
              type="button"
              onClick={() => setBlockModalOpen(true)}
              className={`inline-flex items-center gap-2 rounded-lg border px-4 py-2 text-sm font-medium transition ${
                isBlocked
                  ? "border-ng-safe/40 bg-ng-safe/15 text-ng-safe"
                  : "border-ng-alert/40 bg-ng-alert/15 text-ng-alert"
              }`}
            >
              <ShieldBan className="h-4 w-4" />
              {isBlocked ? "Unblock This Device" : "Block This Device"}
            </button>
            <BlockHelpTooltip systemType={systemType} />
          </div>
        </div>

        <dl className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div>
            <dt className="text-xs uppercase tracking-wider text-gray-500">
              MAC Address
            </dt>
            <dd className="mt-1 font-mono text-sm text-gray-300">
              {device.mac_address}
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wider text-gray-500">
              Vendor
            </dt>
            <dd className="mt-1 text-sm text-gray-300">
              {device.vendor ?? "Unknown"}
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wider text-gray-500">
              First Seen
            </dt>
            <dd className="mt-1 text-sm text-gray-300">
              {formatTimestamp(device.first_seen)}
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wider text-gray-500">
              Last Seen
            </dt>
            <dd className="mt-1 text-sm text-gray-300">
              {formatTimestamp(device.last_seen)}
            </dd>
          </div>
        </dl>
      </div>

      <div className="rounded-xl border border-ng-border bg-ng-card">
        <div className="border-b border-ng-border p-4">
          <h3 className="text-lg font-semibold text-white">Open Ports</h3>
        </div>

        {portsError ? (
          <p className="px-4 py-8 text-center text-gray-500">
            Unable to load port data
          </p>
        ) : ports.length === 0 ? (
          <p className="px-4 py-8 text-center text-gray-500">
            No open ports detected yet. Port scans run automatically every 30
            seconds with device discovery.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[560px] text-left text-sm">
              <thead>
                <tr className="border-b border-ng-border text-xs uppercase tracking-wider text-gray-500">
                  <th className="px-4 py-3 font-medium">Port</th>
                  <th className="px-4 py-3 font-medium">Service Name</th>
                  <th className="px-4 py-3 font-medium">Risk</th>
                  <th className="px-4 py-3 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ng-border">
                {ports.map((port) => {
                  const dangerous = port.is_dangerous === 1;
                  const portRiskLevel = resolvePortRiskLevel(port);
                  const elevatedPortRisk =
                    portRiskLevel === "Critical" ||
                    portRiskLevel === "High" ||
                    portRiskLevel === "Medium";

                  return (
                    <tr
                      key={port.id}
                      className={
                        elevatedPortRisk || dangerous
                          ? "bg-ng-alert/5 hover:bg-ng-alert/10"
                          : "hover:bg-ng-elevated/50"
                      }
                    >
                      <td className="px-4 py-3 font-mono text-white">
                        {port.port}
                      </td>
                      <td className="px-4 py-3 text-gray-300">
                        {port.service_name ?? "—"}
                      </td>
                      <td className="px-4 py-3">
                        <div>
                          <PortRiskBadge level={portRiskLevel} />
                          {port.risk_reason && (
                            <p className="mt-1 text-xs text-gray-400">
                              {port.risk_reason}
                            </p>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <button
                          type="button"
                          onClick={() => setInstructionsPort(port.port)}
                          className={`rounded-lg border px-3 py-1 text-xs font-semibold transition ${
                            dangerous
                              ? "border-ng-alert/40 bg-ng-alert/10 text-ng-alert hover:bg-ng-alert/20"
                              : "border-ng-border bg-ng-elevated text-gray-300 hover:border-ng-accent/40 hover:text-ng-accent"
                          }`}
                        >
                          How to fix
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <DeviceTimeline deviceIp={device.ip_address} />

      <ConfirmModal
        isOpen={trustModalOpen}
        title={isTrusted ? "Remove Trusted Status" : "Mark as Trusted"}
        message={
          isTrusted
            ? `Remove trusted status from ${device.ip_address}?`
            : `Mark ${device.ip_address} as a trusted device on your network?`
        }
        confirmLabel={isTrusted ? "Remove Trust" : "Mark as Trusted"}
        loading={actionLoading}
        onConfirm={handleTrustConfirm}
        onClose={() => setTrustModalOpen(false)}
      />

      <BlockConfirmDialog
        open={blockModalOpen}
        isBlocked={isBlocked}
        systemType={systemType}
        loading={actionLoading}
        onConfirm={handleBlockConfirm}
        onOpenChange={setBlockModalOpen}
      />

      <RiskDetailModal
        device={riskModalOpen ? device : null}
        onClose={() => setRiskModalOpen(false)}
      />

      <PortInstructionsModal
        open={instructionsPort !== null}
        port={instructionsPort}
        defaultPlatform={instructionPlatform(systemType)}
        onClose={() => setInstructionsPort(null)}
      />
    </div>
  );
}
