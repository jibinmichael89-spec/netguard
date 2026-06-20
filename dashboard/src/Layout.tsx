import { Outlet } from "react-router-dom";
import { useCallback, useEffect, useState } from "react";
import Navbar from "./components/Navbar";
import { apiFetch } from "./api";
import type { DevicesResponse } from "./types";

export default function Layout() {
  const [lastScanTime, setLastScanTime] = useState<string | null>(null);

  const refreshLastScan = useCallback(async () => {
    try {
      const data = await apiFetch<DevicesResponse>("/devices");
      if (data.devices.length > 0) {
        const latest = data.devices.reduce((max, device) =>
          device.last_seen > max ? device.last_seen : max,
        data.devices[0].last_seen);
        setLastScanTime(latest);
      }
    } catch {
      /* Navbar scan time is best-effort */
    }
  }, []);

  useEffect(() => {
    refreshLastScan();
    const interval = setInterval(refreshLastScan, 30_000);
    return () => clearInterval(interval);
  }, [refreshLastScan]);

  return (
    <div className="min-h-screen bg-ng-bg">
      <Navbar lastScanTime={lastScanTime} />
      <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
        <Outlet />
      </main>
    </div>
  );
}
