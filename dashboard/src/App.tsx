import { HashRouter, Routes, Route } from "react-router-dom";
import Layout from "./Layout";
import DashboardPage from "./pages/DashboardPage";
import AlertsPage from "./pages/AlertsPage";
import DnsPage from "./pages/DnsPage";
import DnsDeviceDetailPage from "./pages/DnsDeviceDetailPage";
import DeviceDetailPage from "./pages/DeviceDetailPage";
import VaultPage from "./pages/VaultPage";
import SettingsPage from "./pages/SettingsPage";
import MspPage from "./pages/MspPage";

export default function App() {
  return (
    <HashRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/dns" element={<DnsPage />} />
          <Route path="/dns/device/:ip" element={<DnsDeviceDetailPage />} />
          <Route path="/device/:ip" element={<DeviceDetailPage />} />
          <Route path="/vault" element={<VaultPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/msp" element={<MspPage />} />
        </Route>
      </Routes>
    </HashRouter>
  );
}
