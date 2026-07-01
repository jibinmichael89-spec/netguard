import { useCallback, useEffect, useState } from "react";
import {
  Bell,
  Copy,
  FileDown,
  KeyRound,
  RefreshCw,
  Router,
  Save,
  Server,
  Send,
  Shield,
  Mail,
} from "lucide-react";
import {
  apiFetch,
  clearStoredApiKey,
  downloadComplianceReport,
  getStoredApiKey,
  setStoredApiKey,
} from "../api";
import type {
  ApiKeyResponse,
  NotificationConfigResponse,
  PoliciesResponse,
  RouterConfigUpdate,
  RouterSettingsResponse,
  SyslogSettingsResponse,
  ThreatIntelStatusResponse,
} from "../types";

type Tab = "security" | "notifications" | "syslog" | "threat-intel" | "policies" | "router" | "reports";

const TABS: { id: Tab; label: string; icon: typeof Bell }[] = [
  { id: "security", label: "API key", icon: KeyRound },
  { id: "notifications", label: "Notifications", icon: Bell },
  { id: "syslog", label: "SIEM / Syslog", icon: Server },
  { id: "threat-intel", label: "Threat Intel", icon: Shield },
  { id: "policies", label: "Policies", icon: Shield },
  { id: "router", label: "Router", icon: Router },
  { id: "reports", label: "Reports", icon: Mail },
];

export default function SettingsPage() {
  const [tab, setTab] = useState<Tab>("security");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();
  const [message, setMessage] = useState<string>();

  const [apiKeyInput, setApiKeyInput] = useState("");
  const [apiKeyConfigured, setApiKeyConfigured] = useState(() => Boolean(getStoredApiKey()));
  const [displayedApiKey, setDisplayedApiKey] = useState<string | null>(null);
  const [showApiKey, setShowApiKey] = useState(false);
  const [verifyingApiKey, setVerifyingApiKey] = useState(false);
  const [loadingApiKey, setLoadingApiKey] = useState(false);

  const [notifConfig, setNotifConfig] = useState<Record<string, string>>({});
  const [syslogSettings, setSyslogSettings] = useState<SyslogSettingsResponse | null>(null);
  const [syslogForm, setSyslogForm] = useState({
    enabled: false,
    host: "",
    port: "514",
    protocol: "udp" as "udp" | "tcp",
  });
  const [savingSyslog, setSavingSyslog] = useState(false);
  const [threatIntel, setThreatIntel] = useState<ThreatIntelStatusResponse | null>(null);
  const [policies, setPolicies] = useState<PoliciesResponse["policies"]>([]);
  const [routerSettings, setRouterSettings] = useState<RouterSettingsResponse | null>(null);
  const [routerForm, setRouterForm] = useState<RouterConfigUpdate>({
    router_type: "",
    router_url: "",
    router_user: "admin",
    router_password: "",
    router_token: "",
  });
  const [saving, setSaving] = useState(false);
  const [restartingApi, setRestartingApi] = useState(false);
  const [testingRouter, setTestingRouter] = useState(false);
  const [updatingIntel, setUpdatingIntel] = useState(false);
  const [generatingCompliance, setGeneratingCompliance] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(undefined);
    const errors: string[] = [];

    const [notif, syslog, intel, policyData, router] = await Promise.allSettled([
      apiFetch<NotificationConfigResponse>("/notifications/config"),
      apiFetch<SyslogSettingsResponse>("/settings/syslog"),
      apiFetch<ThreatIntelStatusResponse>("/threat-intel/status"),
      apiFetch<PoliciesResponse>("/policies"),
      apiFetch<RouterSettingsResponse>("/settings/router"),
    ]);

    if (notif.status === "fulfilled") {
      setNotifConfig(notif.value.config);
    } else {
      errors.push("Notifications");
    }

    if (syslog.status === "fulfilled") {
      setSyslogSettings(syslog.value);
      setSyslogForm({
        enabled: syslog.value.enabled,
        host: syslog.value.host || "",
        port: String(syslog.value.port || 514),
        protocol: syslog.value.protocol === "tcp" ? "tcp" : "udp",
      });
    } else {
      errors.push("Syslog export");
    }

    if (intel.status === "fulfilled") {
      setThreatIntel(intel.value);
    } else {
      errors.push("Threat intel");
    }

    if (policyData.status === "fulfilled") {
      setPolicies(policyData.value.policies);
    } else {
      errors.push("Policies");
    }

    if (router.status === "fulfilled") {
      setRouterSettings(router.value);
      setRouterForm({
        router_type: router.value.router_type || "",
        router_url: router.value.router_url || "",
        router_user: router.value.router_user || "admin",
        router_password: router.value.router_password || "",
        router_token: router.value.router_token || "",
      });
    } else {
      errors.push("Router");
    }

    if (errors.length > 0) {
      setError(`Could not load: ${errors.join(", ")}`);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const loadStoredApiKey = useCallback(async () => {
    const stored = getStoredApiKey();
    if (!stored) {
      setApiKeyConfigured(false);
      setDisplayedApiKey(null);
      return;
    }

    setLoadingApiKey(true);
    try {
      const result = await apiFetch<ApiKeyResponse>("/settings/api-key", {
        requireAuth: true,
      });
      setDisplayedApiKey(result.api_key);
      setApiKeyConfigured(true);
      setApiKeyInput("");
    } catch {
      clearStoredApiKey();
      setApiKeyConfigured(false);
      setDisplayedApiKey(null);
    } finally {
      setLoadingApiKey(false);
    }
  }, []);

  useEffect(() => {
    if (tab === "security") {
      void loadStoredApiKey();
    }
  }, [tab, loadStoredApiKey]);

  const verifyAndSaveApiKey = async () => {
    const candidate = apiKeyInput.trim();
    if (!candidate) {
      setError("Enter the API key from your netguard.env file");
      return;
    }

    setVerifyingApiKey(true);
    setError(undefined);
    setMessage(undefined);
    try {
      const result = await apiFetch<ApiKeyResponse>("/settings/api-key", {
        headers: { "X-API-Key": candidate },
      });
      setStoredApiKey(candidate);
      setDisplayedApiKey(result.api_key);
      setApiKeyConfigured(true);
      setApiKeyInput("");
      setMessage("API key verified and saved in this browser");
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Invalid API key — check %ProgramData%\\NetGuard\\netguard.env (Windows) or /etc/netguard/netguard.env (Pi)",
      );
    } finally {
      setVerifyingApiKey(false);
    }
  };

  const copyApiKey = async () => {
    if (!displayedApiKey) {
      return;
    }
    try {
      await navigator.clipboard.writeText(displayedApiKey);
      setMessage("API key copied to clipboard");
    } catch {
      setError("Could not copy — select the key and copy manually");
    }
  };

  const forgetStoredApiKey = () => {
    clearStoredApiKey();
    setApiKeyConfigured(false);
    setDisplayedApiKey(null);
    setApiKeyInput("");
    setShowApiKey(false);
    setMessage("Stored API key removed from this browser");
  };

  const saveNotifications = async () => {
    setSaving(true);
    setMessage(undefined);
    try {
      await apiFetch("/notifications/config", {
        method: "PUT",
        body: JSON.stringify({
          telegram_bot_token: notifConfig.telegram_bot_token || undefined,
          telegram_chat_id: notifConfig.telegram_chat_id || undefined,
          smtp_host: notifConfig.smtp_host || undefined,
          smtp_port: notifConfig.smtp_port || undefined,
          smtp_user: notifConfig.smtp_user || undefined,
          smtp_password:
            notifConfig.smtp_password === "***"
              ? undefined
              : notifConfig.smtp_password || undefined,
          smtp_from: notifConfig.smtp_from || undefined,
          alert_email_to: notifConfig.alert_email_to || undefined,
        }),
      });
      setMessage("Notification settings saved");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  };

  const saveSyslogSettings = async () => {
    setSavingSyslog(true);
    setError(undefined);
    setMessage(undefined);
    try {
      const port = Number.parseInt(syslogForm.port, 10);
      const updated = await apiFetch<SyslogSettingsResponse>("/settings/syslog", {
        method: "PUT",
        body: JSON.stringify({
          enabled: syslogForm.enabled,
          host: syslogForm.host.trim() || undefined,
          port: Number.isFinite(port) ? port : 514,
          protocol: syslogForm.protocol,
        }),
      });
      setSyslogSettings(updated);
      setSyslogForm({
        enabled: updated.enabled,
        host: updated.host || "",
        port: String(updated.port || 514),
        protocol: updated.protocol === "tcp" ? "tcp" : "udp",
      });
      setMessage(
        updated.configured
          ? "Syslog export enabled — alerts will forward in RFC 5424 format"
          : "Syslog settings saved",
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Syslog save failed");
    } finally {
      setSavingSyslog(false);
    }
  };

  const testNotifications = async () => {
    try {
      await apiFetch("/notifications/test", { method: "POST" });
      setMessage("Test notification sent (check Telegram / email)");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Test failed");
    }
  };

  const updateThreatIntel = async () => {
    setUpdatingIntel(true);
    try {
      const result = await apiFetch<{ domain_count: number }>("/threat-intel/update", {
        method: "POST",
      });
      setMessage(`Threat intel updated: ${result.domain_count} domains`);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Update failed");
    } finally {
      setUpdatingIntel(false);
    }
  };

  const togglePolicy = async (policyId: string, enabled: boolean) => {
    try {
      await apiFetch(`/policies/${policyId}`, {
        method: "PUT",
        body: JSON.stringify({ enabled }),
      });
      setPolicies((prev) =>
        prev.map((p) => (p.id === policyId ? { ...p, enabled } : p)),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Policy update failed");
    }
  };

  const runPolicyEvaluation = async () => {
    try {
      const result = await apiFetch<{ new_violations: number }>("/policies/evaluate", {
        method: "POST",
      });
      setMessage(`Policy evaluation complete: ${result.new_violations} new violations`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Evaluation failed");
    }
  };

  const sendWeeklyReport = async () => {
    try {
      const result = await apiFetch<{ success: boolean; message: string }>(
        "/reports/weekly/send",
        { method: "POST" },
      );
      setMessage(result.message);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Report send failed");
    }
  };

  const generateComplianceReport = async () => {
    setGeneratingCompliance(true);
    setError(undefined);
    setMessage(undefined);
    try {
      await downloadComplianceReport();
      setMessage("Compliance report downloaded (PDF)");
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Compliance report failed — configure API key in Settings if needed",
      );
    } finally {
      setGeneratingCompliance(false);
    }
  };

  const updateRouterField = (key: keyof RouterConfigUpdate, value: string) => {
    setRouterForm((prev) => {
      const next = { ...prev, [key]: value };
      if (key === "router_type") {
        const type = value.toLowerCase();
        const user = (prev.router_user || "").trim();
        if (type === "linksys" || type === "velop") {
          if (!user || user === "root") {
            next.router_user = "admin";
          }
        } else if (type === "openwrt" && (!user || user === "admin")) {
          next.router_user = "root";
        }
      }
      return next;
    });
  };

  const buildRouterPayload = (): RouterConfigUpdate => ({
    router_type: routerForm.router_type?.trim() || "",
    router_url: routerForm.router_url?.trim() || "",
    router_user: routerForm.router_user?.trim() || "",
    router_password:
      routerForm.router_password === "***" ? undefined : routerForm.router_password?.trim(),
    router_token:
      routerForm.router_token === "***" ? undefined : routerForm.router_token?.trim(),
  });

  const waitForApiHealth = async (attempts = 20, delayMs = 1500): Promise<boolean> => {
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      try {
        await apiFetch<{ status: string }>("/health", {}, 4000);
        return true;
      } catch {
        /* API still restarting */
      }
    }
    return false;
  };

  const saveRouterSettings = async (restartAfter = false) => {
    if (restartAfter) {
      setRestartingApi(true);
    } else {
      setSaving(true);
    }
    setError(undefined);
    setMessage(undefined);
    try {
      const updated = await apiFetch<RouterSettingsResponse>("/settings/router", {
        method: "PUT",
        body: JSON.stringify(buildRouterPayload()),
      });
      setRouterSettings(updated);
      setRouterForm({
        router_type: updated.router_type || "",
        router_url: updated.router_url || "",
        router_user: updated.router_user || "admin",
        router_password: updated.router_password || "",
        router_token: updated.router_token || "",
      });

      if (!restartAfter) {
        setMessage("Router settings saved");
        return;
      }

      setMessage("Settings saved — restarting API…");
      try {
        await apiFetch<{ message: string }>("/settings/restart-api", { method: "POST" }, 8000);
      } catch {
        /* connection drop is expected while the API restarts */
      }

      const healthy = await waitForApiHealth();
      if (healthy) {
        setMessage("Router settings saved and API restarted.");
        await load();
      } else {
        setMessage(
          "Settings saved. API is still restarting — refresh the page in a few seconds.",
        );
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Router save failed");
    } finally {
      setSaving(false);
      setRestartingApi(false);
    }
  };

  const testRouterConnection = async () => {
    setTestingRouter(true);
    setError(undefined);
    setMessage(undefined);
    try {
      await apiFetch<RouterSettingsResponse>("/settings/router", {
        method: "PUT",
        body: JSON.stringify(buildRouterPayload()),
      });
      const result = await apiFetch<{ success: boolean; detail: string }>(
        "/settings/router/test",
        { method: "POST" },
      );
      if (result.success) {
        setMessage(`Router test OK: ${result.detail}`);
      } else {
        setError(`Router test failed: ${result.detail}`);
      }
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Router test failed");
    } finally {
      setTestingRouter(false);
    }
  };

  const updateField = (key: string, value: string) => {
    setNotifConfig((prev) => ({ ...prev, [key]: value }));
  };

  if (loading) {
    return (
      <div className="flex min-h-[40vh] items-center justify-center text-gray-400">
        Loading settings…
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-white">Settings</h2>
        <p className="text-sm text-gray-500">
          Notifications, threat intelligence, policies, and router enforcement
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}
      {message && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300">
          {message}
        </div>
      )}

      {!apiKeyConfigured && (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
          Write actions (block, save settings, vault, etc.) require an API key.
          Open the <strong>API key</strong> tab and paste the key from your{" "}
          <code>netguard.env</code> file.
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            onClick={() => setTab(id)}
            className={`flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition ${
              tab === id
                ? "bg-ng-accent/15 text-ng-accent"
                : "bg-ng-elevated text-gray-400 hover:text-white"
            }`}
          >
            <Icon className="h-4 w-4" />
            {label}
          </button>
        ))}
      </div>

      {tab === "security" && (
        <div className="rounded-xl border border-ng-border bg-ng-card p-6 space-y-4">
          <div>
            <h3 className="text-lg font-semibold text-white">API key</h3>
            <p className="mt-1 text-sm text-gray-400">
              Required for block, save, and other write actions. The key is generated
              automatically on first API start if missing — find it in{" "}
              <code>%ProgramData%\NetGuard\netguard.env</code> (Windows) or{" "}
              <code>/etc/netguard/netguard.env</code> (Pi). Save it here once; this
              browser will send it on every write request.
            </p>
          </div>

          {loadingApiKey ? (
            <p className="text-sm text-gray-500">Checking stored key…</p>
          ) : apiKeyConfigured && displayedApiKey ? (
            <div className="space-y-4">
              <div className="flex flex-wrap items-end gap-3">
                <label className="block flex-1 min-w-[16rem] text-sm">
                  <span className="text-gray-400">Current key</span>
                  <div className="mt-1 flex gap-2">
                    <input
                      readOnly
                      type={showApiKey ? "text" : "password"}
                      className="w-full rounded-lg border border-ng-border bg-ng-bg px-3 py-2 font-mono text-sm text-white"
                      value={displayedApiKey}
                    />
                    <button
                      type="button"
                      onClick={() => setShowApiKey((v) => !v)}
                      className="rounded-lg border border-ng-border px-3 py-2 text-sm text-gray-300 hover:text-white"
                    >
                      {showApiKey ? "Hide" : "Show"}
                    </button>
                  </div>
                </label>
                <button
                  type="button"
                  onClick={() => void copyApiKey()}
                  className="flex items-center gap-2 rounded-lg border border-ng-border px-4 py-2 text-sm text-gray-300 hover:text-white"
                >
                  <Copy className="h-4 w-4" />
                  Copy
                </button>
              </div>
              <p className="text-xs text-gray-500">
                Use this key in scripts or a second browser via the{" "}
                <code>X-API-Key</code> header.
              </p>
              <button
                type="button"
                onClick={forgetStoredApiKey}
                className="rounded-lg border border-red-500/30 px-4 py-2 text-sm text-red-300 hover:bg-red-500/10"
              >
                Remove key from this browser
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              <label className="block text-sm">
                <span className="text-gray-400">Paste API key</span>
                <input
                  type="password"
                  autoComplete="off"
                  className="mt-1 w-full rounded-lg border border-ng-border bg-ng-bg px-3 py-2 font-mono text-sm text-white"
                  value={apiKeyInput}
                  onChange={(e) => setApiKeyInput(e.target.value)}
                  placeholder="32-character key from netguard.env"
                />
              </label>
              <button
                type="button"
                onClick={() => void verifyAndSaveApiKey()}
                disabled={verifyingApiKey}
                className="flex items-center gap-2 rounded-lg bg-ng-accent px-4 py-2 text-sm font-medium text-white hover:bg-ng-accent/90 disabled:opacity-50"
              >
                <KeyRound className="h-4 w-4" />
                {verifyingApiKey ? "Verifying…" : "Verify & save"}
              </button>
            </div>
          )}
        </div>
      )}

      {tab === "notifications" && (
        <div className="rounded-xl border border-ng-border bg-ng-card p-6 space-y-4">
          <h3 className="text-lg font-semibold text-white">Telegram</h3>
          <div className="grid gap-4 sm:grid-cols-2">
            <label className="block text-sm">
              <span className="text-gray-400">Bot token</span>
              <input
                className="mt-1 w-full rounded-lg border border-ng-border bg-ng-bg px-3 py-2 text-white"
                value={notifConfig.telegram_bot_token || ""}
                onChange={(e) => updateField("telegram_bot_token", e.target.value)}
                placeholder="123456:ABC..."
              />
            </label>
            <label className="block text-sm">
              <span className="text-gray-400">Chat ID</span>
              <input
                className="mt-1 w-full rounded-lg border border-ng-border bg-ng-bg px-3 py-2 text-white"
                value={notifConfig.telegram_chat_id || ""}
                onChange={(e) => updateField("telegram_chat_id", e.target.value)}
              />
            </label>
          </div>

          <h3 className="text-lg font-semibold text-white pt-2">Email (SMTP)</h3>
          <div className="grid gap-4 sm:grid-cols-2">
            {[
              ["smtp_host", "SMTP host"],
              ["smtp_port", "Port"],
              ["smtp_user", "Username"],
              ["smtp_password", "Password"],
              ["smtp_from", "From address"],
              ["alert_email_to", "Alert recipient"],
            ].map(([key, label]) => (
              <label key={key} className="block text-sm">
                <span className="text-gray-400">{label}</span>
                <input
                  type={key.includes("password") ? "password" : "text"}
                  className="mt-1 w-full rounded-lg border border-ng-border bg-ng-bg px-3 py-2 text-white"
                  value={notifConfig[key] || ""}
                  onChange={(e) => updateField(key, e.target.value)}
                />
              </label>
            ))}
          </div>

          <div className="flex flex-wrap gap-3 pt-2">
            <button
              type="button"
              onClick={() => void saveNotifications()}
              disabled={saving}
              className="flex items-center gap-2 rounded-lg bg-ng-accent px-4 py-2 text-sm font-medium text-white hover:bg-ng-accent/90 disabled:opacity-50"
            >
              <Save className="h-4 w-4" />
              Save
            </button>
            <button
              type="button"
              onClick={() => void testNotifications()}
              className="flex items-center gap-2 rounded-lg border border-ng-border px-4 py-2 text-sm text-gray-300 hover:text-white"
            >
              <Send className="h-4 w-4" />
              Send test
            </button>
          </div>
        </div>
      )}

      {tab === "syslog" && syslogSettings && (
        <div className="rounded-xl border border-ng-border bg-ng-card p-6 space-y-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 className="text-lg font-semibold text-white">SIEM / Syslog export</h3>
              <p className="mt-1 text-sm text-gray-400">
                Forward NetGuard security alerts to your syslog collector (Wazuh, Elastic,
                Splunk, rsyslog) in RFC 5424 format. The syslog-export service polls new
                alerts every 30 seconds.
              </p>
            </div>
            <span
              className={`rounded-full px-3 py-1 text-xs font-medium ${
                syslogSettings.configured
                  ? "bg-emerald-500/10 text-emerald-400"
                  : "bg-amber-500/10 text-amber-400"
              }`}
            >
              {syslogSettings.configured ? "Active" : "Disabled"}
            </span>
          </div>

          <label className="flex items-center gap-3 text-sm text-gray-300">
            <input
              type="checkbox"
              checked={syslogForm.enabled}
              onChange={(e) =>
                setSyslogForm((prev) => ({ ...prev, enabled: e.target.checked }))
              }
              className="h-4 w-4 rounded border-ng-border"
            />
            Enable syslog export
          </label>

          <div className="grid gap-4 sm:grid-cols-2">
            <label className="block text-sm sm:col-span-2">
              <span className="text-gray-400">Syslog server host</span>
              <input
                className="mt-1 w-full rounded-lg border border-ng-border bg-ng-bg px-3 py-2 text-white"
                value={syslogForm.host}
                onChange={(e) => setSyslogForm((prev) => ({ ...prev, host: e.target.value }))}
                placeholder="192.168.1.10 or siem.example.com"
              />
            </label>
            <label className="block text-sm">
              <span className="text-gray-400">Port</span>
              <input
                className="mt-1 w-full rounded-lg border border-ng-border bg-ng-bg px-3 py-2 text-white"
                value={syslogForm.port}
                onChange={(e) => setSyslogForm((prev) => ({ ...prev, port: e.target.value }))}
                placeholder="514"
              />
            </label>
            <label className="block text-sm">
              <span className="text-gray-400">Protocol</span>
              <select
                className="mt-1 w-full rounded-lg border border-ng-border bg-ng-bg px-3 py-2 text-white"
                value={syslogForm.protocol}
                onChange={(e) =>
                  setSyslogForm((prev) => ({
                    ...prev,
                    protocol: e.target.value === "tcp" ? "tcp" : "udp",
                  }))
                }
              >
                <option value="udp">UDP</option>
                <option value="tcp">TCP</option>
              </select>
            </label>
          </div>

          <p className="text-xs text-gray-500">
            Settings are written to <code>{syslogSettings.env_file}</code>. Example:
            severity CRITICAL maps to syslog priority 130 (local0.critical). Structured
            data uses enterprise ID <code>netguard@32473</code>.
          </p>

          <div className="flex flex-wrap gap-3 pt-2">
            <button
              type="button"
              onClick={() => void saveSyslogSettings()}
              disabled={savingSyslog}
              className="flex items-center gap-2 rounded-lg bg-ng-accent px-4 py-2 text-sm font-medium text-white hover:bg-ng-accent/90 disabled:opacity-50"
            >
              <Save className="h-4 w-4" />
              Save
            </button>
          </div>
        </div>
      )}

      {tab === "threat-intel" && threatIntel && (
        <div className="rounded-xl border border-ng-border bg-ng-card p-6 space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <p className="text-sm text-gray-500">Blocked domains in feed</p>
              <p className="text-2xl font-bold text-white">{threatIntel.domain_count}</p>
            </div>
            <div>
              <p className="text-sm text-gray-500">Last updated</p>
              <p className="text-lg text-gray-300">
                {threatIntel.last_updated
                  ? new Date(threatIntel.last_updated).toLocaleString()
                  : "Never"}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => void updateThreatIntel()}
            disabled={updatingIntel}
            className="flex items-center gap-2 rounded-lg bg-ng-accent px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${updatingIntel ? "animate-spin" : ""}`} />
            Update feed now
          </button>
          <p className="text-xs text-gray-500">
            Pi installs also run a weekly timer. Feed URL is set via NETGUARD_THREAT_FEED_URL on the server.
          </p>
        </div>
      )}

      {tab === "policies" && (
        <div className="rounded-xl border border-ng-border bg-ng-card p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-white">Security policies</h3>
            <button
              type="button"
              onClick={() => void runPolicyEvaluation()}
              className="rounded-lg border border-ng-border px-3 py-1.5 text-sm text-gray-300 hover:text-white"
            >
              Run evaluation
            </button>
          </div>
          <p className="text-sm text-gray-500">
            Detection policies and automated-response playbooks. Playbooks enforce a
            24-hour per-device cooldown to prevent notification spam.
          </p>
          <ul className="divide-y divide-ng-border">
            {policies.map((policy) => (
              <li key={policy.id} className="flex items-start justify-between gap-4 py-4">
                <div>
                  <p className="font-medium text-white">{policy.name}</p>
                  <p className="text-sm text-gray-500">{policy.description}</p>
                  <div className="mt-1 flex flex-wrap gap-2">
                    <span className="inline-block rounded bg-ng-elevated px-2 py-0.5 text-xs text-gray-400">
                      {policy.severity}
                    </span>
                    {policy.playbook && (
                      <span className="inline-block rounded bg-ng-accent/15 px-2 py-0.5 text-xs text-ng-accent">
                        Automated playbook
                      </span>
                    )}
                  </div>
                </div>
                <label className="flex items-center gap-2 text-sm text-gray-400">
                  <input
                    type="checkbox"
                    checked={policy.enabled !== false}
                    onChange={(e) => void togglePolicy(policy.id, e.target.checked)}
                    className="h-4 w-4 rounded border-ng-border"
                  />
                  Enabled
                </label>
              </li>
            ))}
          </ul>
        </div>
      )}

      {tab === "router" && routerSettings && (
        <div className="rounded-xl border border-ng-border bg-ng-card p-6 space-y-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 className="text-lg font-semibold text-white">Router enforcement</h3>
              <p className="mt-1 text-sm text-gray-400">
                Block devices on your router when you click Block in the dashboard.
                Supports OpenWrt, Linksys/Velop, and custom webhooks.
              </p>
            </div>
            <span
              className={`rounded-full px-3 py-1 text-xs font-medium ${
                routerSettings.configured
                  ? "bg-emerald-500/10 text-emerald-400"
                  : "bg-amber-500/10 text-amber-400"
              }`}
            >
              {routerSettings.configured ? "Configured" : "Not configured"}
            </span>
          </div>

          {routerSettings.env_overrides.length > 0 && (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
              Some values in your install env file override saved settings (
              {routerSettings.env_overrides.join(", ")}). Remove them from{" "}
              <code>%ProgramData%\NetGuard\netguard.env</code> (Windows) or{" "}
              <code>/etc/netguard/netguard.env</code> (Pi) to use the dashboard values below.
            </div>
          )}

          <div className="grid gap-4 sm:grid-cols-2">
            <label className="block text-sm sm:col-span-2">
              <span className="text-gray-400">Router type</span>
              <select
                className="mt-1 w-full rounded-lg border border-ng-border bg-ng-bg px-3 py-2 text-white"
                value={routerForm.router_type || ""}
                onChange={(e) => updateRouterField("router_type", e.target.value)}
              >
                <option value="">Disabled (dashboard-only block)</option>
                {routerSettings.supported_types.map((type) => (
                  <option key={type} value={type}>
                    {type}
                  </option>
                ))}
              </select>
            </label>
            <label className="block text-sm sm:col-span-2">
              <span className="text-gray-400">Router URL</span>
              <input
                className="mt-1 w-full rounded-lg border border-ng-border bg-ng-bg px-3 py-2 text-white"
                value={routerForm.router_url || ""}
                onChange={(e) => updateRouterField("router_url", e.target.value)}
                placeholder="http://192.168.1.1"
              />
            </label>
            <label className="block text-sm">
              <span className="text-gray-400">Username</span>
              <input
                className="mt-1 w-full rounded-lg border border-ng-border bg-ng-bg px-3 py-2 text-white"
                value={routerForm.router_user || ""}
                onChange={(e) => updateRouterField("router_user", e.target.value)}
                placeholder="admin (Linksys) or root (OpenWrt)"
              />
            </label>
            <label className="block text-sm">
              <span className="text-gray-400">Password</span>
              <input
                type="password"
                className="mt-1 w-full rounded-lg border border-ng-border bg-ng-bg px-3 py-2 text-white"
                value={routerForm.router_password || ""}
                onChange={(e) => updateRouterField("router_password", e.target.value)}
                placeholder="Router admin password"
              />
            </label>
            <label className="block text-sm sm:col-span-2">
              <span className="text-gray-400">API token (optional)</span>
              <input
                type="password"
                className="mt-1 w-full rounded-lg border border-ng-border bg-ng-bg px-3 py-2 text-white"
                value={routerForm.router_token || ""}
                onChange={(e) => updateRouterField("router_token", e.target.value)}
                placeholder="OpenWrt ubus token or webhook bearer token"
              />
            </label>
          </div>

          <p className="text-xs text-gray-500">
            OpenWrt uses ubus login or token. Linksys/Velop uses JNAP at{" "}
            <code>http://192.168.1.1</code> with username <code>admin</code> and your router
            password. Works on Windows and Pi when NetGuard can reach the router on your LAN.
            BT/Virgin/Sky hubs usually do not support API block.
          </p>

          <div className="flex flex-wrap gap-3 pt-2">
            <button
              type="button"
              onClick={() => void testRouterConnection()}
              disabled={testingRouter || saving || restartingApi}
              className="flex items-center gap-2 rounded-lg border border-ng-border px-4 py-2 text-sm font-medium text-gray-300 hover:text-white disabled:opacity-50"
            >
              <Send className="h-4 w-4" />
              Test router login
            </button>
            <button
              type="button"
              onClick={() => void saveRouterSettings(false)}
              disabled={saving || restartingApi}
              className="flex items-center gap-2 rounded-lg bg-ng-accent px-4 py-2 text-sm font-medium text-white hover:bg-ng-accent/90 disabled:opacity-50"
            >
              <Save className="h-4 w-4" />
              Save
            </button>
            <button
              type="button"
              onClick={() => void saveRouterSettings(true)}
              disabled={saving || restartingApi}
              className="flex items-center gap-2 rounded-lg border border-ng-accent/40 bg-ng-accent/10 px-4 py-2 text-sm font-medium text-ng-accent hover:bg-ng-accent/20 disabled:opacity-50"
            >
              <RefreshCw className={`h-4 w-4 ${restartingApi ? "animate-spin" : ""}`} />
              Save &amp; restart API
            </button>
          </div>
        </div>
      )}

      {tab === "reports" && (
        <div className="space-y-6">
          <div className="rounded-xl border border-ng-border bg-ng-card p-6 space-y-4">
            <h3 className="text-lg font-semibold text-white">GDPR compliance report</h3>
            <p className="text-sm text-gray-400">
              Generates a GDPR Article 32 evidence PDF: network asset inventory, technical
              security measures, risk assessment, incident log, and data-handling statement.
              Default reporting period is the last 30 days.
            </p>
            <button
              type="button"
              onClick={() => void generateComplianceReport()}
              disabled={generatingCompliance}
              className="flex items-center gap-2 rounded-lg bg-ng-accent px-4 py-2 text-sm font-medium text-white hover:bg-ng-accent/90 disabled:opacity-50"
            >
              <FileDown className={`h-4 w-4 ${generatingCompliance ? "animate-pulse" : ""}`} />
              {generatingCompliance ? "Generating…" : "Generate compliance report"}
            </button>
          </div>

          <div className="rounded-xl border border-ng-border bg-ng-card p-6 space-y-4">
            <h3 className="text-lg font-semibold text-white">Weekly email report</h3>
            <p className="text-sm text-gray-400">
              Sends an HTML summary to the alert email address configured under Notifications.
              On Pi, a systemd timer runs this every Monday at 08:00.
            </p>
            <button
              type="button"
              onClick={() => void sendWeeklyReport()}
              className="flex items-center gap-2 rounded-lg border border-ng-border px-4 py-2 text-sm font-medium text-gray-300 hover:text-white"
            >
              <Mail className="h-4 w-4" />
              Send weekly report now
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
