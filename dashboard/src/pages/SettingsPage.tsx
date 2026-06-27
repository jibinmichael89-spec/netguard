import { useCallback, useEffect, useState } from "react";
import {
  Bell,
  RefreshCw,
  Router,
  Save,
  Send,
  Shield,
  Mail,
} from "lucide-react";
import { apiFetch } from "../api";
import type {
  NotificationConfigResponse,
  PoliciesResponse,
  RouterSettingsResponse,
  ThreatIntelStatusResponse,
} from "../types";

type Tab = "notifications" | "threat-intel" | "policies" | "router" | "reports";

const TABS: { id: Tab; label: string; icon: typeof Bell }[] = [
  { id: "notifications", label: "Notifications", icon: Bell },
  { id: "threat-intel", label: "Threat Intel", icon: Shield },
  { id: "policies", label: "Policies", icon: Shield },
  { id: "router", label: "Router", icon: Router },
  { id: "reports", label: "Reports", icon: Mail },
];

export default function SettingsPage() {
  const [tab, setTab] = useState<Tab>("notifications");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();
  const [message, setMessage] = useState<string>();

  const [notifConfig, setNotifConfig] = useState<Record<string, string>>({});
  const [threatIntel, setThreatIntel] = useState<ThreatIntelStatusResponse | null>(null);
  const [policies, setPolicies] = useState<PoliciesResponse["policies"]>([]);
  const [routerSettings, setRouterSettings] = useState<RouterSettingsResponse | null>(null);
  const [saving, setSaving] = useState(false);
  const [updatingIntel, setUpdatingIntel] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(undefined);
    try {
      const [notif, intel, policyData, router] = await Promise.all([
        apiFetch<NotificationConfigResponse>("/notifications/config"),
        apiFetch<ThreatIntelStatusResponse>("/threat-intel/status"),
        apiFetch<PoliciesResponse>("/policies"),
        apiFetch<RouterSettingsResponse>("/settings/router"),
      ]);
      setNotifConfig(notif.config);
      setThreatIntel(intel);
      setPolicies(policyData.policies);
      setRouterSettings(router);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load settings");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

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
          <ul className="divide-y divide-ng-border">
            {policies.map((policy) => (
              <li key={policy.id} className="flex items-start justify-between gap-4 py-4">
                <div>
                  <p className="font-medium text-white">{policy.name}</p>
                  <p className="text-sm text-gray-500">{policy.description}</p>
                  <span className="mt-1 inline-block rounded bg-ng-elevated px-2 py-0.5 text-xs text-gray-400">
                    {policy.severity}
                  </span>
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
          <h3 className="text-lg font-semibold text-white">Router enforcement</h3>
          <p className="text-sm text-gray-400">
            Configure on the Pi via <code className="text-ng-accent">/etc/netguard/netguard.env</code>
            {" "}then restart NetGuard. Supports OpenWrt (ubus), Linksys JNAP pause, and custom webhooks.
          </p>
          <dl className="grid gap-3 sm:grid-cols-2 text-sm">
            <div>
              <dt className="text-gray-500">Type</dt>
              <dd className="text-white">{routerSettings.router_type || "Not set"}</dd>
            </div>
            <div>
              <dt className="text-gray-500">URL</dt>
              <dd className="text-white">{routerSettings.router_url || "—"}</dd>
            </div>
            <div>
              <dt className="text-gray-500">Configured</dt>
              <dd className={routerSettings.configured ? "text-emerald-400" : "text-amber-400"}>
                {routerSettings.configured ? "Yes" : "No — DB-only block"}
              </dd>
            </div>
          </dl>
          <ul className="list-disc pl-5 text-xs text-gray-500 space-y-1">
            {routerSettings.env_keys.map((key) => (
              <li key={key}>{key}</li>
            ))}
          </ul>
        </div>
      )}

      {tab === "reports" && (
        <div className="rounded-xl border border-ng-border bg-ng-card p-6 space-y-4">
          <h3 className="text-lg font-semibold text-white">Weekly email report</h3>
          <p className="text-sm text-gray-400">
            Sends an HTML summary to the alert email address configured under Notifications.
            On Pi, a systemd timer runs this every Monday at 08:00.
          </p>
          <button
            type="button"
            onClick={() => void sendWeeklyReport()}
            className="flex items-center gap-2 rounded-lg bg-ng-accent px-4 py-2 text-sm font-medium text-white"
          >
            <Mail className="h-4 w-4" />
            Send report now
          </button>
        </div>
      )}
    </div>
  );
}
