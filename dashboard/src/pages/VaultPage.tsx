import { useState } from "react";
import { Lock, Plus, Shield, X } from "lucide-react";
import { apiFetch } from "../api";
import type { VaultAddResponse, VaultListResponse } from "../types";
import { formatTimestamp } from "../utils/format";
import StrengthMeter from "../components/StrengthMeter";

export default function VaultPage() {
  const [masterPassword, setMasterPassword] = useState("");
  const [unlocked, setUnlocked] = useState(false);
  const [sessionPassword, setSessionPassword] = useState("");
  const [credentials, setCredentials] = useState<
    VaultListResponse["credentials"]
  >([]);
  const [loading, setLoading] = useState(false);
  const [unlockError, setUnlockError] = useState<string>();
  const [showAddForm, setShowAddForm] = useState(false);
  const [addForm, setAddForm] = useState({
    device_name: "",
    device_ip: "",
    username: "",
    password: "",
  });
  const [addError, setAddError] = useState<string>();
  const [addLoading, setAddLoading] = useState(false);

  const loadCredentials = async (password: string) => {
    const data = await apiFetch<VaultListResponse>("/vault/list", {
      method: "POST",
      body: JSON.stringify({ master_password: password }),
    });
    setCredentials(data.credentials);
  };

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setUnlockError(undefined);
    try {
      const result = await apiFetch<{ unlocked: boolean }>("/vault/unlock", {
        method: "POST",
        body: JSON.stringify({ master_password: masterPassword }),
      });
      if (!result.unlocked) {
        setUnlockError("Incorrect master password");
        return;
      }
      await loadCredentials(masterPassword);
      setSessionPassword(masterPassword);
      setUnlocked(true);
      setMasterPassword("");
    } catch (error) {
      setUnlockError(
        error instanceof Error ? error.message : "Failed to unlock vault",
      );
    } finally {
      setLoading(false);
    }
  };

  const handleAddCredential = async (e: React.FormEvent) => {
    e.preventDefault();
    setAddLoading(true);
    setAddError(undefined);
    try {
      await apiFetch<VaultAddResponse>("/vault/add", {
        method: "POST",
        body: JSON.stringify({
          master_password: sessionPassword,
          ...addForm,
        }),
      });
      await loadCredentials(sessionPassword);
      setAddForm({ device_name: "", device_ip: "", username: "", password: "" });
      setShowAddForm(false);
    } catch (error) {
      setAddError(
        error instanceof Error ? error.message : "Failed to add credential",
      );
    } finally {
      setAddLoading(false);
    }
  };

  if (!unlocked) {
    return (
      <div className="mx-auto max-w-md space-y-6 pt-12">
        <div className="text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-ng-accent/10">
            <Lock className="h-7 w-7 text-ng-accent" />
          </div>
          <h2 className="text-2xl font-bold text-white">Password Vault</h2>
          <p className="mt-2 text-sm text-gray-400">
            Enter your master password to access encrypted credentials
          </p>
        </div>

        <form
          onSubmit={handleUnlock}
          className="space-y-4 rounded-xl border border-ng-border bg-ng-card p-6"
        >
          <div>
            <label
              htmlFor="master-password"
              className="mb-1.5 block text-sm font-medium text-gray-400"
            >
              Master Password
            </label>
            <input
              id="master-password"
              type="password"
              value={masterPassword}
              onChange={(e) => setMasterPassword(e.target.value)}
              className="w-full rounded-lg border border-ng-border bg-ng-elevated px-4 py-2.5 text-white outline-none focus:border-ng-accent/50"
              required
              autoComplete="current-password"
            />
          </div>

          {unlockError && (
            <p className="text-sm text-ng-alert">{unlockError}</p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-ng-accent py-2.5 text-sm font-semibold text-ng-bg transition hover:brightness-110 disabled:opacity-50"
          >
            {loading ? "Unlocking..." : (
              <>
                <Shield className="h-4 w-4" />
                Unlock Vault
              </>
            )}
          </button>
        </form>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white">Password Vault</h2>
          <p className="mt-1 text-sm text-gray-400">
            {credentials.length} stored credential
            {credentials.length !== 1 ? "s" : ""}
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowAddForm(true)}
          className="inline-flex items-center gap-2 rounded-lg bg-ng-accent px-4 py-2 text-sm font-semibold text-ng-bg transition hover:brightness-110"
        >
          <Plus className="h-4 w-4" />
          Add Credential
        </button>
      </div>

      {showAddForm && (
        <div className="rounded-xl border border-ng-border bg-ng-card p-6">
          <div className="mb-4 flex items-center justify-between">
            <h3 className="text-lg font-semibold text-white">Add Credential</h3>
            <button
              type="button"
              onClick={() => setShowAddForm(false)}
              className="text-gray-500 hover:text-white"
              aria-label="Close form"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
          <form onSubmit={handleAddCredential} className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="mb-1.5 block text-sm text-gray-400">
                Device Name
              </label>
              <input
                value={addForm.device_name}
                onChange={(e) =>
                  setAddForm({ ...addForm, device_name: e.target.value })
                }
                className="w-full rounded-lg border border-ng-border bg-ng-elevated px-3 py-2 text-white outline-none focus:border-ng-accent/50"
                required
              />
            </div>
            <div>
              <label className="mb-1.5 block text-sm text-gray-400">
                Device IP
              </label>
              <input
                value={addForm.device_ip}
                onChange={(e) =>
                  setAddForm({ ...addForm, device_ip: e.target.value })
                }
                className="w-full rounded-lg border border-ng-border bg-ng-elevated px-3 py-2 text-white outline-none focus:border-ng-accent/50"
              />
            </div>
            <div>
              <label className="mb-1.5 block text-sm text-gray-400">
                Username
              </label>
              <input
                value={addForm.username}
                onChange={(e) =>
                  setAddForm({ ...addForm, username: e.target.value })
                }
                className="w-full rounded-lg border border-ng-border bg-ng-elevated px-3 py-2 text-white outline-none focus:border-ng-accent/50"
                required
              />
            </div>
            <div>
              <label className="mb-1.5 block text-sm text-gray-400">
                Password
              </label>
              <input
                type="password"
                value={addForm.password}
                onChange={(e) =>
                  setAddForm({ ...addForm, password: e.target.value })
                }
                className="w-full rounded-lg border border-ng-border bg-ng-elevated px-3 py-2 text-white outline-none focus:border-ng-accent/50"
                required
                autoComplete="new-password"
              />
            </div>
            <div className="sm:col-span-2">
              {addError && (
                <p className="mb-2 text-sm text-ng-alert">{addError}</p>
              )}
              <button
                type="submit"
                disabled={addLoading}
                className="rounded-lg bg-ng-accent px-5 py-2 text-sm font-semibold text-ng-bg transition hover:brightness-110 disabled:opacity-50"
              >
                {addLoading ? "Saving..." : "Save Credential"}
              </button>
            </div>
          </form>
        </div>
      )}

      {credentials.length === 0 ? (
        <p className="rounded-xl border border-ng-border bg-ng-card py-12 text-center text-gray-500">
          No credentials stored yet.
        </p>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {credentials.map((cred) => (
            <div
              key={cred.id}
              className="rounded-xl border border-ng-border bg-ng-card p-5"
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <h3 className="font-semibold text-white">{cred.device_name}</h3>
                  <p className="font-mono text-sm text-ng-accent">
                    {cred.device_ip ?? "—"}
                  </p>
                </div>
                <span
                  className={`rounded-full px-2 py-0.5 text-xs font-bold ${
                    cred.is_compromised
                      ? "bg-ng-alert/20 text-ng-alert"
                      : "bg-ng-safe/20 text-ng-safe"
                  }`}
                >
                  {cred.is_compromised ? "Compromised" : "Safe"}
                </span>
              </div>
              <p className="mt-3 text-sm text-gray-400">
                User: <span className="text-gray-300">{cred.username}</span>
              </p>
              <div className="mt-4">
                <StrengthMeter score={cred.strength_score} />
              </div>
              <p className="mt-3 text-xs text-gray-500">
                Added {formatTimestamp(cred.created_at)}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
