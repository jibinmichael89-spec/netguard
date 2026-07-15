import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Copy,
  KeyRound,
  Lock,
  Plus,
  RefreshCw,
  Search,
  Shield,
  StickyNote,
  Trash2,
  X,
} from "lucide-react";
import { apiFetch } from "../api";
import ConfirmModal from "../components/ConfirmModal";
import StrengthMeter from "../components/StrengthMeter";
import type {
  VaultCredential,
  VaultCredentialDetail,
  VaultGeneratePasswordResponse,
  VaultListResponse,
  VaultNote,
  VaultNoteDetail,
  VaultNotesListResponse,
  VaultPasswordCheckResponse,
  VaultSetupResponse,
  VaultStatusResponse,
  VaultUnlockResponse,
} from "../types";
import { VAULT_CATEGORIES } from "../types";
import { formatTimestamp } from "../utils/format";

const CLIPBOARD_CLEAR_SECONDS = 30;
const PASSWORD_CHECK_DEBOUNCE_MS = 500;
const DEFAULT_AUTO_LOCK_MINUTES = 15;
const AUTO_LOCK_WARNING_MS = 2 * 60 * 1000;

type VaultTab = "passwords" | "notes";

type CredentialForm = {
  device_name: string;
  device_ip: string;
  username: string;
  password: string;
  category: string;
};

const EMPTY_FORM: CredentialForm = {
  device_name: "",
  device_ip: "",
  username: "",
  password: "",
  category: "Other",
};

function readAutoLockMinutes(): number {
  const stored = localStorage.getItem("vault_auto_lock_minutes");
  const parsed = stored ? Number.parseInt(stored, 10) : DEFAULT_AUTO_LOCK_MINUTES;
  return Number.isFinite(parsed) && parsed >= 1 ? parsed : DEFAULT_AUTO_LOCK_MINUTES;
}

function breachBadge(status: VaultCredential["breach_status"], breachCount: number) {
  if (status === "breached") {
    return {
      label: breachCount > 0 ? `Breached (${breachCount.toLocaleString()})` : "Breached",
      className: "bg-ng-alert/20 text-ng-alert",
      title: breachCount > 0 ? `Found in ${breachCount.toLocaleString()} breaches` : "Known breach",
    };
  }
  if (status === "clean") {
    return {
      label: "Clean",
      className: "bg-ng-safe/20 text-ng-safe",
      title: "No known breaches",
    };
  }
  return {
    label: "Unchecked",
    className: "bg-gray-500/20 text-gray-400",
    title: "Not yet checked against breach databases",
  };
}

export default function VaultPage() {
  const [masterPassword, setMasterPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [vaultInitialized, setVaultInitialized] = useState<boolean | null>(null);
  const [statusLoading, setStatusLoading] = useState(true);
  const [showResetForm, setShowResetForm] = useState(false);
  const [resetPhrase, setResetPhrase] = useState("");
  const [resetPassword, setResetPassword] = useState("");
  const [resetConfirmPassword, setResetConfirmPassword] = useState("");
  const [resetLoading, setResetLoading] = useState(false);
  const [setupLoading, setSetupLoading] = useState(false);
  const [sessionToken, setSessionToken] = useState("");
  const [unlocked, setUnlocked] = useState(false);
  const [lockMessage, setLockMessage] = useState<string>();
  const [vaultTab, setVaultTab] = useState<VaultTab>("passwords");

  const [credentials, setCredentials] = useState<VaultCredential[]>([]);
  const [notes, setNotes] = useState<VaultNote[]>([]);
  const [loading, setLoading] = useState(false);
  const [unlockError, setUnlockError] = useState<string>();
  const [pageError, setPageError] = useState<string>();
  const [pageMessage, setPageMessage] = useState<string>();

  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("All");

  const [showCredentialForm, setShowCredentialForm] = useState(false);
  const [editingCredentialId, setEditingCredentialId] = useState<number | null>(null);
  const [credentialForm, setCredentialForm] = useState<CredentialForm>(EMPTY_FORM);
  const [credentialSaving, setCredentialSaving] = useState(false);

  const [passwordCheck, setPasswordCheck] = useState<VaultPasswordCheckResponse | null>(null);
  const [passwordChecking, setPasswordChecking] = useState(false);
  const [riskAcknowledged, setRiskAcknowledged] = useState(false);

  const [showGenerator, setShowGenerator] = useState(false);
  const [generatorLength, setGeneratorLength] = useState(16);
  const [generatorUpper, setGeneratorUpper] = useState(true);
  const [generatorLower] = useState(true);
  const [generatorNumbers, setGeneratorNumbers] = useState(true);
  const [generatorSymbols, setGeneratorSymbols] = useState(true);
  const [generatorMemorable, setGeneratorMemorable] = useState(false);
  const [generatedPreview, setGeneratedPreview] = useState<VaultGeneratePasswordResponse | null>(null);
  const [generating, setGenerating] = useState(false);

  const [clipboardCountdown, setClipboardCountdown] = useState<Record<number, number>>({});
  const [autoLockMinutes, setAutoLockMinutes] = useState(readAutoLockMinutes);
  const [autoLockRemainingMs, setAutoLockRemainingMs] = useState<number | null>(null);

  const [selectedNoteId, setSelectedNoteId] = useState<number | null>(null);
  const [noteForm, setNoteForm] = useState({ title: "", content: "", category: "Other" });
  const [showNoteForm, setShowNoteForm] = useState(false);
  const [noteSaving, setNoteSaving] = useState(false);

  const [deleteTarget, setDeleteTarget] = useState<{ type: "credential" | "note"; id: number } | null>(null);
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [recheckLoading, setRecheckLoading] = useState(false);

  const lastActivityRef = useRef(Date.now());
  const clipboardTimersRef = useRef<Record<number, number>>({});

  const autoLockMs = useMemo(() => autoLockMinutes * 60 * 1000, [autoLockMinutes]);

  const touchActivity = useCallback(() => {
    lastActivityRef.current = Date.now();
    setAutoLockRemainingMs(null);
  }, []);

  const lockVault = useCallback((message?: string) => {
    setUnlocked(false);
    setSessionToken("");
    setCredentials([]);
    setNotes([]);
    setSelectedNoteId(null);
    setShowCredentialForm(false);
    setShowNoteForm(false);
    setEditingCredentialId(null);
    setCredentialForm(EMPTY_FORM);
    setPasswordCheck(null);
    setRiskAcknowledged(false);
    setLockMessage(message);
  }, []);

  const loadCredentials = useCallback(async (token: string = sessionToken) => {
    const data = await apiFetch<VaultListResponse>("/vault/list", {
      method: "POST",
      body: JSON.stringify({ session_token: token }),
    });
    setCredentials(data.credentials);
  }, [sessionToken]);

  const loadNotes = useCallback(async (token: string = sessionToken) => {
    const data = await apiFetch<VaultNotesListResponse>(
      `/vault/notes/list?session_token=${encodeURIComponent(token)}`,
    );
    setNotes(data.notes);
  }, [sessionToken]);

  const loadVaultStatus = useCallback(async () => {
    setStatusLoading(true);
    try {
      const status = await apiFetch<VaultStatusResponse>("/vault/status");
      setVaultInitialized(status.initialized);
    } catch {
      setVaultInitialized(null);
    } finally {
      setStatusLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadVaultStatus();
  }, [loadVaultStatus]);

  const completeUnlock = useCallback(
    async (token: string) => {
      setSessionToken(token);
      setUnlocked(true);
      setMasterPassword("");
      setConfirmPassword("");
      setShowResetForm(false);
      setResetPhrase("");
      setResetPassword("");
      setResetConfirmPassword("");
      touchActivity();
      await loadCredentials(token);
      await loadNotes(token);
    },
    [loadCredentials, loadNotes, touchActivity],
  );

  const handleCreateVault = async (e: React.FormEvent) => {
    e.preventDefault();
    if (masterPassword !== confirmPassword) {
      setUnlockError("Passwords do not match");
      return;
    }
    if (masterPassword.length < 8) {
      setUnlockError("Master password must be at least 8 characters");
      return;
    }
    setSetupLoading(true);
    setUnlockError(undefined);
    try {
      const result = await apiFetch<VaultSetupResponse>("/vault/initialize", {
        method: "POST",
        body: JSON.stringify({
          master_password: masterPassword,
          confirm_password: confirmPassword,
        }),
      });
      setVaultInitialized(true);
      setPageMessage(result.message);
      await completeUnlock(result.session_token);
    } catch (error) {
      setUnlockError(error instanceof Error ? error.message : "Failed to create vault");
    } finally {
      setSetupLoading(false);
    }
  };

  const handleResetVault = async (e: React.FormEvent) => {
    e.preventDefault();
    if (resetPhrase.trim().toUpperCase() !== "RESET") {
      setUnlockError('Type RESET in the confirmation field');
      return;
    }
    if (resetPassword !== resetConfirmPassword) {
      setUnlockError("New passwords do not match");
      return;
    }
    if (resetPassword.length < 8) {
      setUnlockError("Master password must be at least 8 characters");
      return;
    }
    setResetLoading(true);
    setUnlockError(undefined);
    try {
      const result = await apiFetch<VaultSetupResponse>("/vault/reset", {
        method: "POST",
        body: JSON.stringify({
          confirm_phrase: resetPhrase,
          new_master_password: resetPassword,
          confirm_password: resetConfirmPassword,
        }),
      });
      setVaultInitialized(true);
      setPageMessage(result.message);
      await completeUnlock(result.session_token);
    } catch (error) {
      setUnlockError(error instanceof Error ? error.message : "Failed to reset vault");
    } finally {
      setResetLoading(false);
    }
  };

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setUnlockError(undefined);
    setLockMessage(undefined);
    try {
      const result = await apiFetch<VaultUnlockResponse>("/vault/unlock", {
        method: "POST",
        body: JSON.stringify({ master_password: masterPassword }),
      });
      if (!result.unlocked || !result.session_token) {
        if (result.reason === "not_initialized") {
          setVaultInitialized(false);
          setUnlockError("Vault is not set up yet — create a master password below");
        } else {
          setUnlockError("Incorrect master password");
        }
        return;
      }
      await completeUnlock(result.session_token);
    } catch (error) {
      setUnlockError(error instanceof Error ? error.message : "Failed to unlock vault");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!unlocked) return undefined;

    const interval = window.setInterval(() => {
      const elapsed = Date.now() - lastActivityRef.current;
      const remaining = autoLockMs - elapsed;
      if (remaining <= 0) {
        lockVault("Vault locked due to inactivity");
        return;
      }
      if (remaining <= AUTO_LOCK_WARNING_MS) {
        setAutoLockRemainingMs(remaining);
      } else {
        setAutoLockRemainingMs(null);
      }
    }, 1000);

    return () => window.clearInterval(interval);
  }, [unlocked, autoLockMs, lockVault]);

  useEffect(() => {
    if (!showCredentialForm || !credentialForm.password.trim() || !sessionToken) {
      setPasswordCheck(null);
      setRiskAcknowledged(false);
      return undefined;
    }

    const timer = window.setTimeout(async () => {
      setPasswordChecking(true);
      try {
        const result = await apiFetch<VaultPasswordCheckResponse>("/vault/check-password", {
          method: "POST",
          body: JSON.stringify({
            session_token: sessionToken,
            password: credentialForm.password,
            exclude_credential_id: editingCredentialId ?? undefined,
          }),
        });
        setPasswordCheck(result);
        setRiskAcknowledged(false);
      } catch {
        setPasswordCheck(null);
      } finally {
        setPasswordChecking(false);
      }
    }, PASSWORD_CHECK_DEBOUNCE_MS);

    return () => window.clearTimeout(timer);
  }, [
    credentialForm.password,
    showCredentialForm,
    sessionToken,
    editingCredentialId,
  ]);

  useEffect(
    () => () => {
      Object.values(clipboardTimersRef.current).forEach((timerId) => window.clearInterval(timerId));
    },
    [],
  );

  const requiresRiskAck =
    Boolean(passwordCheck?.breached) || Boolean(passwordCheck?.duplicate_of?.length);

  const filteredCredentials = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    return credentials.filter((cred) => {
      if (categoryFilter !== "All" && cred.category !== categoryFilter) return false;
      if (!query) return true;
      return (
        cred.device_name.toLowerCase().includes(query) ||
        (cred.device_ip ?? "").toLowerCase().includes(query) ||
        cred.username.toLowerCase().includes(query) ||
        cred.category.toLowerCase().includes(query)
      );
    });
  }, [credentials, searchQuery, categoryFilter]);

  const runGeneratePassword = async () => {
    setGenerating(true);
    try {
      const params = new URLSearchParams({
        length: String(generatorLength),
        uppercase: String(generatorUpper),
        lowercase: String(generatorLower),
        numbers: String(generatorNumbers),
        symbols: String(generatorSymbols),
        memorable: String(generatorMemorable),
      });
      const result = await apiFetch<VaultGeneratePasswordResponse>(
        `/vault/generate-password?${params.toString()}`,
      );
      setGeneratedPreview(result);
    } catch (error) {
      setPageError(error instanceof Error ? error.message : "Password generation failed");
    } finally {
      setGenerating(false);
    }
  };

  useEffect(() => {
    if (showGenerator) {
      void runGeneratePassword();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    showGenerator,
    generatorLength,
    generatorUpper,
    generatorLower,
    generatorNumbers,
    generatorSymbols,
    generatorMemorable,
  ]);

  const useGeneratedPassword = () => {
    if (!generatedPreview) return;
    setCredentialForm((prev) => ({ ...prev, password: generatedPreview.password }));
    touchActivity();
  };

  const openAddCredential = () => {
    touchActivity();
    setEditingCredentialId(null);
    setCredentialForm(EMPTY_FORM);
    setPasswordCheck(null);
    setRiskAcknowledged(false);
    setShowGenerator(false);
    setShowCredentialForm(true);
  };

  const openEditCredential = async (credentialId: number) => {
    touchActivity();
    setPageError(undefined);
    try {
      const detail = await apiFetch<VaultCredentialDetail>(
        `/vault/credential/${credentialId}?session_token=${encodeURIComponent(sessionToken)}`,
      );
      setEditingCredentialId(credentialId);
      setCredentialForm({
        device_name: detail.device_name,
        device_ip: detail.device_ip ?? "",
        username: detail.username,
        password: detail.password,
        category: detail.category || "Other",
      });
      setPasswordCheck(null);
      setRiskAcknowledged(false);
      setShowGenerator(false);
      setShowCredentialForm(true);
    } catch (error) {
      setPageError(error instanceof Error ? error.message : "Failed to load credential");
    }
  };

  const saveCredential = async (e: React.FormEvent) => {
    e.preventDefault();
    if (requiresRiskAck && !riskAcknowledged) {
      setPageError("Acknowledge the breach or duplicate warning before saving");
      return;
    }
    setCredentialSaving(true);
    setPageError(undefined);
    touchActivity();
    try {
      if (editingCredentialId) {
        await apiFetch(`/vault/credential/${editingCredentialId}`, {
          method: "PUT",
          body: JSON.stringify({
            session_token: sessionToken,
            ...credentialForm,
          }),
        });
        setPageMessage("Credential updated");
      } else {
        await apiFetch("/vault/add", {
          method: "POST",
          body: JSON.stringify({
            session_token: sessionToken,
            ...credentialForm,
          }),
        });
        setPageMessage("Credential saved");
      }
      await loadCredentials();
      setShowCredentialForm(false);
      setEditingCredentialId(null);
      setCredentialForm(EMPTY_FORM);
      setPasswordCheck(null);
      setRiskAcknowledged(false);
    } catch (error) {
      setPageError(error instanceof Error ? error.message : "Failed to save credential");
    } finally {
      setCredentialSaving(false);
    }
  };

  const copyPassword = async (credentialId: number, password: string) => {
    touchActivity();
    await navigator.clipboard.writeText(password);
    setClipboardCountdown((prev) => ({ ...prev, [credentialId]: CLIPBOARD_CLEAR_SECONDS }));

    if (clipboardTimersRef.current[credentialId]) {
      window.clearInterval(clipboardTimersRef.current[credentialId]);
    }

    let remaining = CLIPBOARD_CLEAR_SECONDS;
    clipboardTimersRef.current[credentialId] = window.setInterval(() => {
      remaining -= 1;
      if (remaining <= 0) {
        window.clearInterval(clipboardTimersRef.current[credentialId]);
        delete clipboardTimersRef.current[credentialId];
        void navigator.clipboard.writeText("");
        setClipboardCountdown((prev) => {
          const next = { ...prev };
          delete next[credentialId];
          return next;
        });
        return;
      }
      setClipboardCountdown((prev) => ({ ...prev, [credentialId]: remaining }));
    }, 1000);
  };

  const copyCredentialPassword = async (credentialId: number) => {
    touchActivity();
    try {
      const detail = await apiFetch<VaultCredentialDetail>(
        `/vault/credential/${credentialId}?session_token=${encodeURIComponent(sessionToken)}`,
      );
      await copyPassword(credentialId, detail.password);
    } catch (error) {
      setPageError(error instanceof Error ? error.message : "Failed to copy password");
    }
  };

  const handleCopyFromDetail = async () => {
    if (!credentialForm.password || editingCredentialId === null) return;
    await copyPassword(editingCredentialId, credentialForm.password);
  };

  const recheckBreaches = async () => {
    setRecheckLoading(true);
    setPageError(undefined);
    touchActivity();
    try {
      const result = await apiFetch<{ newly_breached_count: number }>("/vault/recheck-breaches", {
        method: "POST",
        body: JSON.stringify({ session_token: sessionToken }),
      });
      await loadCredentials();
      setPageMessage(
        result.newly_breached_count > 0
          ? `${result.newly_breached_count} credential(s) newly flagged as breached`
          : "Breach recheck complete — no new breaches found",
      );
    } catch (error) {
      setPageError(error instanceof Error ? error.message : "Breach recheck failed");
    } finally {
      setRecheckLoading(false);
    }
  };

  const openNote = async (noteId: number) => {
    touchActivity();
    setPageError(undefined);
    try {
      const detail = await apiFetch<VaultNoteDetail>(
        `/vault/notes/${noteId}?session_token=${encodeURIComponent(sessionToken)}`,
      );
      setSelectedNoteId(noteId);
      setNoteForm({
        title: detail.title,
        content: detail.content,
        category: detail.category,
      });
      setShowNoteForm(true);
    } catch (error) {
      setPageError(error instanceof Error ? error.message : "Failed to load note");
    }
  };

  const openNewNote = () => {
    touchActivity();
    setSelectedNoteId(null);
    setNoteForm({ title: "", content: "", category: "Other" });
    setShowNoteForm(true);
  };

  const saveNote = async (e: React.FormEvent) => {
    e.preventDefault();
    setNoteSaving(true);
    setPageError(undefined);
    touchActivity();
    try {
      if (selectedNoteId) {
        await apiFetch(`/vault/notes/${selectedNoteId}`, {
          method: "PUT",
          body: JSON.stringify({ session_token: sessionToken, ...noteForm }),
        });
      } else {
        await apiFetch("/vault/notes/add", {
          method: "POST",
          body: JSON.stringify({ session_token: sessionToken, ...noteForm }),
        });
      }
      await loadNotes();
      setShowNoteForm(false);
      setSelectedNoteId(null);
      setPageMessage("Note saved");
    } catch (error) {
      setPageError(error instanceof Error ? error.message : "Failed to save note");
    } finally {
      setNoteSaving(false);
    }
  };

  const confirmDelete = async () => {
    if (!deleteTarget) return;
    setDeleteLoading(true);
    touchActivity();
    try {
      if (deleteTarget.type === "credential") {
        await apiFetch(`/vault/${deleteTarget.id}`, { method: "DELETE" });
        await loadCredentials();
      } else {
        await apiFetch(`/vault/notes/${deleteTarget.id}`, { method: "DELETE" });
        await loadNotes();
      }
      setDeleteTarget(null);
    } catch (error) {
      setPageError(error instanceof Error ? error.message : "Delete failed");
    } finally {
      setDeleteLoading(false);
    }
  };

  if (!unlocked) {
    if (statusLoading) {
      return (
        <div className="flex min-h-[40vh] items-center justify-center text-gray-400">
          Loading vault…
        </div>
      );
    }

    const isCreateMode = vaultInitialized === false;

    return (
      <div className="mx-auto max-w-md space-y-6 pt-12">
        <div className="text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-ng-accent/10">
            <Lock className="h-7 w-7 text-ng-accent" />
          </div>
          <h2 className="text-2xl font-bold text-white">Password Vault</h2>
          <p className="mt-2 text-sm text-gray-400">
            {lockMessage
              ?? (isCreateMode
                ? "Create a master password to encrypt your credentials on this device"
                : showResetForm
                  ? "Reset the vault and set a new master password"
                  : "Enter your master password to access encrypted credentials")}
          </p>
        </div>

        {showResetForm ? (
          <form
            onSubmit={handleResetVault}
            className="space-y-4 rounded-xl border border-ng-alert/30 bg-ng-card p-6"
          >
            <p className="text-sm text-ng-alert">
              This permanently deletes all stored credentials and notes. This cannot be undone.
            </p>
            <div>
              <label className="mb-1.5 block text-sm font-medium text-gray-400">
                Type RESET to confirm
              </label>
              <input
                value={resetPhrase}
                onChange={(e) => setResetPhrase(e.target.value)}
                className="w-full rounded-lg border border-ng-border bg-ng-elevated px-4 py-2.5 text-white outline-none focus:border-ng-accent/50"
                placeholder="RESET"
                required
              />
            </div>
            <div>
              <label className="mb-1.5 block text-sm font-medium text-gray-400">
                New master password
              </label>
              <input
                type="password"
                value={resetPassword}
                onChange={(e) => setResetPassword(e.target.value)}
                className="w-full rounded-lg border border-ng-border bg-ng-elevated px-4 py-2.5 text-white outline-none focus:border-ng-accent/50"
                required
                minLength={8}
                autoComplete="new-password"
              />
            </div>
            <div>
              <label className="mb-1.5 block text-sm font-medium text-gray-400">
                Confirm new master password
              </label>
              <input
                type="password"
                value={resetConfirmPassword}
                onChange={(e) => setResetConfirmPassword(e.target.value)}
                className="w-full rounded-lg border border-ng-border bg-ng-elevated px-4 py-2.5 text-white outline-none focus:border-ng-accent/50"
                required
                minLength={8}
                autoComplete="new-password"
              />
            </div>
            {unlockError && <p className="text-sm text-ng-alert">{unlockError}</p>}
            <div className="flex flex-wrap gap-3">
              <button
                type="submit"
                disabled={resetLoading}
                className="rounded-lg bg-ng-alert px-4 py-2.5 text-sm font-semibold text-white disabled:opacity-50"
              >
                {resetLoading ? "Resetting..." : "Reset vault"}
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowResetForm(false);
                  setUnlockError(undefined);
                  setResetPhrase("");
                  setResetPassword("");
                  setResetConfirmPassword("");
                }}
                className="rounded-lg border border-ng-border px-4 py-2.5 text-sm text-gray-300 hover:text-white"
              >
                Cancel
              </button>
            </div>
          </form>
        ) : isCreateMode ? (
          <form
            onSubmit={handleCreateVault}
            className="space-y-4 rounded-xl border border-ng-border bg-ng-card p-6"
          >
            <div>
              <label htmlFor="create-master-password" className="mb-1.5 block text-sm font-medium text-gray-400">
                Master password
              </label>
              <input
                id="create-master-password"
                type="password"
                value={masterPassword}
                onChange={(e) => setMasterPassword(e.target.value)}
                className="w-full rounded-lg border border-ng-border bg-ng-elevated px-4 py-2.5 text-white outline-none focus:border-ng-accent/50"
                required
                minLength={8}
                autoComplete="new-password"
              />
            </div>
            <div>
              <label htmlFor="confirm-master-password" className="mb-1.5 block text-sm font-medium text-gray-400">
                Confirm master password
              </label>
              <input
                id="confirm-master-password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full rounded-lg border border-ng-border bg-ng-elevated px-4 py-2.5 text-white outline-none focus:border-ng-accent/50"
                required
                minLength={8}
                autoComplete="new-password"
              />
            </div>
            <p className="text-xs text-gray-500">
              Minimum 8 characters. Store this somewhere safe — it cannot be recovered.
            </p>
            {unlockError && <p className="text-sm text-ng-alert">{unlockError}</p>}
            <button
              type="submit"
              disabled={setupLoading}
              className="flex w-full items-center justify-center gap-2 rounded-lg bg-ng-accent py-2.5 text-sm font-semibold text-ng-bg transition hover:brightness-110 disabled:opacity-50"
            >
              {setupLoading ? "Creating..." : (
                <>
                  <Shield className="h-4 w-4" />
                  Create vault
                </>
              )}
            </button>
          </form>
        ) : (
          <form
            onSubmit={handleUnlock}
            className="space-y-4 rounded-xl border border-ng-border bg-ng-card p-6"
          >
            <div>
              <label htmlFor="master-password" className="mb-1.5 block text-sm font-medium text-gray-400">
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
            {unlockError && <p className="text-sm text-ng-alert">{unlockError}</p>}
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
            <button
              type="button"
              onClick={() => {
                setShowResetForm(true);
                setUnlockError(undefined);
              }}
              className="w-full text-center text-sm text-gray-500 hover:text-ng-alert"
            >
              Forgot master password? Reset vault
            </button>
          </form>
        )}
      </div>
    );
  }

  const autoLockLabel =
    autoLockRemainingMs !== null
      ? `Vault locks in ${Math.floor(autoLockRemainingMs / 60000)}:${String(
          Math.floor((autoLockRemainingMs % 60000) / 1000),
        ).padStart(2, "0")}`
      : null;

  return (
    <div className="space-y-6" onMouseDown={touchActivity} onKeyDown={touchActivity}>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-white">Password Vault</h2>
          <p className="mt-1 text-sm text-gray-400">
            {credentials.length} credential{credentials.length !== 1 ? "s" : ""} · {notes.length} note
            {notes.length !== 1 ? "s" : ""}
          </p>
          {autoLockLabel && (
            <p className="mt-1 text-xs text-ng-warning">{autoLockLabel}</p>
          )}
          <label className="mt-2 inline-flex items-center gap-2 text-xs text-gray-500">
            Auto-lock after
            <select
              value={autoLockMinutes}
              onChange={(e) => {
                const minutes = Number.parseInt(e.target.value, 10);
                setAutoLockMinutes(minutes);
                localStorage.setItem("vault_auto_lock_minutes", String(minutes));
                touchActivity();
              }}
              className="rounded border border-ng-border bg-ng-elevated px-2 py-1 text-gray-300"
            >
              {[5, 10, 15, 30, 60].map((minutes) => (
                <option key={minutes} value={minutes}>{minutes} min</option>
              ))}
            </select>
          </label>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => void recheckBreaches()}
            disabled={recheckLoading}
            className="inline-flex items-center gap-2 rounded-lg border border-ng-border px-3 py-2 text-sm text-gray-300 hover:text-white disabled:opacity-50"
          >
            <RefreshCw className={`h-4 w-4 ${recheckLoading ? "animate-spin" : ""}`} />
            Recheck breaches
          </button>
          <button
            type="button"
            onClick={() => lockVault()}
            className="inline-flex items-center gap-2 rounded-lg border border-ng-border px-3 py-2 text-sm text-gray-300 hover:text-white"
          >
            <Lock className="h-4 w-4" />
            Lock
          </button>
          <button
            type="button"
            onClick={() => {
              lockVault();
              setShowResetForm(true);
            }}
            className="inline-flex items-center gap-2 rounded-lg border border-ng-alert/40 px-3 py-2 text-sm text-ng-alert hover:bg-ng-alert/10"
          >
            Reset vault
          </button>
        </div>
      </div>

      {pageError && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {pageError}
        </div>
      )}
      {pageMessage && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-300">
          {pageMessage}
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => { setVaultTab("passwords"); touchActivity(); }}
          className={`rounded-lg px-4 py-2 text-sm font-medium ${
            vaultTab === "passwords" ? "bg-ng-accent text-ng-bg" : "border border-ng-border text-gray-300"
          }`}
        >
          Passwords
        </button>
        <button
          type="button"
          onClick={() => { setVaultTab("notes"); touchActivity(); }}
          className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium ${
            vaultTab === "notes" ? "bg-ng-accent text-ng-bg" : "border border-ng-border text-gray-300"
          }`}
        >
          <StickyNote className="h-4 w-4" />
          Notes
        </button>
      </div>

      {vaultTab === "passwords" && (
        <>
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative min-w-[220px] flex-1">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
              <input
                value={searchQuery}
                onChange={(e) => { setSearchQuery(e.target.value); touchActivity(); }}
                placeholder="Search name, IP, username, category..."
                className="w-full rounded-lg border border-ng-border bg-ng-elevated py-2 pl-10 pr-3 text-sm text-white outline-none focus:border-ng-accent/50"
              />
            </div>
            <button
              type="button"
              onClick={openAddCredential}
              className="inline-flex items-center gap-2 rounded-lg bg-ng-accent px-4 py-2 text-sm font-semibold text-ng-bg hover:brightness-110"
            >
              <Plus className="h-4 w-4" />
              Add Credential
            </button>
          </div>

          <div className="flex flex-wrap gap-2">
            {["All", ...VAULT_CATEGORIES].map((category) => (
              <button
                key={category}
                type="button"
                onClick={() => { setCategoryFilter(category); touchActivity(); }}
                className={`rounded-full px-3 py-1 text-xs font-medium ${
                  categoryFilter === category
                    ? "bg-ng-accent/20 text-ng-accent"
                    : "border border-ng-border text-gray-400 hover:text-white"
                }`}
              >
                {category}
              </button>
            ))}
          </div>

          {showCredentialForm && (
            <div className="rounded-xl border border-ng-border bg-ng-card p-6">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-lg font-semibold text-white">
                  {editingCredentialId ? "Edit Credential" : "Add Credential"}
                </h3>
                <button type="button" onClick={() => setShowCredentialForm(false)} className="text-gray-500 hover:text-white">
                  <X className="h-5 w-5" />
                </button>
              </div>
              <form onSubmit={saveCredential} className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="mb-1.5 block text-sm text-gray-400">Device Name</label>
                  <input
                    value={credentialForm.device_name}
                    onChange={(e) => setCredentialForm({ ...credentialForm, device_name: e.target.value })}
                    className="w-full rounded-lg border border-ng-border bg-ng-elevated px-3 py-2 text-white"
                    required
                  />
                </div>
                <div>
                  <label className="mb-1.5 block text-sm text-gray-400">Device IP</label>
                  <input
                    value={credentialForm.device_ip}
                    onChange={(e) => setCredentialForm({ ...credentialForm, device_ip: e.target.value })}
                    className="w-full rounded-lg border border-ng-border bg-ng-elevated px-3 py-2 text-white"
                  />
                </div>
                <div>
                  <label className="mb-1.5 block text-sm text-gray-400">Username</label>
                  <input
                    value={credentialForm.username}
                    onChange={(e) => setCredentialForm({ ...credentialForm, username: e.target.value })}
                    className="w-full rounded-lg border border-ng-border bg-ng-elevated px-3 py-2 text-white"
                    required
                  />
                </div>
                <div>
                  <label className="mb-1.5 block text-sm text-gray-400">Category</label>
                  <select
                    value={credentialForm.category}
                    onChange={(e) => setCredentialForm({ ...credentialForm, category: e.target.value })}
                    className="w-full rounded-lg border border-ng-border bg-ng-elevated px-3 py-2 text-white"
                  >
                    {VAULT_CATEGORIES.map((category) => (
                      <option key={category} value={category}>{category}</option>
                    ))}
                  </select>
                </div>
                <div className="sm:col-span-2">
                  <div className="mb-1.5 flex items-center justify-between">
                    <label className="block text-sm text-gray-400">Password</label>
                    <button
                      type="button"
                      onClick={() => setShowGenerator((prev) => !prev)}
                      className="inline-flex items-center gap-1 text-xs text-ng-accent hover:underline"
                    >
                      <KeyRound className="h-3.5 w-3.5" />
                      Generate
                    </button>
                  </div>
                  <input
                    type="password"
                    value={credentialForm.password}
                    onChange={(e) => setCredentialForm({ ...credentialForm, password: e.target.value })}
                    className="w-full rounded-lg border border-ng-border bg-ng-elevated px-3 py-2 text-white"
                    required
                    autoComplete="new-password"
                  />
                  {editingCredentialId !== null && credentialForm.password && (
                    <button
                      type="button"
                      onClick={() => void handleCopyFromDetail()}
                      className="mt-2 inline-flex items-center gap-1 text-xs text-gray-400 hover:text-white"
                    >
                      <Copy className="h-3.5 w-3.5" />
                      {clipboardCountdown[editingCredentialId]
                        ? `Clears in ${clipboardCountdown[editingCredentialId]}s`
                        : "Copy password"}
                    </button>
                  )}
                </div>

                {showGenerator && (
                  <div className="space-y-3 rounded-lg border border-ng-border bg-ng-elevated p-4 sm:col-span-2">
                    <div className="flex flex-wrap items-center gap-4">
                      <label className="text-sm text-gray-400">
                        Length: {generatorLength}
                        <input
                          type="range"
                          min={8}
                          max={64}
                          value={generatorLength}
                          onChange={(e) => setGeneratorLength(Number(e.target.value))}
                          className="ml-2 align-middle"
                          disabled={generatorMemorable}
                        />
                      </label>
                      {[
                        ["Uppercase", generatorUpper, setGeneratorUpper],
                        ["Numbers", generatorNumbers, setGeneratorNumbers],
                        ["Symbols", generatorSymbols, setGeneratorSymbols],
                        ["Memorable", generatorMemorable, setGeneratorMemorable],
                      ].map(([label, checked, setter]) => (
                        <label key={label as string} className="flex items-center gap-2 text-sm text-gray-300">
                          <input
                            type="checkbox"
                            checked={checked as boolean}
                            onChange={(e) => (setter as (v: boolean) => void)(e.target.checked)}
                          />
                          {label as string}
                        </label>
                      ))}
                    </div>
                    {generatedPreview && (
                      <>
                        <p className="break-all font-mono text-sm text-white">{generatedPreview.password}</p>
                        <StrengthMeter score={generatedPreview.strength_score} />
                      </>
                    )}
                    <div className="flex gap-2">
                      <button
                        type="button"
                        onClick={() => void runGeneratePassword()}
                        disabled={generating}
                        className="rounded-lg border border-ng-border px-3 py-1.5 text-sm text-gray-300 hover:text-white"
                      >
                        Regenerate
                      </button>
                      <button
                        type="button"
                        onClick={useGeneratedPassword}
                        className="rounded-lg bg-ng-accent px-3 py-1.5 text-sm font-semibold text-ng-bg"
                      >
                        Use this password
                      </button>
                    </div>
                  </div>
                )}

                {passwordChecking && (
                  <p className="text-sm text-gray-500 sm:col-span-2">Checking password...</p>
                )}
                {passwordCheck && !passwordChecking && (
                  <div className="space-y-2 sm:col-span-2">
                    {!passwordCheck.breached && passwordCheck.duplicate_of.length === 0 && (
                      <p className="text-sm text-ng-safe">✅ No known breaches</p>
                    )}
                    {passwordCheck.breached && (
                      <p className="text-sm text-ng-warning">
                        ⚠️ Found in {passwordCheck.breach_count.toLocaleString()} breaches — consider a different password
                      </p>
                    )}
                    {passwordCheck.duplicate_of.length > 0 && (
                      <p className="text-sm text-ng-alert">
                        🔴 Duplicate: already used for {passwordCheck.duplicate_of.join(", ")}
                      </p>
                    )}
                    {requiresRiskAck && (
                      <label className="flex items-center gap-2 text-sm text-gray-300">
                        <input
                          type="checkbox"
                          checked={riskAcknowledged}
                          onChange={(e) => setRiskAcknowledged(e.target.checked)}
                        />
                        I understand the risk, save anyway
                      </label>
                    )}
                  </div>
                )}

                <div className="sm:col-span-2">
                  <button
                    type="submit"
                    disabled={credentialSaving || (requiresRiskAck && !riskAcknowledged)}
                    className="rounded-lg bg-ng-accent px-5 py-2 text-sm font-semibold text-ng-bg disabled:opacity-50"
                  >
                    {credentialSaving ? "Saving..." : editingCredentialId ? "Update Credential" : "Save Credential"}
                  </button>
                </div>
              </form>
            </div>
          )}

          {filteredCredentials.length === 0 ? (
            <p className="rounded-xl border border-ng-border bg-ng-card py-12 text-center text-gray-500">
              No credentials match your filters.
            </p>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {filteredCredentials.map((cred) => {
                const badge = breachBadge(cred.breach_status, cred.breach_count);
                return (
                  <div key={cred.id} className="rounded-xl border border-ng-border bg-ng-card p-5">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <h3 className="font-semibold text-white">{cred.device_name}</h3>
                        <p className="font-mono text-sm text-ng-accent">{cred.device_ip ?? "—"}</p>
                        <p className="mt-1 text-xs text-gray-500">{cred.category}</p>
                      </div>
                      <span
                        className={`rounded-full px-2 py-0.5 text-xs font-bold ${badge.className}`}
                        title={badge.title}
                      >
                        {badge.label}
                      </span>
                    </div>
                    <p className="mt-3 text-sm text-gray-400">
                      User: <span className="text-gray-300">{cred.username}</span>
                    </p>
                    <div className="mt-4">
                      <StrengthMeter score={cred.strength_score} />
                    </div>
                    <p className="mt-3 text-xs text-gray-500">Added {formatTimestamp(cred.created_at)}</p>
                    <div className="mt-4 flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={() => void openEditCredential(cred.id)}
                        className="rounded-lg border border-ng-border px-3 py-1.5 text-xs text-gray-300 hover:text-white"
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        onClick={() => void copyCredentialPassword(cred.id)}
                        className="inline-flex items-center gap-1 rounded-lg border border-ng-border px-3 py-1.5 text-xs text-gray-300 hover:text-white"
                      >
                        <Copy className="h-3.5 w-3.5" />
                        {clipboardCountdown[cred.id] ? `Clears in ${clipboardCountdown[cred.id]}s` : "Copy"}
                      </button>
                      <button
                        type="button"
                        onClick={() => setDeleteTarget({ type: "credential", id: cred.id })}
                        className="inline-flex items-center gap-1 rounded-lg border border-ng-border px-3 py-1.5 text-xs text-ng-alert hover:bg-ng-alert/10"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        Delete
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}

      {vaultTab === "notes" && (
        <>
          <div className="flex justify-end">
            <button
              type="button"
              onClick={openNewNote}
              className="inline-flex items-center gap-2 rounded-lg bg-ng-accent px-4 py-2 text-sm font-semibold text-ng-bg"
            >
              <Plus className="h-4 w-4" />
              Add Note
            </button>
          </div>

          {showNoteForm && (
            <div className="rounded-xl border border-ng-border bg-ng-card p-6">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-lg font-semibold text-white">
                  {selectedNoteId ? "Edit Note" : "New Secure Note"}
                </h3>
                <button type="button" onClick={() => setShowNoteForm(false)} className="text-gray-500 hover:text-white">
                  <X className="h-5 w-5" />
                </button>
              </div>
              <form onSubmit={saveNote} className="space-y-4">
                <div className="grid gap-4 sm:grid-cols-2">
                  <div>
                    <label className="mb-1.5 block text-sm text-gray-400">Title</label>
                    <input
                      value={noteForm.title}
                      onChange={(e) => setNoteForm({ ...noteForm, title: e.target.value })}
                      className="w-full rounded-lg border border-ng-border bg-ng-elevated px-3 py-2 text-white"
                      required
                    />
                  </div>
                  <div>
                    <label className="mb-1.5 block text-sm text-gray-400">Category</label>
                    <select
                      value={noteForm.category}
                      onChange={(e) => setNoteForm({ ...noteForm, category: e.target.value })}
                      className="w-full rounded-lg border border-ng-border bg-ng-elevated px-3 py-2 text-white"
                    >
                      {VAULT_CATEGORIES.map((category) => (
                        <option key={category} value={category}>{category}</option>
                      ))}
                    </select>
                  </div>
                </div>
                <div>
                  <label className="mb-1.5 block text-sm text-gray-400">Content</label>
                  <textarea
                    value={noteForm.content}
                    onChange={(e) => setNoteForm({ ...noteForm, content: e.target.value })}
                    rows={8}
                    className="w-full rounded-lg border border-ng-border bg-ng-elevated px-3 py-2 text-white"
                    required
                  />
                </div>
                <button
                  type="submit"
                  disabled={noteSaving}
                  className="rounded-lg bg-ng-accent px-5 py-2 text-sm font-semibold text-ng-bg disabled:opacity-50"
                >
                  {noteSaving ? "Saving..." : "Save Note"}
                </button>
                {selectedNoteId && (
                  <button
                    type="button"
                    onClick={() => setDeleteTarget({ type: "note", id: selectedNoteId })}
                    className="ml-3 rounded-lg border border-ng-alert/40 px-5 py-2 text-sm text-ng-alert hover:bg-ng-alert/10"
                  >
                    Delete Note
                  </button>
                )}
              </form>
            </div>
          )}

          {notes.length === 0 ? (
            <p className="rounded-xl border border-ng-border bg-ng-card py-12 text-center text-gray-500">
              No secure notes yet.
            </p>
          ) : (
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {notes.map((note) => (
                <button
                  key={note.id}
                  type="button"
                  onClick={() => void openNote(note.id)}
                  className="rounded-xl border border-ng-border bg-ng-card p-5 text-left transition hover:border-ng-accent/40"
                >
                  <h3 className="font-semibold text-white">{note.title}</h3>
                  <p className="mt-1 text-xs text-gray-500">{note.category}</p>
                  <p className="mt-3 text-xs text-gray-500">Updated {formatTimestamp(note.updated_at)}</p>
                </button>
              ))}
            </div>
          )}
        </>
      )}

      <ConfirmModal
        isOpen={deleteTarget !== null}
        title={deleteTarget?.type === "credential" ? "Delete credential?" : "Delete note?"}
        message="This action cannot be undone."
        confirmLabel="Delete"
        loading={deleteLoading}
        onConfirm={() => void confirmDelete()}
        onClose={() => setDeleteTarget(null)}
      />
    </div>
  );
}
