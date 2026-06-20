import { useEffect, useState } from "react";
import { X } from "lucide-react";
import { apiFetch } from "../api";
import type { DeviceTagResponse } from "../types";

interface TagModalProps {
  isOpen: boolean;
  deviceIp: string;
  currentTag: string | null;
  onClose: () => void;
  onSaved: () => void;
}

export default function TagModal({
  isOpen,
  deviceIp,
  currentTag,
  onClose,
  onSaved,
}: TagModalProps) {
  const [tagValue, setTagValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setTagValue(currentTag ?? "");
      setError(null);
      setLoading(false);
    }
  }, [isOpen, currentTag, deviceIp]);

  if (!isOpen) {
    return null;
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      await apiFetch<DeviceTagResponse>(
        `/devices/${encodeURIComponent(deviceIp)}/tag`,
        {
          method: "PUT",
          body: JSON.stringify({ device_tag: tagValue.trim() }),
        },
      );
      onSaved();
      onClose();
    } catch {
      setError("Failed to save tag");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div
        className="w-full max-w-md rounded-xl border border-ng-border bg-ng-card p-6 shadow-xl"
        role="dialog"
        aria-labelledby="tag-modal-title"
      >
        <div className="mb-4 flex items-center justify-between">
          <h3 id="tag-modal-title" className="text-lg font-semibold text-white">
            Device Tag
          </h3>
          <button
            type="button"
            onClick={onClose}
            className="text-gray-500 transition hover:text-white"
            aria-label="Close"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <p className="mb-4 text-sm text-gray-400">
          Tag device{" "}
          <span className="font-mono text-ng-accent">{deviceIp}</span>
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="device-tag-input"
              className="mb-1.5 block text-sm font-medium text-gray-400"
            >
              Tag
            </label>
            <input
              id="device-tag-input"
              type="text"
              value={tagValue}
              onChange={(e) => setTagValue(e.target.value)}
              placeholder='e.g. "DHCP Server", "CEO PC", "Smart TV"'
              className="w-full rounded-lg border border-ng-border bg-ng-elevated px-4 py-2.5 text-white outline-none focus:border-ng-accent/50"
              required
              autoFocus
            />
          </div>

          {error && <p className="text-sm text-ng-alert">{error}</p>}

          <div className="flex justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="rounded-lg border border-ng-border px-4 py-2 text-sm font-medium text-gray-300 transition hover:bg-ng-elevated disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading || !tagValue.trim()}
              className="rounded-lg bg-ng-accent px-4 py-2 text-sm font-semibold text-ng-bg transition hover:brightness-110 disabled:opacity-50"
            >
              {loading ? "Saving..." : "Save Tag"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
