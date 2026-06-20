import { useEffect, useState } from "react";
import { X } from "lucide-react";
import { apiFetch } from "../api";
import type { PortInstructionsResponse } from "../types";
import type { InstructionPlatform } from "../hooks/useSystemDetection";
import LoadingSpinner from "./LoadingSpinner";

const PLATFORM_OPTIONS: { id: InstructionPlatform; label: string }[] = [
  { id: "windows", label: "Windows" },
  { id: "linux", label: "Linux" },
  { id: "pi", label: "Raspberry Pi" },
];

interface PortInstructionsModalProps {
  open: boolean;
  port: number | null;
  defaultPlatform: InstructionPlatform;
  onClose: () => void;
}

export default function PortInstructionsModal({
  open,
  port,
  defaultPlatform,
  onClose,
}: PortInstructionsModalProps) {
  const [platform, setPlatform] = useState<InstructionPlatform>(defaultPlatform);
  const [instructions, setInstructions] = useState<PortInstructionsResponse | null>(
    null,
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setPlatform(defaultPlatform);
    }
  }, [open, defaultPlatform, port]);

  useEffect(() => {
    if (!open || port === null) {
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);

    apiFetch<PortInstructionsResponse>(
      `/ports/${port}/instructions?platform=${platform}`,
    )
      .then((data) => {
        if (!cancelled) {
          setInstructions(data);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setInstructions(null);
          setError(
            err instanceof Error
              ? err.message
              : "Unable to load port instructions.",
          );
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [open, port, platform]);

  if (!open || port === null) {
    return null;
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div
        className="flex max-h-[90vh] w-full max-w-lg flex-col rounded-xl border border-ng-border bg-ng-card shadow-xl"
        role="dialog"
        aria-labelledby="port-instructions-title"
      >
        <div className="flex items-start justify-between border-b border-ng-border p-5">
          <div>
            <h3 id="port-instructions-title" className="text-lg font-semibold text-white">
              Close Port {port}
              {instructions?.service ? ` — ${instructions.service}` : ""}
            </h3>
            <p className="mt-1 text-sm text-gray-400">
              Step-by-step instructions to reduce this attack vector
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-gray-500 transition hover:text-white"
            aria-label="Close"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="border-b border-ng-border px-5 py-3">
          <div className="flex flex-wrap gap-2">
            {PLATFORM_OPTIONS.map(({ id, label }) => (
              <button
                key={id}
                type="button"
                onClick={() => setPlatform(id)}
                className={`rounded-full border px-3 py-1 text-xs font-medium transition ${
                  platform === id
                    ? "border-ng-accent/50 bg-ng-accent/15 text-ng-accent"
                    : "border-ng-border bg-ng-elevated text-gray-400 hover:text-gray-200"
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        <div className="overflow-y-auto p-5">
          {loading ? (
            <LoadingSpinner label="Loading instructions..." />
          ) : error ? (
            <p className="rounded-lg border border-ng-alert/40 bg-ng-alert/10 px-4 py-3 text-sm text-ng-alert">
              {error}
            </p>
          ) : instructions ? (
            <div className="space-y-4">
              <div className="rounded-lg border border-ng-alert/30 bg-ng-alert/10 px-4 py-3">
                <p className="text-xs font-semibold uppercase tracking-wider text-ng-alert">
                  Why this is dangerous
                </p>
                <p className="mt-1 text-sm text-gray-300">
                  {instructions.dangerous_reason}
                </p>
              </div>

              <div>
                <p className="text-sm font-medium text-white">
                  {instructions.description}
                </p>
                <ol className="mt-3 list-decimal space-y-2 pl-5 text-sm text-gray-300">
                  {instructions.steps.map((step, index) => (
                    <li key={`${platform}-${index}`} className="leading-relaxed">
                      {step}
                    </li>
                  ))}
                </ol>
              </div>
            </div>
          ) : (
            <p className="text-sm text-gray-400">No instructions available.</p>
          )}
        </div>

        <div className="border-t border-ng-border p-5">
          <button
            type="button"
            onClick={onClose}
            className="w-full rounded-lg border border-ng-border px-4 py-2 text-sm font-medium text-gray-300 transition hover:bg-ng-elevated"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
