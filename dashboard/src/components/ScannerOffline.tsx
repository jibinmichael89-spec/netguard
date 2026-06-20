import { WifiOff, RefreshCw } from "lucide-react";

interface ScannerOfflineProps {
  message?: string;
  onRetry: () => void;
}

export default function ScannerOffline({
  message = "Unable to reach the NetGuard API. Make sure the scanner and API server are running.",
  onRetry,
}: ScannerOfflineProps) {
  return (
    <div className="flex min-h-[50vh] flex-col items-center justify-center gap-6 px-4 text-center">
      <div className="flex h-16 w-16 items-center justify-center rounded-full bg-ng-alert/10">
        <WifiOff className="h-8 w-8 text-ng-alert" />
      </div>
      <div className="max-w-md space-y-2">
        <h2 className="text-xl font-semibold text-white">Scanner Offline</h2>
        <p className="text-sm text-gray-400">{message}</p>
      </div>
      <button
        type="button"
        onClick={onRetry}
        className="inline-flex items-center gap-2 rounded-lg bg-ng-accent px-5 py-2.5 text-sm font-semibold text-ng-bg transition hover:brightness-110"
      >
        <RefreshCw className="h-4 w-4" />
        Retry
      </button>
    </div>
  );
}
