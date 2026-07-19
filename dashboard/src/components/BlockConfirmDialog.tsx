import type { SystemType } from "../hooks/useSystemDetection";
import {
  getBlockConfirmMessage,
  getUnblockConfirmMessage,
} from "../utils/blockMessages";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "./ui/alert-dialog";

interface BlockConfirmDialogProps {
  open: boolean;
  isBlocked: boolean;
  systemType: SystemType;
  loading?: boolean;
  onConfirm: () => void | Promise<void>;
  onOpenChange: (open: boolean) => void;
}

export default function BlockConfirmDialog({
  open,
  isBlocked,
  systemType,
  loading = false,
  onConfirm,
  onOpenChange,
}: BlockConfirmDialogProps) {
  const title = isBlocked ? "Unblock Device" : "Block Device";
  const message = isBlocked
    ? getUnblockConfirmMessage(systemType)
    : getBlockConfirmMessage(systemType);
  const confirmLabel = isBlocked ? "Unblock Device" : "Block Device";

  return (
    <AlertDialog
      open={open}
      onOpenChange={(nextOpen) => {
        // Ignore dismiss while the block/unblock request is in flight.
        if (!nextOpen && loading) return;
        onOpenChange(nextOpen);
      }}
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{message}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={loading}>Cancel</AlertDialogCancel>
          {/*
            Use a plain button instead of AlertDialogAction. Radix Action closes
            the dialog on click, which raced with async confirm and required a
            second attempt.
          */}
          <button
            type="button"
            disabled={loading}
            onClick={() => {
              void onConfirm();
            }}
            className="inline-flex h-10 items-center justify-center rounded-lg bg-ng-accent px-4 py-2 text-sm font-semibold text-ng-bg transition hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ng-accent disabled:pointer-events-none disabled:opacity-50"
          >
            {loading ? "Please wait..." : confirmLabel}
          </button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
