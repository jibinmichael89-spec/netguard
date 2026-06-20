import type { SystemType } from "../hooks/useSystemDetection";
import {
  getBlockConfirmMessage,
  getUnblockConfirmMessage,
} from "../utils/blockMessages";
import {
  AlertDialog,
  AlertDialogAction,
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
  onConfirm: () => void;
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
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{message}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={loading}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            disabled={loading}
            onClick={(event) => {
              event.preventDefault();
              onConfirm();
            }}
          >
            {loading ? "Please wait..." : confirmLabel}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
