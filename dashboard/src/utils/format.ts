export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    const date = new Date(iso);
    return date.toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return iso;
  }
}

export function formatRelativeTime(iso: string | null | undefined): string {
  if (!iso) return "never";
  try {
    const seconds = Math.max(
      0,
      Math.floor((Date.now() - new Date(iso).getTime()) / 1000),
    );
    if (seconds < 60) return "just now";
    if (seconds < 3600) {
      const minutes = Math.floor(seconds / 60);
      return `${minutes} min ago`;
    }
    if (seconds < 86400) {
      const hours = Math.floor(seconds / 3600);
      return `${hours} hr ago`;
    }
    const days = Math.floor(seconds / 86400);
    return `${days} day${days === 1 ? "" : "s"} ago`;
  } catch {
    return "unknown";
  }
}

export function isRecentlyAdded(firstSeen: string, windowHours: number): boolean {
  try {
    const cutoff = Date.now() - windowHours * 60 * 60 * 1000;
    return new Date(firstSeen).getTime() >= cutoff;
  } catch {
    return false;
  }
}
