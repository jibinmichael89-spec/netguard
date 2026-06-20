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

export function isRecentlyAdded(firstSeen: string, windowHours: number): boolean {
  try {
    const cutoff = Date.now() - windowHours * 60 * 60 * 1000;
    return new Date(firstSeen).getTime() >= cutoff;
  } catch {
    return false;
  }
}
