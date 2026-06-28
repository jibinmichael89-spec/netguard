type Platform = 'windows' | 'pi' | 'unknown';

export function getBlockModalMessage(isBlocked: boolean, platform: Platform): string {
  const routerHint =
    "Router enforcement (Settings → Router) pauses the device on Linksys/OpenWrt when configured.";

  if (isBlocked) {
    if (platform === 'windows' || platform === 'pi') {
      return 'This device will be unblocked in NetGuard and resumed on your router if configured.';
    }
    return 'This device will be unblocked.';
  }

  if (platform === 'windows') {
    return `${routerHint} Otherwise it is dashboard-only. Continue?`;
  }

  if (platform === 'pi') {
    return `${routerHint} On Pi, ARP network blocker is a fallback when router API is unavailable. Continue?`;
  }

  return 'This device will be blocked.';
}
