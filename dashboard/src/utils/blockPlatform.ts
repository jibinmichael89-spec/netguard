type Platform = 'windows' | 'pi' | 'unknown';

export function getBlockModalMessage(isBlocked: boolean, platform: Platform): string {
  if (isBlocked) {
    if (platform === 'pi') {
      return 'This device will regain network access within a few seconds.';
    }
    if (platform === 'windows') {
      return 'This device will be unblocked in NetGuard and resumed on your router if configured.';
    }
    return 'This device will be unblocked.';
  }

  if (platform === 'windows') {
    return 'This will flag the device in the dashboard. To enforce real network blocking, deploy NetGuard on a Raspberry Pi connected to your network.';
  }

  if (platform === 'pi') {
    return 'This will disconnect the device from the network via your router. The device will lose internet access immediately. Click Unblock to restore access.';
  }

  return 'This device will be blocked.';
}
