type Platform = 'windows' | 'pi' | 'unknown';

export function getBlockModalMessage(isBlocked: boolean, platform: Platform): string {
  if (isBlocked) {
    // Unblock message
    if (platform === 'windows') {
      return 'This device will reappear in the dashboard.';
    } else if (platform === 'pi') {
      return 'This device will regain network access within ~5 seconds.';
    }
    return 'This device will be unblocked.';
  }

  // Block message
  if (platform === 'windows') {
    return 'This will hide the device from the dashboard only. To actually disconnect devices, NetGuard must run on a Raspberry Pi with the network_blocker daemon active. Continue?';
  } else if (platform === 'pi') {
    return 'This will immediately disconnect the device from the network (~5 seconds). The network_blocker daemon must be running. Continue?';
  }

  return 'This device will be blocked.';
}
