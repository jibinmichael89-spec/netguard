type Platform = 'windows' | 'pi' | 'unknown';

export function getBlockModalMessage(isBlocked: boolean, platform: Platform): string {
  if (isBlocked) {
    // Unblock message
    if (platform === 'windows') {
      return 'This device will reappear in the dashboard.';
    } else if (platform === 'pi') {
      return 'This device will be removed from the block list. Network access should restore within ~5 seconds on standard networks.';
    }
    return 'This device will be unblocked.';
  }

  // Block message
  if (platform === 'windows') {
    return 'This will hide the device from the dashboard only. To actually disconnect devices, NetGuard must run on a Raspberry Pi with the network_blocker daemon active. Continue?';
  } else if (platform === 'pi') {
    return 'This will attempt to disconnect the device from the network via ARP isolation. Note: On mesh WiFi systems (Linksys Velop, Eero, Orbi, etc.), hardware-level blocking may be limited by mesh firmware. Use your router app as a backup for guaranteed enforcement.';
  }

  return 'This device will be blocked.';
}
