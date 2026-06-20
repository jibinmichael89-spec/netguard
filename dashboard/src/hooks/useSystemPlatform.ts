import { useEffect, useState } from 'react';
import { API_BASE_URL } from '../config';

type Platform = 'windows' | 'pi' | 'unknown';

export function useSystemPlatform(): Platform {
  const [platform, setPlatform] = useState<Platform>('unknown');

  useEffect(() => {
    // Detect based on API_BASE_URL and hostname
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
      // Local development on Windows
      setPlatform('windows');
    } else if (API_BASE_URL.includes('.ngrok') || API_BASE_URL.includes('raspberrypi') || API_BASE_URL.includes('192.168')) {
      // Remote Pi via ngrok or direct Pi IP
      setPlatform('pi');
    } else {
      setPlatform('unknown');
    }
  }, []);

  return platform;
}
