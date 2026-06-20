import { useEffect, useState } from "react";
import {
  detectPlatformFallback,
  fetchSystemPlatform,
  type BlockPlatform,
} from "../utils/blockPlatform";

export function useSystemPlatform(): BlockPlatform {
  const [platform, setPlatform] = useState<BlockPlatform>(detectPlatformFallback);

  useEffect(() => {
    let cancelled = false;

    fetchSystemPlatform().then((resolved) => {
      if (!cancelled) {
        setPlatform(resolved);
      }
    });

    return () => {
      cancelled = true;
    };
  }, []);

  return platform;
}
