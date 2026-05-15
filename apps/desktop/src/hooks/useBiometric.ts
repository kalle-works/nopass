import { invoke } from "@tauri-apps/api/core";
import { useCallback, useEffect, useState } from "react";

export function useBiometric() {
  const [available, setAvailable] = useState(false);
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    invoke<boolean>("touch_id_available")
      .then((v) => { setAvailable(v); setChecked(true); })
      .catch(() => setChecked(true));
  }, []);

  const authenticate = useCallback(async (reason: string): Promise<boolean> => {
    try {
      return await invoke<boolean>("touch_id_authenticate", { reason });
    } catch {
      return false;
    }
  }, []);

  return { available, checked, authenticate };
}
