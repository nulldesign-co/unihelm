import { useEffect, useRef, useState } from "react";

export interface TaskLogEvent {
  task_id: string;
  seq: number;
  line: string;
}

export interface TaskStateEvent {
  task_id: string;
  status: string;
  progress: number | null;
  detail: string | null;
}

interface Handlers {
  onLog?: (event: TaskLogEvent) => void;
  onState?: (event: TaskStateEvent) => void;
  onLagged?: () => void;
}

/**
 * Subscribe to the panel's event stream.
 *
 * `EventSource` reconnects on its own, which is most of why the API uses SSE
 * rather than a websocket (spec §11.17).
 */
export function useEventStream(enabled: boolean, handlers: Handlers) {
  const [connected, setConnected] = useState(false);
  // Keep the latest handlers without re-opening the stream on every render.
  const latest = useRef(handlers);
  latest.current = handlers;

  useEffect(() => {
    if (!enabled) return;

    const source = new EventSource("/api/events", { withCredentials: true });

    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);

    source.addEventListener("task.log", (event) => {
      latest.current.onLog?.(JSON.parse((event as MessageEvent).data) as TaskLogEvent);
    });
    source.addEventListener("task.state", (event) => {
      latest.current.onState?.(JSON.parse((event as MessageEvent).data) as TaskStateEvent);
    });
    source.addEventListener("lagged", () => latest.current.onLagged?.());

    return () => source.close();
  }, [enabled]);

  return { connected };
}
