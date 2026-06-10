import { useEffect, useRef } from "react";

export function useSSE(onMessage: (event: string, data: unknown) => void): void {
  const ref = useRef<EventSource | null>(null);
  useEffect(() => {
    const es = new EventSource("/api/stream");
    ref.current = es;
    const handler = (eventName: string) => (ev: MessageEvent<string>) => {
      try {
        onMessage(eventName, JSON.parse(ev.data));
      } catch {
        onMessage(eventName, ev.data);
      }
    };
    for (const name of ["event", "ap", "client", "status", "hello"]) {
      es.addEventListener(name, handler(name));
    }
    return () => {
      ref.current?.close();
      ref.current = null;
    };
  }, [onMessage]);
}
