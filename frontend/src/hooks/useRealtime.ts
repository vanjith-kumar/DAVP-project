import { useEffect, useRef, useState } from 'react';

export const useRealtime = () => {
  const token = localStorage.getItem('token');
  const ws = useRef<WebSocket | null>(null);
  const [status, setStatus] = useState<'OFFLINE' | 'CONNECTING' | 'LIVE'>('OFFLINE');
  const [lastEvent, setLastEvent] = useState<any>(null);

  useEffect(() => {
    if (!token) return;

    const connect = () => {
      setStatus('CONNECTING');
      const wsUrl = `ws://localhost:8000/ws?token=${token}`;
      ws.current = new WebSocket(wsUrl);

      ws.current.onopen = () => {
        setStatus('LIVE');
      };

      ws.current.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setLastEvent(data);
        } catch (e) {
          console.error("WS Parse error", e);
        }
      };

      ws.current.onclose = () => {
        setStatus('OFFLINE');
        setTimeout(connect, 5000); // Reconnect
      };
      
      ws.current.onerror = () => {
        ws.current?.close();
      };
    };

    connect();

    return () => {
      if (ws.current) {
        ws.current.close();
      }
    };
  }, [token]);

  return { status, lastEvent };
};
