/**
 * WebSocket hook for real-time scan progress streaming.
 */
import { useState, useEffect, useCallback, useRef } from 'react';

export default function useScanSocket(scanId) {
  const [progress, setProgress] = useState(0);
  const [event, setEvent] = useState('');
  const [message, setMessage] = useState('Waiting for connection...');
  const [isConnected, setIsConnected] = useState(false);
  const [isComplete, setIsComplete] = useState(false);
  const [error, setError] = useState(null);
  const wsRef = useRef(null);

  const connect = useCallback(() => {
    if (!scanId) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/scan/${scanId}`;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setIsConnected(true);
      setError(null);
    };

    ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data.event === 'pong') return;

        setEvent(data.event || '');
        setProgress(data.progress || 0);
        setMessage(data.message || '');

        if (data.event === 'complete') {
          setIsComplete(true);
          setProgress(100);
        } else if (data.event === 'error') {
          setError(data.message);
          setIsComplete(true);
        }
      } catch (err) {
        console.error('WebSocket parse error:', err);
      }
    };

    ws.onerror = () => {
      setError('WebSocket connection error');
    };

    ws.onclose = () => {
      setIsConnected(false);
    };

    // Ping interval
    const pingInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send('ping');
      }
    }, 30000);

    return () => {
      clearInterval(pingInterval);
      ws.close();
    };
  }, [scanId]);

  useEffect(() => {
    const cleanup = connect();
    return cleanup;
  }, [connect]);

  return { progress, event, message, isConnected, isComplete, error };
}
