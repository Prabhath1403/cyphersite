import { useState, useEffect, useRef } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';

export function useGitMonitorSocket() {
  const [connected, setConnected] = useState(false);
  const [latestEvent, setLatestEvent] = useState(null);
  const socketRef = useRef(null);
  const queryClient = useQueryClient();

  useEffect(() => {
    let reconnectTimeout = null;
    let isMounted = true;

    function connect() {
      if (!isMounted) return;

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.port === '3000' ? 'localhost:8000' : window.location.host;
      const wsUrl = `${protocol}//${host}/ws/git-monitor`;

      try {
        const ws = new WebSocket(wsUrl);
        socketRef.current = ws;

        ws.onopen = () => {
          if (!isMounted) return;
          setConnected(true);
        };

        ws.onmessage = (event) => {
          if (!isMounted) return;
          try {
            const data = JSON.parse(event.data);
            if (data.event === 'GIT_COMMIT_PROCESSED') {
              setLatestEvent(data);

              // Instantly invalidate React Query cache across all views
              queryClient.invalidateQueries({ queryKey: ['crypto-assets'] });
              queryClient.invalidateQueries({ queryKey: ['crypto-graph'] });
              queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] });
              queryClient.invalidateQueries({ queryKey: ['scans'] });
              queryClient.invalidateQueries({ queryKey: ['git-events'] });
              queryClient.invalidateQueries({ queryKey: ['git-monitor-status'] });

              // User notification
              const fixed = data.vulnerabilities_fixed || 0;
              if (fixed > 0) {
                toast.success(
                  `🎉 Git Remediation: ${data.file_path} fixed (${fixed} vulnerability resolved)! Inventory & Graph updated.`,
                  { duration: 6000 }
                );
              } else {
                toast.success(
                  `⚡ Git Monitor: ${data.file_path} incrementally scanned (${data.stats?.quantum_safe_count || 0} PQC safe).`,
                  { duration: 4000 }
                );
              }
            }
          } catch (err) {
            console.error('Git monitor WebSocket message parse error:', err);
          }
        };

        ws.onclose = () => {
          if (!isMounted) return;
          setConnected(false);
          // Try reconnecting in 3 seconds
          reconnectTimeout = setTimeout(connect, 3000);
        };

        ws.onerror = () => {
          if (!isMounted) return;
          setConnected(false);
        };
      } catch (err) {
        if (!isMounted) return;
        setConnected(false);
        reconnectTimeout = setTimeout(connect, 3000);
      }
    }

    connect();

    return () => {
      isMounted = false;
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (socketRef.current) {
        socketRef.current.close();
      }
    };
  }, [queryClient]);

  return { connected, latestEvent };
}
