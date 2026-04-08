/**
 * React Query hooks for scan data fetching.
 */
import { useQuery } from '@tanstack/react-query';
import { getScan, getScans, getDashboardStats, getAssets, getAssetDetail, getCBOM, getCertificate } from '../api/client';

export function useDashboardStats() {
  return useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: getDashboardStats,
    refetchInterval: 10000,
  });
}

export function useScans(params = {}) {
  return useQuery({
    queryKey: ['scans', params],
    queryFn: () => getScans(params),
    refetchInterval: 5000,
  });
}

export function useScan(scanId) {
  return useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => getScan(scanId),
    enabled: !!scanId,
    refetchInterval: (data) => (data?.status === 'completed' || data?.status === 'failed') ? false : 3000,
  });
}

export function useAssets(params = {}) {
  return useQuery({
    queryKey: ['assets', params],
    queryFn: () => getAssets(params),
    enabled: !!params.scan_id,
  });
}

export function useAssetDetail(assetId) {
  return useQuery({
    queryKey: ['asset', assetId],
    queryFn: () => getAssetDetail(assetId),
    enabled: !!assetId,
  });
}

export function useCBOM(scanId) {
  return useQuery({
    queryKey: ['cbom', scanId],
    queryFn: () => getCBOM(scanId),
    enabled: !!scanId,
  });
}

export function useCertificate(assetId) {
  return useQuery({
    queryKey: ['certificate', assetId],
    queryFn: () => getCertificate(assetId),
    enabled: !!assetId,
    retry: false,
  });
}
