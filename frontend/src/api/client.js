/**
 * API client — Axios instance and API calls for CipherSight.
 */
import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

// === Scans ===
export const createScan = (data) => api.post('/scans', data).then((r) => r.data);
export const getScans = (params) => api.get('/scans', { params }).then((r) => r.data);
export const getScan = (scanId) => api.get(`/scans/${scanId}`).then((r) => r.data);
export const getDashboardStats = () => api.get('/scans/dashboard').then((r) => r.data);
export const submitSourceScan = (data) => api.post('/scan/source', data).then((r) => r.data);
export const submitContainerScan = (data) => api.post('/scan/container', data).then((r) => r.data);
export const getScanDetails = (scanId) => api.get(`/scan/${scanId}`).then((r) => r.data);
export const getScanCoverage = (scanId) => api.get(`/scan/${scanId}/coverage`).then((r) => r.data);

// === Assets ===
export const getAssets = (params) => api.get('/assets', { params }).then((r) => r.data);
export const getAssetDetail = (assetId) => api.get(`/assets/${assetId}`).then((r) => r.data);

// === Crypto Assets ===
export const getCryptoAssets = (params) => api.get('/crypto-assets', { params }).then((r) => r.data);
export const getCryptoAsset = (assetId) => api.get(`/crypto-assets/${assetId}`).then((r) => r.data);
export const createCryptoAsset = (data) => api.post('/crypto-assets', data).then((r) => r.data);

// === CBOM ===
export const getCBOM = (scanId, format = 'json') =>
  api.get(`/cbom/${scanId}`, { params: { format }, responseType: format === 'pdf' ? 'blob' : 'json' }).then((r) => r.data);

export const downloadCBOM = async (scanId, format) => {
  const response = await api.get(`/cbom/${scanId}`, {
    params: { format },
    responseType: 'blob',
  });
  const blob = new Blob([response.data]);
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `cbom_${scanId}.${format}`;
  link.click();
  window.URL.revokeObjectURL(url);
};

// === Certificates ===
export const getCertificate = (assetId) => api.get(`/certificates/${assetId}`).then((r) => r.data);
export const verifyCertificate = (certId) => api.get(`/certificates/verify/${certId}`).then((r) => r.data);

export default api;
