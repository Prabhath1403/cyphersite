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
export const submitGitHubScan = (data) => api.post('/scan/github', data).then((r) => r.data);
export const getGitHubRepoInfo = (params) => api.get('/scan/github/info', { params }).then((r) => r.data);
export const submitContainerScan = (data) => api.post('/scan/container', data).then((r) => r.data);
export const submitBinaryScan = (data) => api.post('/scan/binary', data).then((r) => r.data);
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

// === Graph ===
export const getGraph = (params) => api.get('/graph', { params }).then((r) => r.data);
export const getScanGraph = (scanId) => api.get(`/graph/${scanId}`).then((r) => r.data);

// === Risk ===
export const evaluateRisk = (data) => api.post('/risk/evaluate', data).then((r) => r.data);
export const getScanRisk = (scanId) => api.get(`/risk/scan/${scanId}`).then((r) => r.data);

// === Migration ===
export const getMigrationPlan = (scanId) => api.get(`/migration/plan/${scanId}`).then((r) => r.data);
export const getMigrationRecommendation = (data) => api.post('/migration/recommend', data).then((r) => r.data);

// === Remediation ===
export const getIssuePreview = (findingId) => api.get(`/remediation/finding/${findingId}/issue-preview`).then((r) => r.data);
export const exportIssues = (scanId) => api.get(`/remediation/scan/${scanId}/export-issues`).then((r) => r.data);
export const publishGitHubIssue = (data) => api.post('/remediation/publish', data).then((r) => r.data);

// === AI Cryptographic Explanation ===
export const explainFinding = (data) => api.post('/ai/explain', data).then((r) => r.data);
export const getFindingExplanation = (findingId, params) => api.get(`/ai/finding/${findingId}`, { params }).then((r) => r.data);
export const getScanAISummary = (scanId, params) => api.get(`/ai/scan/${scanId}/summary`, { params }).then((r) => r.data);
export const queryAI = (data) => api.post('/ai/query', data).then((r) => r.data);

// === Certificates ===
export const getCertificate = (assetId) => api.get(`/certificates/${assetId}`).then((r) => r.data);
export const verifyCertificate = (certId) => api.get(`/certificates/verify/${certId}`).then((r) => r.data);

export default api;
