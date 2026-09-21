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

// Token management & seamless auto-authentication
const TOKEN_KEY = 'ciphersight_token';
let currentToken = typeof window !== 'undefined' ? localStorage.getItem(TOKEN_KEY) : null;

export const setAuthToken = (token) => {
  currentToken = token;
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
};

export const getAuthToken = () => currentToken || (typeof window !== 'undefined' ? localStorage.getItem(TOKEN_KEY) : null);

let authPromise = null;
export const ensureAuthenticated = async () => {
  const existing = getAuthToken();
  if (existing) return existing;
  if (authPromise) return authPromise;

  authPromise = (async () => {
    try {
      const res = await axios.post('/api/auth/login', {
        email: 'operator@ciphersight.io',
        password: 'CipherSight_Pass123!',
      });
      if (res.data?.access_token) {
        setAuthToken(res.data.access_token);
        return res.data.access_token;
      }
    } catch {
      try {
        await axios.post('/api/auth/register', {
          email: 'operator@ciphersight.io',
          password: 'CipherSight_Pass123!',
          full_name: 'CipherSight Operator',
        });
        const loginRes = await axios.post('/api/auth/login', {
          email: 'operator@ciphersight.io',
          password: 'CipherSight_Pass123!',
        });
        if (loginRes.data?.access_token) {
          setAuthToken(loginRes.data.access_token);
          return loginRes.data.access_token;
        }
      } catch (err) {
        console.warn('Auto-authentication failed:', err);
      }
    } finally {
      authPromise = null;
    }
    return null;
  })();

  return authPromise;
};

// Request interceptor attaches bearer token
api.interceptors.request.use(async (config) => {
  let token = getAuthToken();
  if (!token && !config.url?.startsWith('/auth/')) {
    token = await ensureAuthenticated();
  }
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor handles 401 retry
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (error.response?.status === 401 && !originalRequest._retry && !originalRequest.url?.startsWith('/auth/')) {
      originalRequest._retry = true;
      setAuthToken(null);
      const newToken = await ensureAuthenticated();
      if (newToken) {
        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        return api(originalRequest);
      }
    }
    return Promise.reject(error);
  }
);

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

// === Cloud Infrastructure Scanner (PQC-CSPM) ===
export const scanCloudFleet = (provider = 'aws', data = {}) =>
  api.post(`/cloud/scan/${provider.toLowerCase()}`, data).then((r) => r.data);
export const evaluateCloudInventory = (data) =>
  api.post('/cloud/evaluate-inventory', data).then((r) => r.data);
export const getCloudInstanceCatalog = () =>
  api.get('/cloud/instance-types').then((r) => r.data);

// === Git Live Monitor ===
export const getGitMonitorStatus = () => api.get('/git-monitor/status').then((r) => r.data);
export const getGitMonitorEvents = (params) => api.get('/git-monitor/events', { params }).then((r) => r.data);
export const simulateGitPush = (data) => api.post('/git-monitor/simulate-push', data).then((r) => r.data);
export const getRemediationPresets = () => api.get('/git-monitor/presets').then((r) => r.data);
export const triggerRemediationPreset = (data) => api.post('/git-monitor/trigger-preset', data).then((r) => r.data);
export const startGitWatcher = (data) => api.post('/git-monitor/watch/start', data).then((r) => r.data);
export const stopGitWatcher = () => api.post('/git-monitor/watch/stop').then((r) => r.data);
export const checkPushesNow = () => api.post('/git-monitor/check-now').then((r) => r.data);
export const getGitWebhookInfo = () => api.get('/git-monitor/webhook-info').then((r) => r.data);

export default api;

