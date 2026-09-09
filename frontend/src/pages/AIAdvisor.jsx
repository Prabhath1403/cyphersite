import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { queryAI, explainFinding, getScanAISummary, getScans } from '../api/client';
import toast from 'react-hot-toast';

const QUICK_PROMPTS = [
  "Why does Shor's algorithm break RSA-2048?",
  "How does Grover's algorithm affect AES-128 vs AES-256?",
  "Explain Harvest Now, Decrypt Later (HNDL) risk in detail",
  "What is NIST FIPS 203 (ML-KEM) and how does it work?",
  "Explain NSA CNSA 2.0 post-quantum migration deadlines",
];

export default function AIAdvisor() {
  // Q&A State
  const [queryInput, setQueryInput] = useState('');
  const [qaHistory, setQaHistory] = useState([]);
  const [isQuerying, setIsQuerying] = useState(false);

  // Algorithm Analyzer State
  const [analyzerAlgo, setAnalyzerAlgo] = useState('RSA');
  const [analyzerKeySize, setAnalyzerKeySize] = useState('2048');
  const [analyzerPrimitive, setAnalyzerPrimitive] = useState('asymmetric');
  const [analyzerSensitivity, setAnalyzerSensitivity] = useState('financial');
  const [analyzerResult, setAnalyzerResult] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Scan Executive Summary State
  const [selectedScanId, setSelectedScanId] = useState('');
  const [scanSummary, setScanSummary] = useState(null);
  const [isGeneratingSummary, setIsGeneratingSummary] = useState(false);

  const { data: scansData } = useQuery({
    queryKey: ['scans-list'],
    queryFn: () => getScans({ limit: 20 }),
  });
  const scans = scansData?.items || [];

  const handleSendQuery = async (textToSend) => {
    const q = textToSend || queryInput;
    if (!q.trim()) return;

    setIsQuerying(true);
    try {
      const res = await queryAI({ query: q });
      setQaHistory((prev) => [
        ...prev,
        {
          id: Date.now(),
          question: q,
          answer: res.answer,
          references: res.references || [],
          engine: res.engine,
        },
      ]);
      setQueryInput('');
    } catch (err) {
      toast.error('Failed to get answer from AI Cryptographic Advisor');
    } finally {
      setIsQuerying(false);
    }
  };

  const handleRunAnalysis = async (e) => {
    e.preventDefault();
    setIsAnalyzing(true);
    try {
      const res = await explainFinding({
        finding_data: {
          algorithm: analyzerAlgo,
          key_size: parseInt(analyzerKeySize, 10) || undefined,
          primitive: analyzerPrimitive,
          sensitivity: analyzerSensitivity,
        },
      });
      setAnalyzerResult(res);
      toast.success('Vulnerability analysis generated!');
    } catch (err) {
      toast.error('Failed to analyze algorithm');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleGenerateExecutiveSummary = async () => {
    const scanId = selectedScanId || (scans.length > 0 ? scans[0].id : null);
    if (!scanId) {
      toast.error('No scan selected');
      return;
    }
    setIsGeneratingSummary(true);
    try {
      const res = await getScanAISummary(scanId);
      setScanSummary(res);
      toast.success('Executive board summary generated!');
    } catch (err) {
      toast.error('Failed to generate scan executive summary');
    } finally {
      setIsGeneratingSummary(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
          <span>🧠</span> AI Cryptographic Advisor & Explainer
        </h1>
        <p className="text-sm text-gray-400 mt-1">
          Mathematically grounded reasoning on quantum attack algorithms (Shor & Grover), qubit estimations, HNDL threats, and FIPS 203/204 migrations.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Interactive Q&A Console (2 cols) */}
        <div className="lg:col-span-2 space-y-4">
          {/* Q&A Chat Container */}
          <div className="glass-card p-6 flex flex-col h-[520px] border border-white/10">
            <h2 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider mb-3 flex items-center justify-between">
              <span>Cryptographic Knowledge Q&A</span>
              <span className="text-[10px] text-gray-500 font-mono">Expert Deterministic + LLM Mode</span>
            </h2>

            {/* Quick Prompt Chips */}
            <div className="flex flex-wrap gap-1.5 mb-4">
              {QUICK_PROMPTS.map((prompt, idx) => (
                <button
                  key={idx}
                  onClick={() => handleSendQuery(prompt)}
                  className="px-2.5 py-1 rounded-full text-[11px] bg-white/5 hover:bg-cyan-500/10 text-gray-300 hover:text-cyan-300 border border-white/5 hover:border-cyan-500/30 transition-colors text-left"
                >
                  💡 {prompt}
                </button>
              ))}
            </div>

            {/* Messages Scroll Area */}
            <div className="flex-1 overflow-y-auto space-y-4 pr-2">
              {qaHistory.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-center text-gray-500 text-sm">
                  <span className="text-4xl mb-2">💬</span>
                  <p>Ask any technical question regarding quantum vulnerabilities, Mosca's theorem, or post-quantum standards.</p>
                </div>
              ) : (
                qaHistory.map((item) => (
                  <div key={item.id} className="space-y-2">
                    {/* User Prompt */}
                    <div className="flex justify-end">
                      <div className="max-w-[85%] px-4 py-2 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-xs text-cyan-200">
                        {item.question}
                      </div>
                    </div>
                    {/* AI Answer */}
                    <div className="flex justify-start">
                      <div className="max-w-[95%] p-4 rounded-xl bg-navy-950/80 border border-white/10 text-xs text-gray-200 space-y-2">
                        <div className="flex items-center justify-between text-[10px] text-gray-500 border-b border-white/5 pb-1">
                          <span className="font-semibold text-emerald-400">CipherSight AI Engine</span>
                          <span className="font-mono">{item.engine}</span>
                        </div>
                        <p className="leading-relaxed">{item.answer}</p>
                        {item.references && item.references.length > 0 && (
                          <div className="pt-2 border-t border-white/5 text-[10px] text-gray-400">
                            <strong>References: </strong> {item.references.join(' • ')}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>

            {/* Input Bar */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSendQuery();
              }}
              className="mt-4 flex gap-2 pt-2 border-t border-white/5"
            >
              <input
                type="text"
                placeholder="Ask about Shor, Grover, HNDL, FIPS 203/204, or migration strategy..."
                value={queryInput}
                onChange={(e) => setQueryInput(e.target.value)}
                className="flex-1 px-4 py-2 rounded-lg bg-navy-950 border border-white/10 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-cyan-400/50"
              />
              <button
                type="submit"
                disabled={isQuerying || !queryInput.trim()}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-black transition-colors disabled:opacity-50 shadow-glow-cyan"
              >
                {isQuerying ? 'Computing...' : 'Ask AI'}
              </button>
            </form>
          </div>

          {/* Executive Board Summary Card */}
          <div className="glass-card p-6 border border-white/10 space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-white/5 pb-3">
              <div>
                <h2 className="text-sm font-bold text-white flex items-center gap-2">
                  <span>👔</span> Executive Post-Quantum Readiness Summary
                </h2>
                <p className="text-xs text-gray-400">
                  Generate board-ready assessments of enterprise quantum exposure.
                </p>
              </div>
              <div className="flex items-center gap-2">
                <select
                  value={selectedScanId}
                  onChange={(e) => setSelectedScanId(e.target.value)}
                  className="px-3 py-1.5 rounded-lg bg-navy-950 border border-white/10 text-xs text-white"
                >
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.target} ({s.id.substring(0, 8)})
                    </option>
                  ))}
                </select>
                <button
                  onClick={handleGenerateExecutiveSummary}
                  disabled={isGeneratingSummary}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-purple-500 hover:bg-purple-400 text-white transition-colors disabled:opacity-50"
                >
                  {isGeneratingSummary ? 'Synthesizing...' : 'Synthesize Report'}
                </button>
              </div>
            </div>

            {scanSummary && (
              <div className="space-y-3 text-xs">
                <div className="flex items-center gap-3">
                  <span className="text-gray-400">Readiness Posture:</span>
                  <span className="px-2.5 py-0.5 rounded font-bold text-xs bg-red-500/20 text-red-400 border border-red-500/40">
                    {scanSummary.quantum_readiness_posture}
                  </span>
                  <span className="text-gray-500">
                    ({scanSummary.vulnerable_findings_count} vulnerable of {scanSummary.total_findings} total findings)
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-navy-950/80 border border-white/5 leading-relaxed text-gray-200">
                  {scanSummary.executive_summary}
                </div>

                {scanSummary.recommended_priority_actions && (
                  <div>
                    <span className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider block mb-1">
                      Recommended Strategic Actions:
                    </span>
                    <ul className="list-disc list-inside space-y-1 text-gray-300">
                      {scanSummary.recommended_priority_actions.map((act, idx) => (
                        <li key={idx}>{act}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Custom Algorithm Vulnerability Analyzer (1 col) */}
        <div className="glass-card p-6 border border-white/10 flex flex-col space-y-4">
          <h2 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">
            Custom Primitive Analyzer
          </h2>
          <form onSubmit={handleRunAnalysis} className="space-y-3">
            <div>
              <label className="block text-[11px] text-gray-400 mb-1">Algorithm</label>
              <select
                value={analyzerAlgo}
                onChange={(e) => setAnalyzerAlgo(e.target.value)}
                className="w-full px-3 py-1.5 rounded bg-navy-950 border border-white/10 text-xs text-white"
              >
                <option value="RSA">RSA</option>
                <option value="ECDSA">ECDSA</option>
                <option value="ECDH">ECDH</option>
                <option value="Diffie-Hellman">Diffie-Hellman</option>
                <option value="AES-128">AES-128</option>
                <option value="AES-256">AES-256</option>
                <option value="ML-KEM-768">ML-KEM-768 (FIPS 203)</option>
                <option value="ML-DSA-65">ML-DSA-65 (FIPS 204)</option>
              </select>
            </div>

            <div>
              <label className="block text-[11px] text-gray-400 mb-1">Key Size (bits)</label>
              <input
                type="number"
                value={analyzerKeySize}
                onChange={(e) => setAnalyzerKeySize(e.target.value)}
                className="w-full px-3 py-1.5 rounded bg-navy-950 border border-white/10 text-xs text-white"
              />
            </div>

            <div>
              <label className="block text-[11px] text-gray-400 mb-1">Data Sensitivity</label>
              <select
                value={analyzerSensitivity}
                onChange={(e) => setAnalyzerSensitivity(e.target.value)}
                className="w-full px-3 py-1.5 rounded bg-navy-950 border border-white/10 text-xs text-white"
              >
                <option value="financial">Financial (PCI/Banking)</option>
                <option value="authentication">Authentication (JWT/Tokens)</option>
                <option value="government_id">Government ID / Classified</option>
                <option value="medical">Medical / HIPAA</option>
                <option value="general">General / Public</option>
              </select>
            </div>

            <button
              type="submit"
              disabled={isAnalyzing}
              className="w-full py-2 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-black transition-colors disabled:opacity-50"
            >
              {isAnalyzing ? 'Calculating...' : '🔬 Analyze Quantum Vulnerability'}
            </button>
          </form>

          {/* Analysis Card Output */}
          {analyzerResult && (
            <div className="pt-3 border-t border-white/5 space-y-3 text-xs overflow-y-auto max-h-[380px]">
              <div>
                <span className="text-gray-500 uppercase text-[10px] tracking-wider">Attack Vector:</span>
                <div className="font-bold text-red-400">
                  {analyzerResult.theoretical_foundation?.attack_algorithm}
                </div>
              </div>

              <div>
                <span className="text-gray-500 uppercase text-[10px] tracking-wider">Quantum Complexity:</span>
                <div className="font-mono text-amber-300">
                  {analyzerResult.theoretical_foundation?.quantum_complexity}
                </div>
              </div>

              <div>
                <span className="text-gray-500 uppercase text-[10px] tracking-wider">Logical Qubit Estimate:</span>
                <div className="font-mono text-purple-300">
                  {analyzerResult.theoretical_foundation?.qubits_required_estimate}
                </div>
              </div>

              <div>
                <span className="text-gray-500 uppercase text-[10px] tracking-wider">HNDL Exposure:</span>
                <div className="font-bold text-red-400">
                  {analyzerResult.harvest_now_decrypt_later_risk?.hndl_exposure}
                </div>
              </div>

              <div className="p-2.5 rounded bg-navy-950 border border-white/5">
                <span className="text-gray-400 font-semibold block mb-1 text-[11px]">Recommended Replacement:</span>
                <div className="text-emerald-400 font-mono font-bold">
                  {analyzerResult.tailored_remediation?.recommended_replacement}
                </div>
                <div className="text-[10px] text-gray-500">
                  Standard: {analyzerResult.tailored_remediation?.target_standard}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
