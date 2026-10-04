import React, { useState } from 'react';
import {
  X,
  Zap,
  Globe,
  Bot,
  Terminal,
  CheckCircle2,
  Copy,
  Check,
  ShieldCheck,
  AlertCircle,
  ExternalLink,
} from 'lucide-react';
import { aegisApi } from '../api/endpoints';
import { API_BASE } from '../api/client';

interface ConnectProductModalProps {
  isOpen: boolean;
  onClose: () => void;
  onProductConnected: () => void;
}

export const ConnectProductModal: React.FC<ConnectProductModalProps> = ({
  isOpen,
  onClose,
  onProductConnected,
}) => {
  const [activeTab, setActiveTab] = useState<'api' | 'llm' | 'sdk'>('api');
  const [productName, setProductName] = useState('');
  const [endpointUrl, setEndpointUrl] = useState('');
  const [productType, setProductType] = useState<'microservice' | 'ai_application' | 'api_gateway'>('microservice');
  const [environment, setEnvironment] = useState('production');
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const [result, setResult] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!productName.trim()) return;

    try {
      setLoading(true);
      setError(null);
      const res = await aegisApi.connectProduct({
        product_name: productName.trim(),
        product_type: activeTab === 'llm' ? 'ai_application' : productType,
        endpoint_url: endpointUrl.trim() || undefined,
        environment,
        probe_health: true,
      });
      setResult(res);
      onProductConnected();
    } catch (err: any) {
      setError(err.message || 'Failed to connect product');
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setResult(null);
    setProductName('');
    setEndpointUrl('');
    setError(null);
  };

  return (
    <div style={styles.overlay}>
      <div style={styles.modalCard}>
        {/* Header */}
        <div style={styles.header}>
          <div style={styles.titleGroup}>
            <div style={styles.iconBadge}>
              <Zap size={18} color="var(--accent-cyan)" />
            </div>
            <div>
              <h2 style={styles.title}>1-Click Connect Client Product</h2>
              <p style={styles.subtitle}>
                Auto-instrument your microservice or AI system into the AEGIS Reliability Mesh
              </p>
            </div>
          </div>
          <button style={styles.closeBtn} onClick={onClose} title="Close">
            <X size={18} />
          </button>
        </div>

        {/* Tab Selection */}
        {!result && (
          <div style={styles.tabBar}>
            <button
              style={activeTab === 'api' ? styles.tabActive : styles.tab}
              onClick={() => { setActiveTab('api'); setProductType('microservice'); }}
            >
              <Globe size={14} /> Web App / Microservice
            </button>
            <button
              style={activeTab === 'llm' ? styles.tabActive : styles.tab}
              onClick={() => { setActiveTab('llm'); setProductType('ai_application'); }}
            >
              <Bot size={14} /> AI Application (LLM Proxy)
            </button>
            <button
              style={activeTab === 'sdk' ? styles.tabActive : styles.tab}
              onClick={() => setActiveTab('sdk')}
            >
              <Terminal size={14} /> 2-Line SDK Drop-in
            </button>
          </div>
        )}

        {/* Body Content */}
        <div style={styles.body}>
          {result ? (
            /* Success State */
            <div style={styles.successContainer}>
              <div style={styles.successBadge}>
                <CheckCircle2 size={36} color="#10b981" />
              </div>
              <h3 style={styles.successTitle}>
                {result.product_name} Connected Successfully!
              </h3>
              <p style={styles.successDesc}>{result.message}</p>

              <div style={styles.credsBox}>
                <div style={styles.credRow}>
                  <span style={styles.credLabel}>AEGIS NODE ID:</span>
                  <code style={styles.credValue}>{result.product_id}</code>
                </div>
                <div style={styles.credRow}>
                  <span style={styles.credLabel}>SECURITY TOKEN:</span>
                  <div style={styles.copyWrapper}>
                    <code style={styles.credValue}>{result.connection_token}</code>
                    <button
                      style={styles.copyBtn}
                      onClick={() => handleCopy(result.connection_token, 'token')}
                    >
                      {copied === 'token' ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                    </button>
                  </div>
                </div>
                {activeTab === 'llm' && (
                  <div style={styles.credRow}>
                    <span style={styles.credLabel}>OPENAI PROXY URL:</span>
                    <div style={styles.copyWrapper}>
                      <code style={styles.credValue}>{result.proxy_endpoint}</code>
                      <button
                        style={styles.copyBtn}
                        onClick={() => handleCopy(result.proxy_endpoint, 'proxy')}
                      >
                        {copied === 'proxy' ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                      </button>
                    </div>
                  </div>
                )}
              </div>

              <div style={styles.actionRow}>
                <button className="btn btn-primary" onClick={onClose}>
                  View in Topology Mesh
                </button>
                <button className="btn" onClick={handleReset}>
                  Connect Another Product
                </button>
              </div>
            </div>
          ) : activeTab === 'sdk' ? (
            /* SDK Code Snippet Tab */
            <div style={styles.sdkTab}>
              <p style={styles.formHint}>
                Add 2 lines of code to your application startup file to report live latency, errors, and traces directly into AEGIS.
              </p>

              {(() => {
                const effectiveApiUrl = API_BASE.startsWith('http')
                  ? API_BASE.replace(/\/api\/v1$/, '')
                  : (typeof window !== 'undefined' ? window.location.origin : 'https://api.aegis.ai');
                return (
                  <>
                    <div style={styles.codeBlockHeader}>
                      <span>Python (FastAPI / Flask / Django)</span>
                      <button
                        style={styles.copyBtn}
                        onClick={() =>
                          handleCopy(
                            `import aegis\naegis.init(api_url="${effectiveApiUrl}", service_name="my-client-app")`,
                            'py'
                          )
                        }
                      >
                        {copied === 'py' ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                      </button>
                    </div>
                    <pre style={styles.codeSnippet}>
                      {`# 1. pip install aegis-client\nimport aegis\naegis.init(api_url="${effectiveApiUrl}", service_name="my-client-app")`}
                    </pre>

                    <div style={styles.codeBlockHeader}>
                      <span>Node.js / TypeScript (Express / Next.js)</span>
                      <button
                        style={styles.copyBtn}
                        onClick={() =>
                          handleCopy(
                            `import { aegis } from '@aegis/sdk';\naegis.connect({ endpoint: '${effectiveApiUrl}', service: 'my-client-app' });`,
                            'js'
                          )
                        }
                      >
                        {copied === 'js' ? <Check size={12} color="#10b981" /> : <Copy size={12} />}
                      </button>
                    </div>
                    <pre style={styles.codeSnippet}>
                      {`// 1. npm i @aegis/sdk\nimport { aegis } from '@aegis/sdk';\naegis.connect({ endpoint: '${effectiveApiUrl}', service: 'my-client-app' });`}
                    </pre>
                  </>
                );
              })()}
            </div>
          ) : (
            /* Form Input (1-Click Connect) */
            <form onSubmit={handleConnect} style={styles.form}>
              <div style={styles.inputGroup}>
                <label style={styles.label}>Product / Service Name *</label>
                <input
                  style={styles.input}
                  placeholder="e.g. Stripe Checkout Gateway or Customer Portal"
                  value={productName}
                  onChange={(e) => setProductName(e.target.value)}
                  required
                />
              </div>

              <div style={styles.inputGroup}>
                <label style={styles.label}>
                  {activeTab === 'llm' ? 'Model Provider / Backend URL (Optional)' : 'Health Check / Base URL (Optional)'}
                </label>
                <input
                  style={styles.input}
                  placeholder={
                    activeTab === 'llm'
                      ? 'https://api.openai.com/v1 (or local vLLM / Ollama)'
                      : 'http://localhost:3000/health or https://api.myclient.com'
                  }
                  value={endpointUrl}
                  onChange={(e) => setEndpointUrl(e.target.value)}
                />
                <span style={styles.inputHint}>
                  {activeTab === 'llm'
                    ? 'AEGIS will proxy all prompt traffic, enforce LLM firewall rules, and detect hallucinations.'
                    : 'AEGIS will ping this endpoint to auto-verify availability and latency.'}
                </span>
              </div>

              <div style={styles.row}>
                <div style={{ ...styles.inputGroup, flex: 1 }}>
                  <label style={styles.label}>Environment</label>
                  <select
                    style={styles.select}
                    value={environment}
                    onChange={(e) => setEnvironment(e.target.value)}
                  >
                    <option value="production">Production</option>
                    <option value="staging">Staging</option>
                    <option value="development">Development</option>
                  </select>
                </div>
              </div>

              {error && (
                <div style={styles.errorNotice}>
                  <AlertCircle size={14} color="#ef4444" />
                  <span>{error}</span>
                </div>
              )}

              <div style={styles.footerRow}>
                <button type="button" className="btn" onClick={onClose}>
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={loading || !productName.trim()}
                >
                  {loading ? 'Verifying & Connecting...' : '⚡ Connect in 1 Click'}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};

const styles: Record<string, React.CSSProperties> = {
  overlay: {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(5, 10, 20, 0.75)',
    backdropFilter: 'blur(8px)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 100,
    padding: '1rem',
  },
  modalCard: {
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--accent-cyan)',
    boxShadow: '0 0 35px rgba(6, 182, 212, 0.25)',
    borderRadius: '12px',
    width: '100%',
    maxWidth: '560px',
    overflow: 'hidden',
    display: 'flex',
    flexDirection: 'column',
    animation: 'fadeIn 0.2s ease-out',
  },
  header: {
    padding: '1.25rem 1.5rem',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    borderBottom: '1px solid var(--border-color)',
    background: 'var(--bg-elevated)',
  },
  titleGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.85rem',
  },
  iconBadge: {
    width: '36px',
    height: '36px',
    borderRadius: '8px',
    backgroundColor: 'rgba(6, 182, 212, 0.12)',
    border: '1px solid var(--accent-cyan)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  title: {
    fontSize: '1.05rem',
    fontWeight: 700,
    color: 'var(--text-primary)',
    margin: 0,
  },
  subtitle: {
    fontSize: '0.75rem',
    color: 'var(--text-secondary)',
    margin: 0,
    marginTop: '0.2rem',
  },
  closeBtn: {
    background: 'transparent',
    border: 'none',
    color: 'var(--text-muted)',
    cursor: 'pointer',
    padding: '0.35rem',
    borderRadius: '6px',
    display: 'flex',
    alignItems: 'center',
  },
  tabBar: {
    display: 'flex',
    backgroundColor: 'rgba(15, 23, 42, 0.4)',
    borderBottom: '1px solid var(--border-color)',
  },
  tab: {
    flex: 1,
    padding: '0.75rem',
    background: 'transparent',
    border: 'none',
    borderBottom: '2px solid transparent',
    color: 'var(--text-secondary)',
    fontSize: '0.78rem',
    fontWeight: 600,
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '0.45rem',
  },
  tabActive: {
    flex: 1,
    padding: '0.75rem',
    background: 'rgba(6, 182, 212, 0.08)',
    border: 'none',
    borderBottom: '2px solid var(--accent-cyan)',
    color: 'var(--accent-cyan)',
    fontSize: '0.78rem',
    fontWeight: 700,
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '0.45rem',
  },
  body: {
    padding: '1.5rem',
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.1rem',
  },
  inputGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.35rem',
  },
  label: {
    fontSize: '0.74rem',
    fontWeight: 700,
    color: 'var(--text-secondary)',
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
  },
  input: {
    backgroundColor: 'var(--bg-primary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.65rem 0.85rem',
    color: 'var(--text-primary)',
    fontSize: '0.85rem',
    outline: 'none',
  },
  select: {
    backgroundColor: 'var(--bg-primary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.65rem 0.85rem',
    color: 'var(--text-primary)',
    fontSize: '0.85rem',
    outline: 'none',
  },
  inputHint: {
    fontSize: '0.7rem',
    color: 'var(--text-muted)',
    marginTop: '0.15rem',
  },
  row: {
    display: 'flex',
    gap: '1rem',
  },
  footerRow: {
    display: 'flex',
    justifyContent: 'flex-end',
    gap: '0.75rem',
    marginTop: '0.5rem',
  },
  errorNotice: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    padding: '0.6rem 0.85rem',
    borderRadius: '6px',
    backgroundColor: 'rgba(239, 68, 68, 0.15)',
    color: '#fca5a5',
    fontSize: '0.78rem',
  },
  successContainer: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    textAlign: 'center',
    gap: '0.75rem',
    padding: '0.5rem 0',
  },
  successBadge: {
    width: '60px',
    height: '60px',
    borderRadius: '50%',
    backgroundColor: 'rgba(16, 185, 129, 0.12)',
    border: '1px solid #10b981',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  successTitle: {
    fontSize: '1.15rem',
    fontWeight: 700,
    color: 'var(--text-primary)',
    margin: 0,
  },
  successDesc: {
    fontSize: '0.82rem',
    color: 'var(--text-secondary)',
    margin: 0,
  },
  credsBox: {
    width: '100%',
    backgroundColor: 'var(--bg-primary)',
    border: '1px solid var(--border-color)',
    borderRadius: '8px',
    padding: '0.85rem',
    marginTop: '0.75rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.55rem',
    textAlign: 'left',
  },
  credRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    fontSize: '0.76rem',
  },
  credLabel: {
    color: 'var(--text-muted)',
    fontWeight: 600,
    fontFamily: 'var(--font-mono)',
  },
  credValue: {
    color: 'var(--accent-cyan)',
    fontFamily: 'var(--font-mono)',
    fontSize: '0.76rem',
  },
  copyWrapper: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.45rem',
  },
  copyBtn: {
    background: 'rgba(255, 255, 255, 0.08)',
    border: 'none',
    color: 'var(--text-primary)',
    cursor: 'pointer',
    padding: '0.25rem',
    borderRadius: '4px',
    display: 'flex',
    alignItems: 'center',
  },
  actionRow: {
    display: 'flex',
    gap: '0.75rem',
    marginTop: '1rem',
  },
  sdkTab: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.75rem',
  },
  formHint: {
    fontSize: '0.8rem',
    color: 'var(--text-secondary)',
    margin: 0,
  },
  codeBlockHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    fontSize: '0.74rem',
    fontWeight: 600,
    color: 'var(--text-muted)',
    marginTop: '0.35rem',
  },
  codeSnippet: {
    backgroundColor: 'var(--bg-primary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.75rem',
    color: '#38bdf8',
    fontFamily: 'var(--font-mono)',
    fontSize: '0.74rem',
    lineHeight: 1.45,
    margin: 0,
    overflowX: 'auto',
  },
};
