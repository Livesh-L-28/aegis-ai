import React, { useState } from 'react';
import { BookOpen, Search, FileText } from 'lucide-react';
import { aegisApi } from '../api/endpoints';

export const KnowledgeView: React.FC = () => {
  const [query, setQuery] = useState<string>('database');
  const [results, setResults] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(false);

  // New Document Upload State
  const [showUpload, setShowUpload] = useState<boolean>(false);
  const [uploadTitle, setUploadTitle] = useState<string>('');
  const [uploadContent, setUploadContent] = useState<string>('');
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [uploading, setUploading] = useState<boolean>(false);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query) return;
    try {
      setLoading(true);
      const res = await aegisApi.searchKnowledge(query);
      setResults(res.knowledge_matches || []);
    } finally {
      setLoading(false);
    }
  };

  const handleIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!uploadTitle.trim() || !uploadContent.trim()) return;
    try {
      setUploading(true);
      setUploadStatus(null);
      await aegisApi.ingestKnowledgeDocument({
        title: uploadTitle.trim(),
        content: uploadContent.trim(),
        source_type: 'RUNBOOK',
        source_uri: `docs/runbooks/${uploadTitle.toLowerCase().replace(/\s+/g, '-')}.md`,
      });
      setUploadStatus('Document successfully ingested, chunked, and embedded into vector store!');
      setUploadTitle('');
      setUploadContent('');
      // Auto-trigger search to show newly embedded runbook
      const res = await aegisApi.searchKnowledge(uploadTitle.split(' ')[0] || 'database');
      setResults(res.knowledge_matches || []);
    } catch (err: any) {
      setUploadStatus(`Ingestion failed: ${err.message || 'Unknown error'}`);
    } finally {
      setUploading(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadTitle(file.name.replace(/\.[^/.]+$/, ''));
    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setUploadContent(content || '');
    };
    reader.readAsText(file);
  };

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <div>
          <h1 style={styles.heading}>Knowledge & Runbook Intelligence</h1>
          <p style={styles.subheading}>
            Runbooks, Architecture Documentation, Postmortems & Grounded Operational Context
          </p>
        </div>
        <button
          className="btn btn-sm btn-primary"
          onClick={() => setShowUpload(!showUpload)}
        >
          {showUpload ? 'Close Ingest Panel' : '+ Ingest New Runbook'}
        </button>
      </div>

      {/* Ingest Panel */}
      {showUpload && (
        <div style={styles.uploadCard}>
          <div style={styles.cardHeader}>
            <h2 style={styles.cardTitle}>Ingest Operational Runbook (Vector Embedding)</h2>
          </div>
          <form onSubmit={handleIngest} style={styles.uploadForm}>
            <div style={styles.inputGroup}>
              <label style={styles.label}>Runbook Title / Service Name</label>
              <input
                style={styles.textInput}
                placeholder="e.g., PostgreSQL High Connection Spillover Remediation"
                value={uploadTitle}
                onChange={(e) => setUploadTitle(e.target.value)}
                required
              />
            </div>

            <div style={styles.inputGroup}>
              <label style={styles.label}>Or Load File (.md, .txt, .json)</label>
              <input
                type="file"
                accept=".md,.txt,.json,.markdown"
                onChange={handleFileUpload}
                style={styles.fileInput}
              />
            </div>

            <div style={styles.inputGroup}>
              <label style={styles.label}>Runbook Markdown Content & SOP Procedures</label>
              <textarea
                style={styles.textArea}
                rows={5}
                placeholder="# Procedure for Redis Cache Exhaustion&#10;1. Drain worker queue&#10;2. Scale replica to 3 instances..."
                value={uploadContent}
                onChange={(e) => setUploadContent(e.target.value)}
                required
              />
            </div>

            {uploadStatus && (
              <div
                style={{
                  ...styles.statusNotice,
                  backgroundColor: uploadStatus.includes('failed')
                    ? 'rgba(239, 68, 68, 0.15)'
                    : 'rgba(16, 185, 129, 0.15)',
                  color: uploadStatus.includes('failed') ? '#fca5a5' : '#6ee7b7',
                }}
              >
                {uploadStatus}
              </div>
            )}

            <button type="submit" className="btn btn-sm btn-success" disabled={uploading}>
              {uploading ? 'Embedding Vectors...' : 'Embed & Index Runbook'}
            </button>
          </form>
        </div>
      )}

      <form onSubmit={handleSearch} style={styles.searchBar}>
        <Search size={16} color="var(--text-muted)" />
        <input
          style={styles.searchInput}
          placeholder="Search runbooks and operational guides (e.g. database, redis, payment)..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
        <button type="submit" className="btn btn-sm btn-primary" disabled={loading}>
          {loading ? 'Searching...' : 'Search'}
        </button>
      </form>

      <div style={styles.resultsCard}>
        <div style={styles.cardHeader}>
          <h2 style={styles.cardTitle}>Runbook Matches ({results.length})</h2>
        </div>
        <div style={styles.cardBody}>
          {results.length === 0 ? (
            <div style={styles.emptyNotice}>
              <BookOpen size={24} color="var(--text-muted)" />
              <p>Search runbook documents with hybrid vector retrieval.</p>
            </div>
          ) : (
            results.map((doc, i) => (
              <div key={i} style={styles.docRow}>
                <div style={styles.docHead}>
                  <span className="badge badge-info">{doc.source_type || 'RUNBOOK'}</span>
                  <span style={styles.docTitle}>{doc.title}</span>
                  <span style={styles.docScore}>Relevance: {doc.score || '0.92'}</span>
                </div>
                <div style={styles.docSnippet}>{doc.content_snippet || doc.content}</div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};

const styles: Record<string, React.CSSProperties> = {
  container: {
    padding: '1.75rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '1.25rem',
    height: '100%',
    overflowY: 'auto',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  heading: {
    fontSize: '1.4rem',
    fontWeight: 700,
    color: 'var(--text-primary)',
  },
  subheading: {
    fontSize: '0.825rem',
    color: 'var(--text-secondary)',
    marginTop: '0.2rem',
  },
  searchBar: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--border-color)',
    borderRadius: '8px',
    padding: '0.6rem 1rem',
  },
  searchInput: {
    flex: 1,
    background: 'transparent',
    border: 'none',
    color: 'var(--text-primary)',
    fontSize: '0.85rem',
    outline: 'none',
  },
  resultsCard: {
    backgroundColor: 'var(--bg-card)',
    backdropFilter: 'blur(10px)',
    border: '1px solid var(--border-color)',
    borderRadius: '10px',
    overflow: 'hidden',
  },
  cardHeader: {
    padding: '1rem 1.25rem',
    borderBottom: '1px solid var(--border-color)',
    background: 'var(--bg-elevated)',
  },
  cardTitle: {
    fontSize: '0.925rem',
    fontWeight: 600,
    color: 'var(--text-primary)',
  },
  cardBody: {
    padding: '1.25rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.75rem',
  },
  docRow: {
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.85rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.35rem',
  },
  docHead: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.65rem',
  },
  docTitle: {
    fontSize: '0.875rem',
    fontWeight: 600,
    color: 'var(--text-primary)',
  },
  docScore: {
    marginLeft: 'auto',
    fontSize: '0.72rem',
    color: 'var(--accent-cyan)',
  },
  docSnippet: {
    fontSize: '0.785rem',
    color: 'var(--text-secondary)',
    lineHeight: 1.4,
  },
  emptyNotice: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '3rem 1rem',
    color: 'var(--text-muted)',
    gap: '0.75rem',
  },
  uploadCard: {
    backgroundColor: 'var(--bg-card)',
    backdropFilter: 'blur(10px)',
    border: '1px solid var(--accent-cyan)',
    borderRadius: '10px',
    overflow: 'hidden',
    boxShadow: '0 0 20px rgba(6, 182, 212, 0.1)',
  },
  uploadForm: {
    padding: '1.25rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem',
  },
  inputGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.35rem',
  },
  label: {
    fontSize: '0.75rem',
    fontWeight: 600,
    color: 'var(--text-secondary)',
    textTransform: 'uppercase',
    letterSpacing: '0.04em',
  },
  textInput: {
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.6rem 0.85rem',
    color: 'var(--text-primary)',
    fontSize: '0.825rem',
    outline: 'none',
  },
  fileInput: {
    fontSize: '0.78rem',
    color: 'var(--text-secondary)',
  },
  textArea: {
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.6rem 0.85rem',
    color: 'var(--text-primary)',
    fontSize: '0.825rem',
    fontFamily: 'var(--font-mono)',
    outline: 'none',
    resize: 'vertical',
  },
  statusNotice: {
    padding: '0.6rem 0.85rem',
    borderRadius: '6px',
    fontSize: '0.78rem',
    fontWeight: 600,
  },
};
