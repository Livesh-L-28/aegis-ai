import React from 'react';
import { GitBranch, Server, Database, Layers, ArrowRight } from 'lucide-react';
import type { SystemDependencyGraph } from '../types';

interface DependenciesViewProps {
  graph: SystemDependencyGraph | null;
}

export const DependenciesView: React.FC<DependenciesViewProps> = ({ graph }) => {
  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <div>
          <h1 style={styles.heading}>System Dependency Topology</h1>
          <p style={styles.subheading}>
            Live Service Nodes, Inter-Service RPC, Caching & Data Layer Mappings
          </p>
        </div>
      </div>

      {/* Interactive Topology Graph Visualizer */}
      <div style={styles.canvasCard}>
        <div style={styles.cardHeader}>
          <h2 style={styles.cardTitle}>Topology Architecture Map & Data Flow</h2>
        </div>
        <div style={styles.canvasArea}>
          <div style={styles.topologyMap}>
            {graph?.nodes.map((node, i) => {
              const total = graph?.nodes.length || 1;
              const angle = (i / total) * 2 * Math.PI;
              const radius = 130;
              const left = 240 + Math.cos(angle) * radius;
              const top = 160 + Math.sin(angle) * radius;
              return (
                <div
                  key={node.id}
                  style={{
                    ...styles.topoNode,
                    left: `${left}px`,
                    top: `${top}px`,
                  }}
                  title={`Service: ${node.name} (${node.type})`}
                >
                  <div style={styles.topoIcon}>
                    {node.type === 'database' ? (
                      <Database size={14} color="var(--accent-cyan)" />
                    ) : node.type === 'cache' ? (
                      <Layers size={14} color="#a855f7" />
                    ) : (
                      <Server size={14} color="#38bdf8" />
                    )}
                  </div>
                  <span style={styles.topoLabel}>{node.name}</span>
                  <span style={styles.topoStatusDot}></span>
                </div>
              );
            })}
            <div style={styles.centerHub}>
              <GitBranch size={22} color="var(--accent-cyan)" />
              <span style={styles.hubLabel}>AEGIS MESH</span>
            </div>
          </div>
        </div>
      </div>

      <div style={styles.contentGrid}>
        {/* Nodes List */}
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <h2 style={styles.cardTitle}>Topology Services ({graph?.nodes.length || 0})</h2>
          </div>
          <div style={styles.cardBody}>
            {graph?.nodes.map((node) => (
              <div key={node.id} style={styles.nodeItem}>
                <div style={styles.nodeIcon}>
                  {node.type === 'database' ? (
                    <Database size={16} color="var(--accent-cyan)" />
                  ) : node.type === 'cache' ? (
                    <Layers size={16} color="#a855f7" />
                  ) : (
                    <Server size={16} color="#38bdf8" />
                  )}
                </div>
                <div style={styles.nodeInfo}>
                  <div style={styles.nodeName}>{node.name}</div>
                  <div style={styles.nodeMeta}>
                    Type: {node.type} | Env: {node.environment}
                  </div>
                </div>
                <span className="badge badge-success">{node.status}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Directed Edges */}
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <h2 style={styles.cardTitle}>Inter-Service Dependencies ({graph?.edges.length || 0})</h2>
          </div>
          <div style={styles.cardBody}>
            {graph?.edges.map((edge, idx) => (
              <div key={idx} style={styles.edgeItem}>
                <div style={styles.edgeLeft}>{edge.source}</div>
                <ArrowRight size={14} color="var(--accent-cyan)" />
                <div style={styles.edgeRight}>{edge.target}</div>
                <span className="badge badge-neutral" style={{ marginLeft: 'auto' }}>
                  {edge.protocol}
                </span>
              </div>
            ))}
          </div>
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
    gap: '1.5rem',
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
  contentGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))',
    gap: '1.5rem',
  },
  card: {
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
  nodeItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.85rem',
    padding: '0.75rem',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '8px',
  },
  nodeIcon: {
    width: '32px',
    height: '32px',
    borderRadius: '6px',
    backgroundColor: 'rgba(56, 189, 248, 0.1)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  nodeInfo: {
    flex: 1,
  },
  nodeName: {
    fontSize: '0.85rem',
    fontWeight: 600,
    color: 'var(--text-primary)',
    fontFamily: 'monospace',
  },
  nodeMeta: {
    fontSize: '0.72rem',
    color: 'var(--text-muted)',
  },
  edgeItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    padding: '0.65rem 0.85rem',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
  },
  edgeLeft: {
    fontSize: '0.8rem',
    fontWeight: 600,
    color: 'var(--text-primary)',
    fontFamily: 'monospace',
  },
  edgeRight: {
    fontSize: '0.8rem',
    fontWeight: 600,
    color: '#38bdf8',
    fontFamily: 'monospace',
  },
  canvasCard: {
    backgroundColor: 'var(--bg-card)',
    backdropFilter: 'blur(10px)',
    border: '1px solid var(--border-color)',
    borderRadius: '10px',
    overflow: 'hidden',
  },
  canvasArea: {
    padding: '1.5rem',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: 'rgba(5, 10, 20, 0.75)',
    backgroundImage: 'radial-gradient(rgba(6, 182, 212, 0.15) 1px, transparent 1px)',
    backgroundSize: '24px 24px',
  },
  topologyMap: {
    position: 'relative',
    width: '560px',
    height: '360px',
  },
  topoNode: {
    position: 'absolute',
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    padding: '0.45rem 0.75rem',
    borderRadius: '8px',
    backgroundColor: 'rgba(15, 23, 42, 0.95)',
    border: '1px solid var(--accent-cyan)',
    boxShadow: '0 0 14px rgba(6, 182, 212, 0.25)',
    transform: 'translate(-50%, -50%)',
    zIndex: 2,
    transition: 'all 0.2s ease',
  },
  topoIcon: {
    display: 'flex',
    alignItems: 'center',
  },
  topoLabel: {
    fontSize: '0.74rem',
    fontWeight: 600,
    color: 'var(--text-primary)',
    fontFamily: 'var(--font-mono)',
  },
  topoStatusDot: {
    width: '6px',
    height: '6px',
    borderRadius: '50%',
    backgroundColor: '#10b981',
    boxShadow: '0 0 6px #10b981',
  },
  centerHub: {
    position: 'absolute',
    left: '240px',
    top: '160px',
    transform: 'translate(-50%, -50%)',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    gap: '0.25rem',
    padding: '0.85rem 1rem',
    borderRadius: '50%',
    width: '90px',
    height: '90px',
    justifyContent: 'center',
    backgroundColor: 'rgba(6, 182, 212, 0.12)',
    border: '2px dashed var(--accent-cyan)',
    boxShadow: '0 0 25px rgba(6, 182, 212, 0.3)',
    zIndex: 1,
  },
  hubLabel: {
    fontSize: '0.62rem',
    fontWeight: 800,
    color: 'var(--accent-cyan)',
    letterSpacing: '0.08em',
  },
};
