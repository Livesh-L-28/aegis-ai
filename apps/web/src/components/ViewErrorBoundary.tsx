import React, { Component, type ErrorInfo, type ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
  tabName?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ViewErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error in view boundary:', error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div style={styles.errorContainer}>
          <div style={styles.card}>
            <AlertTriangle size={36} color="#ef4444" />
            <h2 style={styles.title}>
              {this.props.tabName ? `${this.props.tabName} View Error` : 'Component Error'}
            </h2>
            <p style={styles.desc}>
              An isolated error occurred in this view. Other command center functions remain active.
            </p>
            <div style={styles.errorDetails}>
              <code>{this.state.error?.message || 'Unknown error'}</code>
            </div>
            <button className="btn btn-sm btn-primary" onClick={this.handleReset}>
              <RefreshCw size={14} /> Retry View
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

const styles: Record<string, React.CSSProperties> = {
  errorContainer: {
    padding: '3rem 2rem',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    height: '100%',
  },
  card: {
    maxWidth: '520px',
    backgroundColor: 'var(--bg-card)',
    border: '1px solid rgba(239, 68, 68, 0.4)',
    borderRadius: '12px',
    padding: '2rem',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    textAlign: 'center',
    gap: '1rem',
  },
  title: {
    color: 'var(--text-primary)',
    fontSize: '1.2rem',
    fontWeight: 600,
  },
  desc: {
    color: 'var(--text-secondary)',
    fontSize: '0.85rem',
    lineHeight: 1.5,
  },
  errorDetails: {
    width: '100%',
    padding: '0.75rem',
    borderRadius: '6px',
    backgroundColor: 'rgba(0, 0, 0, 0.4)',
    color: '#fca5a5',
    fontSize: '0.75rem',
    fontFamily: 'monospace',
    overflowX: 'auto',
    textAlign: 'left',
  },
};
