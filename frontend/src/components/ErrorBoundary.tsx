import { Component, type ReactNode } from 'react'
import { AlertTriangle, RefreshCw } from 'lucide-react'

interface Props {
  children: ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
  errorInfo: string
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null, errorInfo: '' }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: '' }
  }

  componentDidCatch(error: Error, info: { componentStack: string }) {
    this.setState({ errorInfo: info.componentStack })
    console.error('TraceVault ErrorBoundary caught:', error, info)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-background flex items-center justify-center p-6">
          <div className="max-w-lg w-full bg-card border border-destructive/40 rounded-xl p-6 shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <AlertTriangle className="w-6 h-6 text-red-500 shrink-0" />
              <h2 className="text-lg font-semibold text-foreground">Application Error</h2>
            </div>
            <p className="text-muted-foreground text-sm mb-3">
              TraceVault encountered an unexpected error. Please refresh the page.
            </p>
            {this.state.error && (
              <div className="bg-secondary rounded-lg p-3 mb-4 font-mono text-xs text-red-400 overflow-auto max-h-32">
                <p className="font-semibold">{this.state.error.name}: {this.state.error.message}</p>
                {this.state.errorInfo && (
                  <pre className="mt-2 text-muted-foreground whitespace-pre-wrap">
                    {this.state.errorInfo.split('\n').slice(0, 8).join('\n')}
                  </pre>
                )}
              </div>
            )}
            <button
              onClick={() => window.location.reload()}
              className="flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg text-sm font-medium hover:bg-primary/90"
            >
              <RefreshCw className="w-4 h-4" />
              Reload Page
            </button>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
