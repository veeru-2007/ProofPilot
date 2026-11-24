import { Component, StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import './workspace.css'
import App from './App.jsx'

class WorkspaceErrorBoundary extends Component {
  state = { failed: false }

  static getDerivedStateFromError() {
    return { failed: true }
  }

  render() {
    if (!this.state.failed) return this.props.children
    return (
      <main className="content">
        <div className="error-banner" role="alert">
          <span>ProofPilot could not display this view. Reload the workspace to fetch fresh data.</span>
          <button type="button" onClick={() => this.setState({ failed: false })}>Reload workspace</button>
        </div>
      </main>
    )
  }
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <WorkspaceErrorBoundary><App /></WorkspaceErrorBoundary>
  </StrictMode>,
)
