import React from 'react'

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error) {
    console.error('[ICDS-H] Uncaught render error:', error)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-black text-[#ededed] flex items-center justify-center p-6">
          <div className="max-w-md text-center space-y-3">
            <h1 className="text-lg font-semibold">Console failed to render</h1>
            <p className="text-sm text-[#a1a1a1]">
              Reload the page. If this continues, sign out and sign back in.
            </p>
            <button
              type="button"
              className="px-4 py-2 rounded-md bg-white text-black text-sm font-medium"
              onClick={() => window.location.reload()}
            >
              Reload
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
