import { useState } from 'react'

export default function CopyValue({ value, label = 'value', className = '' }) {
  const [copied, setCopied] = useState(false)
  const available = typeof value === 'string' && value.length > 0

  const copy = async () => {
    if (!available || !navigator.clipboard?.writeText) return
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1400)
    } catch {
      setCopied(false)
    }
  }

  return (
    <span className={`copy-value ${className}`.trim()}>
      <code title={label}>{available ? value : 'Unavailable'}</code>
      <button type="button" onClick={copy} disabled={!available} aria-label={`Copy ${label}`}>
        {copied ? 'Copied' : 'Copy'}
      </button>
    </span>
  )
}
