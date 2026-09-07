import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'
import type { Severity, IOCType, AuthVerdict } from '@/types'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function getSeverityColor(severity: Severity | null | undefined): string {
  switch (severity) {
    case 'CRITICAL': return 'text-red-500'
    case 'HIGH':     return 'text-orange-500'
    case 'MEDIUM':   return 'text-yellow-500'
    case 'LOW':      return 'text-blue-400'
    case 'BENIGN':   return 'text-green-500'
    default:         return 'text-gray-400'
  }
}

export function getSeverityBgColor(severity: Severity | null | undefined): string {
  switch (severity) {
    case 'CRITICAL': return 'bg-red-600'
    case 'HIGH':     return 'bg-orange-600'
    case 'MEDIUM':   return 'bg-yellow-600'
    case 'LOW':      return 'bg-blue-600'
    case 'BENIGN':   return 'bg-green-600'
    default:         return 'bg-gray-600'
  }
}

export function getSeverityBorderColor(severity: Severity | null | undefined): string {
  switch (severity) {
    case 'CRITICAL': return 'border-red-500'
    case 'HIGH':     return 'border-orange-500'
    case 'MEDIUM':   return 'border-yellow-500'
    case 'LOW':      return 'border-blue-500'
    case 'BENIGN':   return 'border-green-500'
    default:         return 'border-gray-500'
  }
}

export function getVerdictColor(verdict: AuthVerdict | string | null | undefined): string {
  switch (verdict) {
    case 'PASS':     return 'text-green-500'
    case 'WARN':     return 'text-yellow-500'
    case 'FAIL':     return 'text-red-500'
    case 'CRITICAL': return 'text-red-600'
    default:         return 'text-gray-400'
  }
}

export function getAuthResultColor(result: string): string {
  switch (result?.toLowerCase()) {
    case 'pass':     return 'text-green-400'
    case 'fail':     return 'text-red-400'
    case 'softfail': return 'text-yellow-400'
    case 'none':     return 'text-gray-400'
    case 'neutral':  return 'text-blue-400'
    default:         return 'text-gray-400'
  }
}

export function getAuthResultBadgeClass(result: string): string {
  switch (result?.toLowerCase()) {
    case 'pass':     return 'bg-green-900 text-green-300 border-green-700'
    case 'fail':     return 'bg-red-900 text-red-300 border-red-700'
    case 'softfail': return 'bg-yellow-900 text-yellow-300 border-yellow-700'
    case 'none':     return 'bg-gray-800 text-gray-400 border-gray-600'
    default:         return 'bg-gray-800 text-gray-400 border-gray-600'
  }
}

export function formatDate(isoString: string | null | undefined): string {
  if (!isoString) return 'N/A'
  return new Date(isoString).toLocaleString('en-IN', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', timeZoneName: 'short',
  })
}

export function formatRelativeTime(isoString: string | null | undefined): string {
  if (!isoString) return 'N/A'
  const diff = Date.now() - new Date(isoString).getTime()
  const seconds = Math.floor(diff / 1000)
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

export function formatFileSize(bytes: number | null | undefined): string {
  if (!bytes) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  let size = bytes
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit++
  }
  return `${size.toFixed(1)} ${units[unit]}`
}

export function truncateHash(hash: string | null | undefined, chars = 8): string {
  if (!hash) return 'N/A'
  if (hash.length <= chars * 2 + 3) return hash
  return `${hash.slice(0, chars)}...${hash.slice(-chars)}`
}

export function defangUrl(url: string | null | undefined): string {
  if (!url) return ''
  return url
    .replace(/^http/gi, 'hXXp')
    .replace(/\./g, '[.]')
}

export function getIOCTypeIcon(type: IOCType): string {
  switch (type) {
    case 'IP':          return '🌐'
    case 'DOMAIN':      return '🔗'
    case 'URL':         return '↗️'
    case 'EMAIL':       return '📧'
    case 'FILE_HASH':   return '#️⃣'
    case 'ATTACHMENT':  return '📎'
    default:            return '⚠️'
  }
}

export function getIOCTypeColor(type: IOCType): string {
  switch (type) {
    case 'IP':          return 'text-red-400 bg-red-950 border-red-800'
    case 'DOMAIN':      return 'text-orange-400 bg-orange-950 border-orange-800'
    case 'URL':         return 'text-yellow-400 bg-yellow-950 border-yellow-800'
    case 'EMAIL':       return 'text-purple-400 bg-purple-950 border-purple-800'
    case 'FILE_HASH':   return 'text-gray-400 bg-gray-900 border-gray-700'
    case 'ATTACHMENT':  return 'text-pink-400 bg-pink-950 border-pink-800'
    default:            return 'text-gray-400 bg-gray-900 border-gray-700'
  }
}

export function getCytoscapeNodeColor(type: string): string {
  switch (type) {
    case 'case':        return '#3b82f6'
    case 'ip':          return '#ef4444'
    case 'domain':      return '#f97316'
    case 'url':         return '#eab308'
    case 'email':       return '#a855f7'
    case 'file_hash':   return '#6b7280'
    case 'attachment':  return '#ec4899'
    default:            return '#6b7280'
  }
}

export function copyToClipboard(text: string): Promise<void> {
  return navigator.clipboard.writeText(text)
}

export function computeSHA256(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = async (e) => {
      const buffer = e.target?.result as ArrayBuffer
      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
      const hashArray = Array.from(new Uint8Array(hashBuffer))
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
      resolve(hashHex)
    }
    reader.onerror = reject
    reader.readAsArrayBuffer(file)
  })
}
