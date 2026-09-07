import { useState, lazy, Suspense } from 'react'
import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Shield, AlertTriangle, FileText, Globe, Network, Link2,
  Lock, BookOpen, Download, Loader2, Copy, CheckCircle2,
  ExternalLink, ChevronDown, ChevronUp, Info
} from 'lucide-react'
import { casesAPI, analysisAPI, iocsAPI, blockchainAPI, geoAPI, reportsAPI } from '@/lib/api'
import {
  cn, getSeverityColor, getSeverityBgColor, getAuthResultBadgeClass,
  formatDate, truncateHash, defangUrl, getIOCTypeIcon, getIOCTypeColor,
  formatFileSize, copyToClipboard,
} from '@/lib/utils'
import type { Case, AnalysisResult, Severity, IOCType } from '@/types'

// Lazy-load heavy components
const ThreatGraph = lazy(() => import('@/components/investigation/ThreatGraph'))
const GeoIntelMap = lazy(() => import('@/components/investigation/GeoIntelMap'))

const SEVERITY_SCORE_COLOR: Record<string, string> = {
  CRITICAL: 'text-red-500',
  HIGH: 'text-orange-500',
  MEDIUM: 'text-yellow-500',
  LOW: 'text-blue-400',
  BENIGN: 'text-green-500',
}

const TABS = [
  { id: 'overview',   label: 'Overview',         icon: Shield },
  { id: 'ai',        label: 'AI Analysis',        icon: AlertTriangle },
  { id: 'headers',   label: 'Headers & Auth',     icon: FileText },
  { id: 'iocs',      label: 'IOCs',               icon: Link2 },
  { id: 'geo',       label: 'Geo Intelligence',   icon: Globe },
  { id: 'graph',     label: 'Threat Graph',       icon: Network },
  { id: 'custody',   label: 'Chain of Custody',   icon: Lock },
  { id: 'report',    label: 'Report',             icon: BookOpen },
]

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const handleCopy = async () => {
    await copyToClipboard(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button onClick={handleCopy} className="text-muted-foreground hover:text-foreground transition-colors">
      {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-green-500" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  )
}

function OverviewTab({ caseData, analysis }: { caseData: Case | undefined, analysis: AnalysisResult | undefined }) {
  const PIPELINE_STEPS = [
    { key: 'parsing',         label: 'Parse Email',           pct: 10 },
    { key: 'header_forensics',label: 'Header Forensics',      pct: 20 },
    { key: 'auth_validation', label: 'Auth Validation',       pct: 30 },
    { key: 'ioc_extraction',  label: 'IOC Extraction',        pct: 45 },
    { key: 'ai_analysis',     label: 'AI Threat Analysis',    pct: 60 },
    { key: 'geo_intelligence',label: 'Geo Intelligence',      pct: 75 },
    { key: 'correlation',     label: 'Threat Correlation',    pct: 88 },
    { key: 'blockchain',      label: 'Blockchain Log',        pct: 95 },
    { key: 'finalizing',      label: 'Finalizing',            pct: 100 },
  ]

  if (!analysis) {
    const isAnalyzing = caseData?.status === 'ANALYZING'
    const isPending   = caseData?.status === 'PENDING'
    const isFailed    = caseData?.status === 'FAILED'

    return (
      <div className="glass-card space-y-6 py-8 px-6">
        <div className="text-center">
          {isFailed ? (
            <>
              <AlertTriangle className="w-10 h-10 text-red-500 mx-auto mb-3" />
              <p className="text-foreground font-semibold">Analysis Failed</p>
              <p className="text-muted-foreground text-sm mt-1">An error occurred during pipeline execution.</p>
            </>
          ) : (
            <>
              <Loader2 className="w-8 h-8 animate-spin text-primary mx-auto mb-3" />
              <p className="text-foreground font-semibold">
                {isAnalyzing ? 'Analysis In Progress' : 'Waiting to Start Analysis'}
              </p>
              <p className="text-muted-foreground text-sm mt-1">
                {isAnalyzing ? 'Running 9-step forensic pipeline...' : 'Click "Run Analysis" to begin'}
              </p>
            </>
          )}
        </div>

        {(isAnalyzing || isPending) && (
          <div className="max-w-md mx-auto space-y-2">
            {PIPELINE_STEPS.map((step, i) => {
              const done = isAnalyzing && i < 3 // heuristic — show first few as done
              return (
                <div key={step.key} className="flex items-center gap-3">
                  <div className={cn(
                    'w-5 h-5 rounded-full flex items-center justify-center text-xs shrink-0',
                    done
                      ? 'bg-green-600 text-white'
                      : isAnalyzing && i === 3
                      ? 'bg-primary text-white animate-pulse'
                      : 'bg-secondary text-muted-foreground'
                  )}>
                    {done ? '✓' : i + 1}
                  </div>
                  <span className={cn(
                    'text-sm',
                    done ? 'text-green-400' : isAnalyzing && i === 3 ? 'text-primary' : 'text-muted-foreground'
                  )}>
                    {step.label}
                  </span>
                  <span className="text-xs text-muted-foreground ml-auto">{step.pct}%</span>
                </div>
              )
            })}
          </div>
        )}
      </div>
    )
  }


  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Threat gauge (SVG) */}
      <div className="glass-card flex flex-col items-center justify-center py-8">
        <svg viewBox="0 0 200 120" className="w-64 h-40">
          <defs>
            <linearGradient id="gauge-grad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#16a34a" />
              <stop offset="50%" stopColor="#d97706" />
              <stop offset="100%" stopColor="#dc2626" />
            </linearGradient>
          </defs>
          {/* Background arc */}
          <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="hsl(var(--secondary))" strokeWidth="16" strokeLinecap="round" />
          {/* Score arc */}
          <path
            d="M 20 100 A 80 80 0 0 1 180 100"
            fill="none"
            stroke="url(#gauge-grad)"
            strokeWidth="16"
            strokeLinecap="round"
            strokeDasharray={`${(analysis.threat_score / 100) * 251} 251`}
          />
          {/* Score text */}
          <text x="100" y="90" textAnchor="middle" className="fill-foreground" fontSize="32" fontWeight="bold" fill="white">
            {analysis.threat_score}
          </text>
          <text x="100" y="112" textAnchor="middle" fontSize="11" fill="hsl(var(--muted-foreground))">
            Threat Score
          </text>
        </svg>
        <span className={cn('text-2xl font-bold mt-2', SEVERITY_SCORE_COLOR[analysis.severity])}>
          {analysis.severity}
        </span>
        <div className="flex gap-3 mt-4 text-xs text-muted-foreground">
          <span>Rules: <strong className="text-foreground">{analysis.rule_score}</strong></span>
          <span>ML: <strong className="text-foreground">{analysis.ml_score}</strong></span>
          <span>AI: <strong className="text-foreground">{analysis.gemini_score}</strong></span>
        </div>
      </div>

      {/* Quick info */}
      <div className="space-y-4">
        {/* Categories */}
        <div className="glass-card">
          <p className="text-xs text-muted-foreground mb-2">Detected Threat Categories</p>
          <div className="flex flex-wrap gap-2">
            {analysis.threat_categories.map((cat: string) => (
              <span key={cat} className="text-xs px-2 py-1 rounded bg-primary/20 text-primary border border-primary/30 font-medium capitalize">
                {cat.replace(/_/g, ' ')}
              </span>
            ))}
          </div>
        </div>

        {/* Auth quick view */}
        <div className="glass-card">
          <p className="text-xs text-muted-foreground mb-2">Email Authentication</p>
          {caseData?.auth_result ? (
            <div className="space-y-1.5">
              {[
                ['SPF', caseData.auth_result?.spf_result],
                ['DKIM', caseData.auth_result?.dkim_result],
                ['DMARC', caseData.auth_result?.dmarc_result],
              ].map(([proto, result]) => (
                <div key={proto as string} className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground font-mono">{proto}</span>
                  <span className={cn('text-xs px-2 py-0.5 rounded border font-medium uppercase', getAuthResultBadgeClass(result as string))}>
                    {result ?? 'none'}
                  </span>
                </div>
              ))}
            </div>
          ) : <p className="text-sm text-muted-foreground">Not yet available</p>}
        </div>

        {/* Recommended actions */}
        <div className="glass-card">
          <p className="text-xs text-muted-foreground mb-2">Recommended Actions</p>
          <ol className="space-y-1.5">
            {analysis.recommended_actions.slice(0, 4).map((action: string, i: number) => (
              <li key={i} className="flex gap-2 text-sm text-foreground">
                <span className="text-primary font-bold shrink-0">{i + 1}.</span>
                <span>{action}</span>
              </li>
            ))}
          </ol>
        </div>
      </div>

      {/* Explanation */}
      <div className="glass-card lg:col-span-2">
        <p className="text-xs text-muted-foreground mb-2 flex items-center gap-1">
          <Info className="w-3 h-3" /> AI Forensic Assessment
        </p>
        <p className="text-sm text-foreground leading-relaxed">{analysis.ai_explanation}</p>
      </div>
    </div>
  )
}

function AIAnalysisTab({ analysis }: { analysis: AnalysisResult | undefined }) {
  if (!analysis) return <div className="text-muted-foreground text-center py-16">Analysis not available</div>

  const shapEntries = Object.entries(analysis.shap_features ?? {})
    .sort(([, a], [, b]) => (b as number) - (a as number))
    .slice(0, 10) as [string, number][]

  const maxShap = shapEntries[0]?.[1] ?? 1

  return (
    <div className="space-y-6">
      {/* Score breakdown */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Rule Engine', score: analysis.rule_score, color: 'bg-orange-600' },
          { label: 'ML Classifier', score: analysis.ml_score, color: 'bg-blue-600' },
          { label: 'Gemini AI', score: analysis.gemini_score, color: 'bg-purple-600' },
        ].map(({ label, score, color }) => (
          <div key={label} className="glass-card text-center">
            <p className="text-xs text-muted-foreground mb-2">{label}</p>
            <p className="text-3xl font-bold text-foreground">{score}<span className="text-sm text-muted-foreground">/100</span></p>
            <div className="mt-2 h-1.5 bg-secondary rounded-full">
              <div className={cn('h-full rounded-full', color)} style={{ width: `${score}%` }} />
            </div>
          </div>
        ))}
      </div>

      {/* Full explanation */}
      <div className="glass-card">
        <h3 className="text-sm font-semibold text-foreground mb-3">AI Forensic Narrative</h3>
        <p className="text-sm text-foreground leading-relaxed">{analysis.ai_explanation}</p>
      </div>

      {/* Social engineering patterns */}
      {analysis.social_engineering_patterns?.length > 0 && (
        <div className="glass-card">
          <h3 className="text-sm font-semibold text-foreground mb-3">Social Engineering Patterns</h3>
          <ul className="space-y-1.5">
            {analysis.social_engineering_patterns.map((p: string, i: number) => (
              <li key={i} className="flex gap-2 text-sm">
                <span className="text-orange-500">⚠</span>
                <span className="text-foreground">{p}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Urgency indicators */}
      {analysis.urgency_phrases?.length > 0 && (
        <div className="glass-card">
          <h3 className="text-sm font-semibold text-foreground mb-3">Urgency Indicators Detected</h3>
          <div className="flex flex-wrap gap-2">
            {analysis.urgency_phrases.map((phrase: string, i: number) => (
              <span key={i} className="px-2 py-1 rounded bg-orange-950 border border-orange-800 text-orange-300 text-xs font-mono">
                "{phrase}"
              </span>
            ))}
          </div>
        </div>
      )}

      {/* BEC indicators */}
      {analysis.bec_indicators?.length > 0 && (
        <div className="glass-card border border-red-700/50">
          <h3 className="text-sm font-semibold text-red-400 mb-3">Business Email Compromise Indicators</h3>
          <ul className="space-y-1.5">
            {analysis.bec_indicators.map((ind: string, i: number) => (
              <li key={i} className="text-sm text-foreground flex gap-2">
                <span className="text-red-500">🔴</span>{ind}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* SHAP features */}
      {shapEntries.length > 0 && (
        <div className="glass-card">
          <h3 className="text-sm font-semibold text-foreground mb-3">Top ML Features (SHAP)</h3>
          <div className="space-y-2">
            {shapEntries.map(([feature, importance]) => (
              <div key={feature} className="flex items-center gap-3">
                <span className="text-xs text-muted-foreground font-mono w-40 truncate shrink-0">{feature}</span>
                <div className="flex-1 h-2 bg-secondary rounded-full overflow-hidden">
                  <div
                    className="h-full bg-primary rounded-full"
                    style={{ width: `${(importance / maxShap) * 100}%` }}
                  />
                </div>
                <span className="text-xs text-muted-foreground w-14 text-right">
                  {(importance * 100).toFixed(1)}%
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function HeadersTab({ caseData }: { caseData: Case | undefined }) {
  const [showRaw, setShowRaw] = useState(false)
  const headers = caseData?.email_headers
  const auth = caseData?.auth_result
  const relayHops = caseData?.relay_hops ?? []

  return (
    <div className="space-y-6">
      {/* Auth results */}
      {auth && (
        <div className="glass-card">
          <h3 className="text-sm font-semibold text-foreground mb-4">Email Authentication Results</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[
              { proto: 'SPF', result: auth.spf_result, domain: auth.spf_domain, note: auth.spf_explanation },
              { proto: 'DKIM', result: auth.dkim_result, domain: auth.dkim_domain, note: auth.dkim_selector ? `Selector: ${auth.dkim_selector}` : '' },
              { proto: 'DMARC', result: auth.dmarc_result, domain: (caseData as { email_headers?: { from_domain: string } })?.email_headers?.from_domain, note: auth.dmarc_policy ? `Policy: ${auth.dmarc_policy}` : '' },
            ].map(({ proto, result, domain, note }) => (
              <div key={proto} className={cn(
                'p-4 rounded-xl border',
                getAuthResultBadgeClass(result)
              )}>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-sm font-mono">{proto}</span>
                  <span className={cn('text-xs font-bold uppercase px-2 py-0.5 rounded', getAuthResultBadgeClass(result))}>
                    {result ?? 'NONE'}
                  </span>
                </div>
                {domain && <p className="text-xs text-muted-foreground truncate">{domain}</p>}
                {note && <p className="text-xs text-muted-foreground mt-1">{note}</p>}
              </div>
            ))}
          </div>
          {auth.spoofing_risk && (
            <div className={cn(
              'mt-4 p-3 rounded-lg text-sm flex items-center gap-2',
              auth.overall_verdict === 'CRITICAL' ? 'bg-red-950/50 text-red-400 border border-red-800' :
              auth.overall_verdict === 'FAIL' ? 'bg-orange-950/50 text-orange-400 border border-orange-800' :
              'bg-yellow-950/50 text-yellow-400 border border-yellow-800'
            )}>
              <AlertTriangle className="w-4 h-4 shrink-0" />
              Spoofing Risk: <strong>{auth.spoofing_risk}</strong>
            </div>
          )}
        </div>
      )}

      {/* Key headers */}
      {headers && (
        <div className="glass-card">
          <h3 className="text-sm font-semibold text-foreground mb-4">Key Email Headers</h3>
          <div className="space-y-2">
            {[
              { label: 'From', value: `${headers.from_name} <${headers.from_addr}>` },
              { label: 'Reply-To', value: headers.reply_to },
              { label: 'Return-Path', value: headers.return_path },
              { label: 'Message-ID', value: headers.message_id },
              { label: 'Date', value: formatDate(headers.date_sent) },
              { label: 'X-Originating-IP', value: headers.x_originating_ip ?? '—' },
              { label: 'X-Mailer', value: headers.x_mailer ?? '—' },
            ].map(({ label, value }) => (
              <div key={label} className="flex gap-4 py-2 border-b border-border/50 last:border-0">
                <span className="text-xs text-muted-foreground font-mono w-32 shrink-0 pt-0.5">{label}</span>
                <span className="text-sm text-foreground break-all flex-1">{value || '—'}</span>
                {value && value !== '—' && <CopyButton text={value} />}
              </div>
            ))}
          </div>

          {/* Spoofing indicators */}
          {headers.spoofing_indicators?.length > 0 && (
            <div className="mt-4 p-3 rounded-lg bg-red-950/30 border border-red-800/50">
              <p className="text-xs font-semibold text-red-400 mb-2">Spoofing Indicators Detected</p>
              <ul className="space-y-1">
                {headers.spoofing_indicators.map((ind: string, i: number) => (
                  <li key={i} className="text-xs text-red-300 flex gap-2">
                    <span>⚠</span>{ind}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {headers.rfc_violations?.length > 0 && (
            <div className="mt-3 p-3 rounded-lg bg-orange-950/30 border border-orange-800/50">
              <p className="text-xs font-semibold text-orange-400 mb-2">RFC Violations</p>
              <ul className="space-y-1">
                {headers.rfc_violations.map((v: string, i: number) => (
                  <li key={i} className="text-xs text-orange-300 flex gap-2"><span>●</span>{v}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Relay path */}
      {relayHops.length > 0 && (
        <div className="glass-card">
          <h3 className="text-sm font-semibold text-foreground mb-4">SMTP Relay Path</h3>
          <div className="space-y-3">
            {[...relayHops].reverse().map((hop, i) => (
              <div key={hop.hop_index} className="relative">
                {i < relayHops.length - 1 && (
                  <div className="absolute left-3 top-10 w-0.5 h-6 bg-border" />
                )}
                <div className={cn(
                  'flex items-start gap-3 p-3 rounded-lg border',
                  hop.is_suspicious
                    ? 'bg-red-950/20 border-red-800/50'
                    : i === 0
                    ? 'bg-primary/10 border-primary/30'
                    : 'bg-secondary/50 border-border'
                )}>
                  <div className={cn(
                    'w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold shrink-0',
                    i === 0 ? 'bg-primary text-white' : 'bg-secondary text-muted-foreground'
                  )}>
                    {hop.hop_index + 1}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-mono text-foreground truncate">
                        {hop.by_server || 'Unknown server'}
                      </span>
                      {hop.ip_address && (
                        <span className={cn(
                          'text-xs px-1.5 py-0.5 rounded font-mono',
                          hop.is_public_ip
                            ? 'bg-orange-950 text-orange-300 border border-orange-800'
                            : 'bg-secondary text-muted-foreground'
                        )}>
                          {hop.ip_address}
                        </span>
                      )}
                      {hop.protocol && (
                        <span className="text-xs text-muted-foreground">{hop.protocol}</span>
                      )}
                    </div>
                    {hop.from_server && (
                      <p className="text-xs text-muted-foreground mt-0.5">From: {hop.from_server}</p>
                    )}
                    {hop.timestamp && (
                      <p className="text-xs text-muted-foreground">{formatDate(hop.timestamp)}</p>
                    )}
                  </div>
                  {i === 0 && (
                    <span className="text-xs text-primary font-medium shrink-0">Origin</span>
                  )}
                  {hop.is_suspicious && (
                    <span className="text-xs text-red-400 font-medium shrink-0">⚠ Suspicious</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Raw headers toggle */}
      {headers?.raw_headers && (
        <div className="glass-card">
          <button
            onClick={() => setShowRaw(!showRaw)}
            className="flex items-center justify-between w-full text-sm text-foreground"
          >
            <span className="font-semibold">Raw Headers</span>
            {showRaw ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
          {showRaw && (
            <div className="mt-4 max-h-80 overflow-auto">
              <div className="space-y-1">
                {Object.entries(headers.raw_headers).map(([k, v]) => (
                  <div key={k} className="flex gap-2 text-xs py-1 border-b border-border/30">
                    <span className="text-muted-foreground font-mono w-40 shrink-0">{k}:</span>
                    <span className="text-foreground break-all">{v as string}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function IOCsTab({ caseId }: { caseId: string }) {
  const [typeFilter, setTypeFilter] = useState<IOCType | ''>('')
  const [severityFilter, setSeverityFilter] = useState<Severity | ''>('')
  const { data: iocs = [], isLoading } = useQuery({
    queryKey: ['iocs', caseId],
    queryFn: () => iocsAPI.getForCase(caseId),
  })

  const filtered = iocs.filter(ioc =>
    (!typeFilter || ioc.ioc_type === typeFilter) &&
    (!severityFilter || ioc.severity === severityFilter)
  )

  const IOC_TYPES: IOCType[] = ['IP', 'DOMAIN', 'URL', 'EMAIL', 'FILE_HASH', 'ATTACHMENT']
  const SEVS: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'BENIGN']

  if (isLoading) return <div className="flex items-center justify-center h-40"><Loader2 className="w-6 h-6 animate-spin text-primary" /></div>

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 flex-wrap">
        <span className="text-sm text-muted-foreground">{iocs.length} IOCs total · {filtered.length} shown</span>
        <select
          className="px-3 py-1.5 rounded-lg bg-secondary border border-border text-sm text-foreground focus:outline-none"
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value as IOCType | '')}
        >
          <option value="">All Types</option>
          {IOC_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <select
          className="px-3 py-1.5 rounded-lg bg-secondary border border-border text-sm text-foreground focus:outline-none"
          value={severityFilter}
          onChange={e => setSeverityFilter(e.target.value as Severity | '')}
        >
          <option value="">All Severities</option>
          {SEVS.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <button
          onClick={() => iocsAPI.exportCSV(caseId)}
          className="ml-auto flex items-center gap-1 px-3 py-1.5 rounded-lg bg-secondary border border-border text-sm text-foreground hover:bg-secondary/80"
        >
          <Download className="w-4 h-4" /> Export CSV
        </button>
      </div>

      {filtered.length === 0 ? (
        <div className="text-center py-12 text-muted-foreground">No IOCs match the current filter</div>
      ) : (
        <div className="glass-card p-0 overflow-hidden">
          <table className="w-full">
            <thead className="border-b border-border">
              <tr className="text-xs text-muted-foreground">
                <th className="text-left px-4 py-3 font-medium">Type</th>
                <th className="text-left px-4 py-3 font-medium">Value</th>
                <th className="text-left px-4 py-3 font-medium">Severity</th>
                <th className="text-left px-4 py-3 font-medium">Context</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map(ioc => (
                <tr key={ioc.id} className="hover:bg-secondary/30 transition-colors">
                  <td className="px-4 py-3">
                    <span className={cn('text-xs px-2 py-1 rounded border font-medium', getIOCTypeColor(ioc.ioc_type))}>
                      {getIOCTypeIcon(ioc.ioc_type)} {ioc.ioc_type}
                    </span>
                  </td>
                  <td className="px-4 py-3 max-w-xs">
                    <span className="text-xs font-mono text-foreground break-all">
                      {ioc.defanged_value || defangUrl(ioc.ioc_value)}
                    </span>
                    {ioc.is_lookalike && (
                      <span className="ml-2 text-xs text-orange-400 bg-orange-950 border border-orange-800 px-1.5 rounded">
                        Lookalike: {ioc.lookalike_target}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className={cn('text-xs font-bold px-2 py-0.5 rounded text-white', getSeverityBgColor(ioc.severity))}>
                      {ioc.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground max-w-xs truncate">
                    {ioc.context ?? '—'}
                  </td>
                  <td className="px-4 py-3">
                    <CopyButton text={ioc.ioc_value} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function GeoTab({ caseId }: { caseId: string }) {
  const { data: geoData = [], isLoading } = useQuery({
    queryKey: ['geo', caseId],
    queryFn: () => geoAPI.getForCase(caseId),
  })

  if (isLoading) return <div className="flex items-center justify-center h-40"><Loader2 className="w-6 h-6 animate-spin text-primary" /></div>
  if (!geoData.length) return <div className="text-center py-16 text-muted-foreground">No geolocation data available yet</div>

  return (
    <div className="space-y-4">
      <Suspense fallback={<div className="h-64 bg-secondary rounded-xl animate-pulse" />}>
        <GeoIntelMap geoData={geoData} />
      </Suspense>

      {geoData.map(geo => (
        <div key={geo.id} className="glass-card">
          <div className="flex items-start justify-between mb-4">
            <div>
              <p className="font-mono text-primary font-bold">{geo.ip_address}</p>
              <p className="text-muted-foreground text-sm">{geo.enrichment_source}</p>
            </div>
            <div className="flex gap-2">
              {geo.is_vpn   && <span className="text-xs px-2 py-1 rounded bg-orange-950 text-orange-400 border border-orange-800">VPN</span>}
              {geo.is_tor   && <span className="text-xs px-2 py-1 rounded bg-red-950 text-red-400 border border-red-800">TOR</span>}
              {geo.is_hosting && <span className="text-xs px-2 py-1 rounded bg-blue-950 text-blue-400 border border-blue-800">HOSTING</span>}
              {geo.is_proxy && <span className="text-xs px-2 py-1 rounded bg-yellow-950 text-yellow-400 border border-yellow-800">PROXY</span>}
            </div>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-sm">
            {[
              ['Country', `${geo.country_code ? `${geo.country_code} ` : ''}${geo.country ?? 'Unknown'}`],
              ['City / Region', [geo.city, geo.region].filter(Boolean).join(', ') || 'Unknown'],
              ['ISP / Org', geo.isp ?? geo.org ?? 'Unknown'],
              ['ASN', geo.asn ?? 'Unknown'],
              ['Hostname', geo.hostname ?? 'Unknown'],
              ['PTR Record', geo.ptr_record ?? 'None'],
            ].map(([label, value]) => (
              <div key={label as string}>
                <p className="text-xs text-muted-foreground">{label}</p>
                <p className="text-foreground truncate">{value}</p>
              </div>
            ))}
          </div>

          {/* Disclaimer */}
          <div className="mt-4 p-3 rounded-lg bg-yellow-950/30 border border-yellow-800/50 flex items-start gap-2">
            <Info className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" />
            <p className="text-xs text-yellow-300">
              <strong>Important:</strong> Geographic data reflects the location of sending infrastructure (mail server, relay, or VPN exit node), not the physical location or identity of the threat actor. This information supports investigation but does not constitute attribution.
            </p>
          </div>
        </div>
      ))}
    </div>
  )
}

function CustodyTab({ caseId, caseData }: { caseId: string, caseData: Case | undefined }) {
  const { data: ledger = [], isLoading } = useQuery({
    queryKey: ['blockchain', caseId],
    queryFn: () => blockchainAPI.getForCase(caseId),
  })
  const [verifyResult, setVerifyResult] = useState<{ is_valid: boolean; tamper_detected_at: number | null; verified_blocks: number } | null>(null)
  const [verifying, setVerifying] = useState(false)

  const handleVerify = async () => {
    setVerifying(true)
    try {
      const result = await blockchainAPI.verify(caseId)
      setVerifyResult(result)
    } finally {
      setVerifying(false)
    }
  }

  const ACTION_ICONS: Record<string, string> = {
    GENESIS: '🏁', EVIDENCE_SUBMITTED: '🔒', ANALYSIS_STARTED: '▶️',
    ANALYSIS_COMPLETED: '✅', REPORT_GENERATED: '📄',
    INTEGRITY_VERIFIED: '🔍', ANALYST_ACCESSED: '👁️', CASE_DELETED: '🗑️',
  }

  const cd = caseData

  return (
    <div className="space-y-4">
      {/* Evidence certificate */}
      <div className="glass-card border border-primary/30">
        <div className="flex items-center gap-3 mb-4">
          <Lock className="w-5 h-5 text-primary" />
          <h3 className="text-sm font-semibold text-foreground">Digital Evidence Certificate</h3>
        </div>
        <div className="space-y-3">
          <div>
            <p className="text-xs text-muted-foreground mb-1">Case ID</p>
            <div className="flex items-center gap-2">
              <span className="hash-display">{cd?.case_id}</span>
              <CopyButton text={cd?.case_id ?? ''} />
            </div>
          </div>
          <div>
            <p className="text-xs text-muted-foreground mb-1">SHA-256 Evidence Hash</p>
            <div className="flex items-center gap-2">
              <span className="hash-display">{cd?.evidence_hash}</span>
              <CopyButton text={cd?.evidence_hash ?? ''} />
            </div>
          </div>
          <div>
            <p className="text-xs text-muted-foreground mb-1">SHA-3-256 Hash</p>
            <div className="flex items-center gap-2">
              <span className="hash-display">{cd?.evidence_hash3}</span>
              <CopyButton text={cd?.evidence_hash3 ?? ''} />
            </div>
          </div>
          <div className="flex gap-4 text-sm">
            <div>
              <p className="text-xs text-muted-foreground">File Size</p>
              <p className="text-foreground">{formatFileSize(cd?.file_size_bytes)}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Submitted</p>
              <p className="text-foreground">{formatDate(cd?.created_at)}</p>
            </div>
          </div>
        </div>

        {/* Verify button */}
        <div className="mt-4 flex items-center gap-3">
          <button
            onClick={handleVerify}
            disabled={verifying}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
          >
            {verifying ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />}
            Verify Integrity
          </button>

          {verifyResult && (
            <div className={cn(
              'flex items-center gap-2 px-3 py-2 rounded-lg border text-sm',
              verifyResult.is_valid
                ? 'bg-green-950/50 border-green-800 text-green-400'
                : 'bg-red-950/50 border-red-800 text-red-400'
            )}>
              {verifyResult.is_valid
                ? <><CheckCircle2 className="w-4 h-4" /> CHAIN INTACT · {verifyResult.verified_blocks} blocks verified</>
                : <><AlertTriangle className="w-4 h-4" /> TAMPER DETECTED at block {verifyResult.tamper_detected_at}</>
              }
            </div>
          )}
        </div>
      </div>

      {/* Blockchain timeline */}
      <div className="glass-card">
        <h3 className="text-sm font-semibold text-foreground mb-4">Chain of Custody Timeline</h3>
        {isLoading ? (
          <div className="flex items-center justify-center h-20"><Loader2 className="w-5 h-5 animate-spin text-primary" /></div>
        ) : (
          <div className="space-y-3">
            {ledger.map((entry, i) => (
              <div key={entry.id} className="flex gap-3">
                <div className="flex flex-col items-center">
                  <div className="w-8 h-8 rounded-full bg-primary/20 border border-primary/50 flex items-center justify-center text-sm shrink-0">
                    {ACTION_ICONS[entry.action] ?? '•'}
                  </div>
                  {i < ledger.length - 1 && <div className="w-0.5 h-6 bg-border mt-1" />}
                </div>
                <div className="flex-1 pb-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-medium text-foreground">{entry.action.replace(/_/g, ' ')}</span>
                    <span className="text-xs text-muted-foreground shrink-0">{formatDate(entry.timestamp)}</span>
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-xs text-muted-foreground">Block #{entry.block_index}</span>
                    <span className="text-xs text-muted-foreground">·</span>
                    <span className="text-xs text-muted-foreground">Actor: {entry.actor}</span>
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-xs text-muted-foreground font-mono">{truncateHash(entry.block_hash)}</span>
                    <CopyButton text={entry.block_hash} />
                  </div>
                  {entry.polygon_tx_hash && (
                    <a
                      href={`https://amoy.polygonscan.com/tx/${entry.polygon_tx_hash}`}
                      target="_blank"
                      rel="noreferrer"
                      className="flex items-center gap-1 text-xs text-primary hover:underline mt-1"
                    >
                      <ExternalLink className="w-3 h-3" /> View on Polygonscan
                    </a>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function ReportTab({ caseId }: { caseId: string }) {
  const [downloading, setDownloading] = useState(false)

  const handleDownload = async () => {
    setDownloading(true)
    try {
      await reportsAPI.downloadPDF(caseId)
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="glass-card">
        <div className="flex items-center gap-3 mb-4">
          <BookOpen className="w-5 h-5 text-primary" />
          <h3 className="text-sm font-semibold text-foreground">Forensic Report Generation</h3>
        </div>
        <p className="text-sm text-muted-foreground mb-6">
          Generate a comprehensive PDF forensic report containing all analysis findings, evidence integrity certificate, and chain of custody record.
        </p>

        <div className="space-y-2 mb-6">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Report Sections</p>
          {[
            'Executive Summary with Threat Score',
            'Email Metadata and Key Headers',
            'AI Threat Analysis (Gemini + ML Findings)',
            'SMTP Relay Path Visualization',
            'SPF / DKIM / DMARC Authentication Results',
            'Indicators of Compromise (IOC Table)',
            'Infrastructure & Geolocation Intelligence',
            'Threat Correlation & Campaign Attribution',
            'Attribution Confidence Assessment',
            'Digital Evidence Integrity Certificate',
            'Blockchain Chain of Custody Record',
            'Recommended Security Actions',
            'Legal Disclaimer',
          ].map(section => (
            <div key={section} className="flex items-center gap-2 text-sm">
              <CheckCircle2 className="w-4 h-4 text-green-500 shrink-0" />
              <span className="text-foreground">{section}</span>
            </div>
          ))}
        </div>

        <div className="flex gap-3">
          <button
            onClick={handleDownload}
            disabled={downloading}
            className="flex items-center gap-2 px-6 py-2.5 bg-primary text-white rounded-lg font-medium hover:bg-primary/90 disabled:opacity-50"
          >
            {downloading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
            Download PDF Report
          </button>
          <a
            href={reportsAPI.getPreviewURL(caseId)}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-2 px-4 py-2.5 bg-secondary border border-border rounded-lg text-sm text-foreground hover:bg-secondary/80"
          >
            <ExternalLink className="w-4 h-4" /> Preview in Browser
          </a>
        </div>
      </div>
    </div>
  )
}

export default function CaseDetailPage() {
  const { caseId } = useParams<{ caseId: string }>()
  const [activeTab, setActiveTab] = useState('overview')
  const [analyzing, setAnalyzing] = useState(false)

  const { data: caseData, isLoading: caseLoading, refetch: refetchCase } = useQuery<Case>({
    queryKey: ['case', caseId],
    queryFn: () => casesAPI.get(caseId!),
    enabled: !!caseId,
    refetchInterval: (data) =>
      data?.status === 'ANALYZING' || data?.status === 'PENDING' ? 3000 : false,
  })

  const { data: analysis } = useQuery<AnalysisResult>({
    queryKey: ['analysis', caseId],
    queryFn: () => analysisAPI.get(caseId!),
    enabled: !!caseId && caseData?.status === 'COMPLETED',
  })

  const handleRunAnalysis = async () => {
    if (!caseData) return
    setAnalyzing(true)
    try {
      await analysisAPI.trigger(caseData.case_id)
      refetchCase()
    } finally {
      setAnalyzing(false)
    }
  }

  if (caseLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    )
  }

  if (!caseData) {
    return (
      <div className="text-center py-16">
        <AlertTriangle className="w-10 h-10 text-orange-500 mx-auto mb-3" />
        <p className="text-foreground font-medium">Case not found</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Case header */}
      <div className="glass-card">
        <div className="flex items-start justify-between flex-wrap gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <span className="font-mono text-primary text-xl font-bold">{caseData.case_id}</span>
              <span className={cn(
                'text-xs font-bold px-2 py-0.5 rounded border',
                caseData.status === 'COMPLETED' ? 'bg-green-950 text-green-400 border-green-800' :
                caseData.status === 'ANALYZING' ? 'bg-blue-950 text-blue-400 border-blue-800 animate-pulse' :
                caseData.status === 'FAILED' ? 'bg-red-950 text-red-400 border-red-800' :
                'bg-gray-900 text-gray-400 border-gray-700'
              )}>
                {caseData.status}
              </span>
              {caseData.campaign && (
                <span className="text-xs px-2 py-0.5 rounded bg-purple-950 text-purple-400 border border-purple-800">
                  Campaign: {caseData.campaign.campaign_id}
                </span>
              )}
            </div>
            <p className="text-muted-foreground text-sm">
              {caseData.email_headers?.subject || 'Awaiting analysis'}
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              Submitted {formatDate(caseData.created_at)} · {formatFileSize(caseData.file_size_bytes)}
            </p>
          </div>

          {caseData.threat_score !== null && (
            <div className="text-right">
              <p className={cn('text-5xl font-bold', getSeverityColor(caseData.severity))}>
                {caseData.threat_score}
              </p>
              <p className="text-sm text-muted-foreground">/ 100</p>
              <p className={cn('text-sm font-bold', getSeverityColor(caseData.severity))}>
                {caseData.severity}
              </p>
            </div>
          )}
        </div>

        {/* Evidence hash quick view */}
        <div className="mt-3 pt-3 border-t border-border flex items-center gap-3 flex-wrap">
          <Lock className="w-4 h-4 text-muted-foreground" />
          <span className="text-xs text-muted-foreground">SHA-256:</span>
          <span className="hash-display flex-1 min-w-0">{caseData.evidence_hash}</span>
          <CopyButton text={caseData.evidence_hash} />
          {(caseData.status === 'PENDING' || caseData.status === 'FAILED') && (
            <button
              onClick={handleRunAnalysis}
              disabled={analyzing}
              className="flex items-center gap-2 px-3 py-1.5 bg-primary text-white rounded-lg text-xs font-medium hover:bg-primary/90 disabled:opacity-50 ml-auto"
            >
              {analyzing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Shield className="w-3.5 h-3.5" />}
              {analyzing ? 'Starting...' : 'Run Analysis'}
            </button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div>
        <div className="flex overflow-x-auto border-b border-border gap-1 pb-0">
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={cn(
                'flex items-center gap-1.5 px-3 py-2.5 text-sm font-medium whitespace-nowrap border-b-2 transition-colors',
                activeTab === tab.id
                  ? 'border-primary text-primary'
                  : 'border-transparent text-muted-foreground hover:text-foreground'
              )}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>

        <div className="mt-6">
          {activeTab === 'overview' && <OverviewTab caseData={caseData} analysis={analysis} />}
          {activeTab === 'ai' && <AIAnalysisTab analysis={analysis} />}
          {activeTab === 'headers' && <HeadersTab caseData={caseData} />}
          {activeTab === 'iocs' && <IOCsTab caseId={caseData.case_id} />}
          {activeTab === 'geo' && <GeoTab caseId={caseData.case_id} />}
          {activeTab === 'graph' && (
            <Suspense fallback={<div className="h-96 bg-secondary rounded-xl animate-pulse" />}>
              <ThreatGraph caseId={caseData.case_id} />
            </Suspense>
          )}
          {activeTab === 'custody' && <CustodyTab caseId={caseData.case_id} caseData={caseData} />}
          {activeTab === 'report' && <ReportTab caseId={caseData.case_id} />}
        </div>
      </div>
    </div>
  )
}
