import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer
} from 'recharts'
import {
  Shield, AlertTriangle, GitFork, Search, CheckCircle2,
  XCircle, ArrowRight, Loader2, Activity, Crosshair, Layers
} from 'lucide-react'
import { statsAPI } from '@/lib/api'
import { cn, formatRelativeTime, getSeverityBgColor } from '@/lib/utils'
import type { Severity, RecentCaseSummary } from '@/types'

// ── Threat Environment Gauge ─────────────────────────────────────────────────

function ThreatGauge({
  score, totalCases, highThreats, totalIocs
}: {
  score: number
  totalCases: number
  highThreats: number
  totalIocs: number
}) {
  const clampedScore = Math.min(100, Math.max(0, Math.round(score)))
  const arcLength = 251.33 // Math.PI * 80

  const gaugeColor =
    clampedScore >= 80 ? '#dc2626' :
    clampedScore >= 60 ? '#ea580c' :
    clampedScore >= 35 ? '#d97706' : '#16a34a'

  const label =
    clampedScore >= 80 ? 'CRITICAL RISK' :
    clampedScore >= 60 ? 'HIGH RISK' :
    clampedScore >= 35 ? 'MODERATE RISK' : 'LOW RISK'

  const highPct = totalCases > 0 ? Math.round((highThreats / totalCases) * 100) : 0
  const iocDensity = totalCases > 0 ? (totalIocs / totalCases).toFixed(1) : '0'
  const dashOffset = arcLength * (1 - clampedScore / 100)

  return (
    <div className="flex flex-col items-center justify-between flex-1 gap-3">
      {/* Semi-circle Gauge */}
      <div className="w-full max-w-[240px] flex justify-center">
        <svg viewBox="0 0 240 135" className="w-full h-auto overflow-visible">
          <defs>
            <filter id="gauge-glow" x="-20%" y="-20%" width="140%" height="140%">
              <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor={gaugeColor} floodOpacity="0.5" />
            </filter>
          </defs>

          {/* Background Track Arc (Radius 80, centered at 120, 100) */}
          <path
            d="M 40 100 A 80 80 0 0 1 200 100"
            fill="none"
            stroke="hsl(var(--secondary))"
            strokeWidth="14"
            strokeLinecap="round"
          />

          {/* Subtle colored backdrop zones */}
          <path
            d="M 40 100 A 80 80 0 0 1 200 100"
            fill="none"
            stroke={gaugeColor}
            strokeWidth="14"
            strokeLinecap="round"
            opacity="0.15"
          />

          {/* Active Progress Arc */}
          <path
            d="M 40 100 A 80 80 0 0 1 200 100"
            fill="none"
            stroke={gaugeColor}
            strokeWidth="14"
            strokeLinecap="round"
            strokeDasharray={arcLength}
            strokeDashoffset={dashOffset}
            filter="url(#gauge-glow)"
            className="transition-all duration-1000 ease-out"
          />

          {/* Large Center Score */}
          <text
            x="120"
            y="78"
            textAnchor="middle"
            className="font-bold font-mono tracking-tight"
            style={{ fontSize: 34, fill: gaugeColor, fontWeight: 800 }}
          >
            {clampedScore}
          </text>

          {/* Status Label */}
          <text
            x="120"
            y="98"
            textAnchor="middle"
            className="font-semibold"
            style={{ fontSize: 11, fill: 'hsl(var(--foreground))', letterSpacing: '0.08em' }}
          >
            {label}
          </text>

          {/* Subtitle */}
          <text
            x="120"
            y="114"
            textAnchor="middle"
            style={{ fontSize: 9, fill: 'hsl(var(--muted-foreground))', letterSpacing: '0.05em' }}
          >
            AVG THREAT SCORE
          </text>

          {/* Scale Anchors */}
          <text x="36" y="118" style={{ fontSize: 9, fill: '#16a34a', fontWeight: 600 }}>0</text>
          <text x="204" y="118" textAnchor="end" style={{ fontSize: 9, fill: '#dc2626', fontWeight: 600 }}>100</text>
        </svg>
      </div>

      {/* Supporting Metrics Bar */}
      <div className="grid grid-cols-3 gap-2.5 w-full text-center mt-1">
        <div className="bg-secondary/60 border border-border/40 rounded-lg py-2 px-1">
          <div className="flex items-center justify-center gap-1 mb-0.5">
            <Activity className="w-3.5 h-3.5 text-primary" />
          </div>
          <p className="text-base font-bold font-mono text-foreground">{clampedScore}</p>
          <p className="text-[10px] text-muted-foreground">Avg Score</p>
        </div>
        <div className="bg-secondary/60 border border-border/40 rounded-lg py-2 px-1">
          <div className="flex items-center justify-center gap-1 mb-0.5">
            <Crosshair className="w-3.5 h-3.5 text-orange-500" />
          </div>
          <p className="text-base font-bold font-mono text-orange-400">{highPct}%</p>
          <p className="text-[10px] text-muted-foreground">High/Critical</p>
        </div>
        <div className="bg-secondary/60 border border-border/40 rounded-lg py-2 px-1">
          <div className="flex items-center justify-center gap-1 mb-0.5">
            <Layers className="w-3.5 h-3.5 text-yellow-500" />
          </div>
          <p className="text-base font-bold font-mono text-yellow-400">{iocDensity}</p>
          <p className="text-[10px] text-muted-foreground">IOCs/Case</p>
        </div>
      </div>
    </div>
  )
}

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'BENIGN']

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#d97706',
  LOW: '#2563eb',
  BENIGN: '#16a34a',
}

function MetricCard({
  icon: Icon, label, value, color = 'text-foreground', sublabel
}: {
  icon: React.ElementType
  label: string
  value: string | number
  color?: string
  sublabel?: string
}) {
  return (
    <div className="glass-card flex items-center gap-4">
      <div className={cn('w-12 h-12 rounded-xl flex items-center justify-center bg-secondary', color)}>
        <Icon className="w-6 h-6" />
      </div>
      <div>
        <p className="text-2xl font-bold text-foreground">{value}</p>
        <p className="text-sm text-muted-foreground">{label}</p>
        {sublabel && <p className="text-xs text-muted-foreground/60">{sublabel}</p>}
      </div>
    </div>
  )
}

export default function DashboardPage() {
  const navigate = useNavigate()
  const { data: stats, isLoading, isError } = useQuery({
    queryKey: ['stats'],
    queryFn: statsAPI.get,
    refetchInterval: 30_000,
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <Loader2 className="w-8 h-8 animate-spin text-primary mx-auto mb-2" />
          <p className="text-muted-foreground text-sm">Loading intelligence data...</p>
        </div>
      </div>
    )
  }

  if (isError || !stats) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <AlertTriangle className="w-8 h-8 text-orange-500 mx-auto mb-2" />
          <p className="text-foreground font-medium">Failed to load dashboard</p>
          <p className="text-muted-foreground text-sm">Check that the backend is running</p>
        </div>
      </div>
    )
  }

  const highThreats = (stats.cases_by_severity['CRITICAL'] ?? 0) +
    (stats.cases_by_severity['HIGH'] ?? 0)

  const severityChartData = SEVERITY_ORDER.map(s => ({
    name: s,
    count: stats.cases_by_severity[s] ?? 0,
    fill: SEVERITY_COLORS[s],
  }))

  const recentCases = stats.recent_cases ?? []

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Threat Intelligence Dashboard</h1>
          <p className="text-muted-foreground text-sm mt-0.5">
            Real-time overview of all forensic investigations
          </p>
        </div>
        <button
          onClick={() => navigate('/cases/new')}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg text-sm font-medium hover:bg-primary/90 transition-colors"
        >
          <Shield className="w-4 h-4" />
          New Investigation
        </button>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard icon={Shield} label="Total Cases" value={stats.total_cases} color="text-primary" />
        <MetricCard icon={AlertTriangle} label="Active Threats" value={highThreats}
          color="text-orange-500" sublabel="HIGH + CRITICAL severity" />
        <MetricCard icon={GitFork} label="Campaigns Detected" value={stats.total_campaigns}
          color="text-purple-500" />
        <MetricCard icon={Search} label="IOCs Extracted" value={stats.total_iocs}
          color="text-yellow-500" />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Severity distribution */}
        <div className="glass-card">
          <h2 className="text-sm font-semibold text-foreground mb-4">Threat Severity Distribution</h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={severityChartData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
              <XAxis dataKey="name" tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }} />
              <YAxis tick={{ fill: 'hsl(var(--muted-foreground))', fontSize: 11 }} />
              <Tooltip
                contentStyle={{
                  background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))',
                  borderRadius: '8px', color: 'hsl(var(--foreground))',
                }}
              />
              <Bar dataKey="count" fill="#4f46e5" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Threat Environment Gauge */}
        <div className="glass-card flex flex-col">
          <h2 className="text-sm font-semibold text-foreground mb-1">Threat Environment Level</h2>
          <p className="text-xs text-muted-foreground mb-4">Real-time risk posture across all cases</p>
          <ThreatGauge score={stats.avg_threat_score ?? 0} totalCases={stats.total_cases} highThreats={highThreats} totalIocs={stats.total_iocs} />
        </div>
      </div>

      {/* Chain integrity + IOC breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Blockchain integrity */}
        <div className="glass-card flex flex-col items-center justify-center py-6 text-center">
          {stats.chain_integrity ? (
            <>
              <CheckCircle2 className="w-12 h-12 text-green-500 mb-3" />
              <p className="font-semibold text-green-400">Evidence Chain Intact</p>
              <p className="text-muted-foreground text-xs mt-1">
                {stats.blockchain_blocks} blocks verified
              </p>
            </>
          ) : (
            <>
              <XCircle className="w-12 h-12 text-red-500 mb-3" />
              <p className="font-semibold text-red-400">Chain Integrity Alert</p>
              <p className="text-muted-foreground text-xs mt-1">Tamper detected — investigate immediately</p>
            </>
          )}
        </div>

        {/* IOC type breakdown */}
        <div className="glass-card lg:col-span-2">
          <h2 className="text-sm font-semibold text-foreground mb-3">IOCs by Type</h2>
          <div className="space-y-2">
            {Object.entries(stats.iocs_by_type).map(([type, count]) => {
              const pct = stats.total_iocs > 0
                ? Math.round((count / stats.total_iocs) * 100)
                : 0
              return (
                <div key={type} className="flex items-center gap-3">
                  <span className="text-xs text-muted-foreground w-20 shrink-0">{type}</span>
                  <div className="flex-1 h-2 bg-secondary rounded-full overflow-hidden">
                    <div
                      className="h-full bg-primary rounded-full transition-all duration-500"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-xs text-muted-foreground w-8 text-right">{count}</span>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* Recent cases */}
      <div className="glass-card">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-foreground">Recent Investigations</h2>
          <button
            onClick={() => navigate('/cases')}
            className="text-xs text-primary hover:text-primary/80 flex items-center gap-1"
          >
            View all <ArrowRight className="w-3 h-3" />
          </button>
        </div>
        <div className="space-y-2">
          {recentCases.length === 0 ? (
            <p className="text-muted-foreground text-sm text-center py-8">
              No cases yet. Upload a suspicious email to begin investigation.
            </p>
          ) : (
            recentCases.map((c: RecentCaseSummary) => (
              <div
                key={c.case_id}
                onClick={() => navigate(`/cases/${c.case_id}`)}
                className="flex items-center gap-4 p-3 rounded-lg hover:bg-secondary cursor-pointer transition-colors"
              >
                <div className={cn(
                  'w-2 h-2 rounded-full shrink-0',
                  getSeverityBgColor(c.severity)
                )} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-mono text-foreground">{c.case_id}</p>
                  <p className="text-xs text-muted-foreground truncate">
                    {c.subject || 'Pending analysis'}
                  </p>
                </div>
                {c.severity && (
                  <span className={cn(
                    'text-xs font-semibold px-2 py-0.5 rounded',
                    getSeverityBgColor(c.severity), 'text-white'
                  )}>
                    {c.severity}
                  </span>
                )}
                <span className="text-xs text-muted-foreground shrink-0">
                  {formatRelativeTime(c.created_at)}
                </span>
                <ArrowRight className="w-4 h-4 text-muted-foreground" />
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
