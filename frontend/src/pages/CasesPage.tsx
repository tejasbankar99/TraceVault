import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  Search, Plus, ChevronLeft, ChevronRight, ArrowRight,
  Loader2, AlertTriangle, Filter
} from 'lucide-react'
import { casesAPI } from '@/lib/api'
import { cn, formatRelativeTime, getSeverityBgColor } from '@/lib/utils'
import type { Severity, CaseStatus, CaseListParams, CaseListResponse, Case } from '@/types'

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'BENIGN']
const STATUSES: CaseStatus[] = ['PENDING', 'ANALYZING', 'COMPLETED', 'FAILED']

const STATUS_COLORS: Record<CaseStatus, string> = {
  PENDING: 'text-gray-400 bg-gray-900 border-gray-700',
  ANALYZING: 'text-blue-400 bg-blue-950 border-blue-800',
  COMPLETED: 'text-green-400 bg-green-950 border-green-800',
  FAILED: 'text-red-400 bg-red-950 border-red-800',
}

export default function CasesPage() {
  const navigate = useNavigate()
  const [params, setParams] = useState<CaseListParams>({ page: 1, per_page: 20 })
  const [search, setSearch] = useState('')

  const { data, isLoading, isError } = useQuery<CaseListResponse>({
    queryKey: ['cases', params, search],
    queryFn: () => casesAPI.list({ ...params, q: search || undefined }),
    placeholderData: (prev: CaseListResponse | undefined) => prev,
  })

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    setParams(p => ({ ...p, page: 1, q: search || undefined }))
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Investigations</h1>
          <p className="text-muted-foreground text-sm">
            {data?.total ?? 0} total cases
          </p>
        </div>
        <button
          onClick={() => navigate('/cases/new')}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg text-sm font-medium hover:bg-primary/90 transition-colors"
        >
          <Plus className="w-4 h-4" />
          New Investigation
        </button>
      </div>

      {/* Filters */}
      <div className="glass-card">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search */}
          <form onSubmit={handleSearch} className="flex-1 min-w-64 flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input
                type="text"
                placeholder="Search case ID, subject..."
                className="w-full pl-9 pr-3 py-2 rounded-lg bg-secondary border border-border text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary"
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
            </div>
            <button type="submit" className="px-3 py-2 bg-primary text-white rounded-lg text-sm">
              Search
            </button>
          </form>

          {/* Severity filter */}
          <div className="flex items-center gap-1">
            <Filter className="w-4 h-4 text-muted-foreground" />
            <select
              className="px-3 py-2 rounded-lg bg-secondary border border-border text-sm text-foreground focus:outline-none"
              value={params.severity ?? ''}
              onChange={e => setParams(p => ({
                ...p, page: 1,
                severity: e.target.value ? e.target.value as Severity : undefined
              }))}
            >
              <option value="">All Severities</option>
              {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>

            <select
              className="px-3 py-2 rounded-lg bg-secondary border border-border text-sm text-foreground focus:outline-none"
              value={params.status ?? ''}
              onChange={e => setParams(p => ({
                ...p, page: 1,
                status: e.target.value ? e.target.value as CaseStatus : undefined
              }))}
            >
              <option value="">All Statuses</option>
              {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="glass-card p-0 overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-40">
            <Loader2 className="w-6 h-6 animate-spin text-primary" />
          </div>
        ) : isError ? (
          <div className="flex items-center justify-center h-40 gap-2 text-orange-500">
            <AlertTriangle className="w-5 h-5" />
            <span className="text-sm">Failed to load cases</span>
          </div>
        ) : data?.cases.length === 0 ? (
          <div className="text-center py-16">
            <Search className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
            <p className="text-foreground font-medium">No investigations found</p>
            <p className="text-muted-foreground text-sm mt-1">
              Upload a suspicious email to create your first case.
            </p>
            <button
              onClick={() => navigate('/cases/new')}
              className="mt-4 px-4 py-2 bg-primary text-white rounded-lg text-sm"
            >
              Start Investigation
            </button>
          </div>
        ) : (
          <table className="w-full">
            <thead className="border-b border-border">
              <tr className="text-xs text-muted-foreground">
                <th className="text-left px-4 py-3 font-medium">Case ID</th>
                <th className="text-left px-4 py-3 font-medium">Subject</th>
                <th className="text-left px-4 py-3 font-medium">Severity</th>
                <th className="text-left px-4 py-3 font-medium">Score</th>
                <th className="text-left px-4 py-3 font-medium">Status</th>
                <th className="text-left px-4 py-3 font-medium">Created</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {data?.cases.map((c: Case) => (
                <tr
                  key={c.id}
                  onClick={() => navigate(`/cases/${c.case_id}`)}
                  className="hover:bg-secondary/50 cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3">
                    <span className="font-mono text-xs text-primary">{c.case_id}</span>
                  </td>
                  <td className="px-4 py-3 max-w-xs">
                    <span className="text-sm text-foreground truncate block">
                      {c.subject || c.email_headers?.[0]?.subject || (
                        <span className="text-muted-foreground italic">Pending analysis</span>
                      )}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {c.severity ? (
                      <span className={cn(
                        'text-xs font-bold px-2 py-0.5 rounded',
                        getSeverityBgColor(c.severity), 'text-white'
                      )}>
                        {c.severity}
                      </span>
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {c.threat_score !== null ? (
                      <div className="flex items-center gap-2 min-w-[80px]">
                        <div className="flex-1 h-1.5 bg-secondary rounded-full overflow-hidden">
                          <div
                            className={cn(
                              'h-full rounded-full',
                              c.threat_score >= 80 ? 'bg-red-500' :
                              c.threat_score >= 60 ? 'bg-orange-500' :
                              c.threat_score >= 40 ? 'bg-yellow-500' :
                              c.threat_score >= 20 ? 'bg-blue-500' : 'bg-green-500'
                            )}
                            style={{ width: `${c.threat_score}%` }}
                          />
                        </div>
                        <span className="text-xs font-mono text-muted-foreground w-8 text-right">
                          {c.threat_score}
                        </span>
                      </div>
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className={cn(
                      'text-xs font-medium px-2 py-0.5 rounded border',
                      STATUS_COLORS[c.status]
                    )}>
                      {c.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs text-muted-foreground">{formatRelativeTime(c.created_at)}</span>
                  </td>
                  <td className="px-4 py-3">
                    <ArrowRight className="w-4 h-4 text-muted-foreground" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      {data && data.total_pages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Page {data.page} of {data.total_pages}
          </p>
          <div className="flex gap-2">
            <button
              disabled={(params.page ?? 1) <= 1}
              onClick={() => setParams(p => ({ ...p, page: (p.page ?? 1) - 1 }))}
              className="px-3 py-1.5 rounded-lg bg-secondary border border-border text-sm text-foreground disabled:opacity-40 flex items-center gap-1"
            >
              <ChevronLeft className="w-4 h-4" /> Prev
            </button>
            <button
              disabled={(params.page ?? 1) >= data.total_pages}
              onClick={() => setParams(p => ({ ...p, page: (p.page ?? 1) + 1 }))}
              className="px-3 py-1.5 rounded-lg bg-secondary border border-border text-sm text-foreground disabled:opacity-40 flex items-center gap-1"
            >
              Next <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
