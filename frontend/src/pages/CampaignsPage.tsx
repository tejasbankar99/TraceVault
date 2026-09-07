import { useQuery } from '@tanstack/react-query'
import { GitFork, Calendar, Hash, ChevronDown, ChevronUp, Loader2, AlertTriangle, Network, Shield } from 'lucide-react'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { campaignsAPI } from '@/lib/api'
import { formatRelativeTime, getSeverityBgColor, cn } from '@/lib/utils'
import type { Campaign } from '@/types'

function CampaignCard({ campaign }: { campaign: Campaign }) {
  const [expanded, setExpanded] = useState(false)
  const navigate = useNavigate()

  return (
    <div className="glass-card space-y-4">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-purple-950 border border-purple-800 flex items-center justify-center">
            <GitFork className="w-5 h-5 text-purple-400" />
          </div>
          <div>
            <p className="font-mono font-bold text-primary">{campaign.campaign_id}</p>
            {campaign.name && <p className="text-muted-foreground text-sm">{campaign.name}</p>}
          </div>
        </div>
        <div className="text-right">
          <p className="text-2xl font-bold text-foreground">{campaign.case_count}</p>
          <p className="text-xs text-muted-foreground">related cases</p>
        </div>
      </div>

      <div className="flex gap-4 text-xs text-muted-foreground">
        <span className="flex items-center gap-1">
          <Calendar className="w-3 h-3" />
          First: {formatRelativeTime(campaign.first_seen)}
        </span>
        <span className="flex items-center gap-1">
          <Calendar className="w-3 h-3" />
          Last: {formatRelativeTime(campaign.last_seen)}
        </span>
        <span className="flex items-center gap-1">
          <Hash className="w-3 h-3" />
          {campaign.shared_indicators.length} shared IOCs
        </span>
      </div>

      {campaign.threat_actor_hypothesis && (
        <div className="p-3 rounded-lg bg-yellow-950/30 border border-yellow-800/50 text-xs text-yellow-300">
          <strong>Attribution Hypothesis:</strong> {campaign.threat_actor_hypothesis}
        </div>
      )}

      {/* Shared IOCs preview */}
      {campaign.shared_indicators.length > 0 && (
        <div>
          <button
            onClick={() => setExpanded(!expanded)}
            className="flex items-center gap-2 text-xs text-muted-foreground hover:text-foreground"
          >
            {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
            {expanded ? 'Hide' : 'Show'} shared indicators
          </button>

          {expanded && (
            <div className="mt-3 space-y-1.5 max-h-48 overflow-auto">
              {campaign.shared_indicators.slice(0, 20).map((ioc, i) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <span className="text-muted-foreground w-16 shrink-0">{ioc.type}</span>
                  <span className="font-mono text-foreground truncate">{ioc.value}</span>
                  <span className="text-muted-foreground shrink-0">w:{ioc.weight.toFixed(1)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Related cases */}
      {campaign.cases && campaign.cases.length > 0 && (
        <div>
          <p className="text-xs font-semibold text-muted-foreground mb-2">Related Cases</p>
          <div className="space-y-1.5">
            {campaign.cases.slice(0, 5).map(c => (
              <div
                key={c.id}
                onClick={() => navigate(`/cases/${c.case_id}`)}
                className="flex items-center gap-3 p-2 rounded-lg hover:bg-secondary cursor-pointer transition-colors"
              >
                <div className={cn('w-2 h-2 rounded-full shrink-0', getSeverityBgColor(c.severity))} />
                <span className="font-mono text-xs text-primary flex-1">{c.case_id}</span>
                {c.severity && (
                  <span className={cn('text-xs px-1.5 py-0.5 rounded text-white', getSeverityBgColor(c.severity))}>
                    {c.severity}
                  </span>
                )}
                <span className="text-xs text-muted-foreground">{formatRelativeTime(c.created_at)}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default function CampaignsPage() {
  const { data: campaigns = [], isLoading, isError } = useQuery({
    queryKey: ['campaigns'],
    queryFn: campaignsAPI.list,
    refetchInterval: 60_000,
  })

  // Derived stats
  const totalCasesAffected = campaigns.reduce((sum, c) => sum + c.case_count, 0)
  const totalSharedIOCs = campaigns.reduce((sum, c) => sum + c.shared_indicators.length, 0)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Campaign Correlation</h1>
        <p className="text-muted-foreground text-sm mt-0.5">
          Phishing campaigns detected by correlating shared indicators across cases
        </p>
      </div>

      {/* Stat Cards */}
      {!isLoading && !isError && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="glass-card flex items-center gap-4">
            <div className="w-11 h-11 rounded-xl bg-purple-950 border border-purple-800 flex items-center justify-center shrink-0">
              <GitFork className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">{campaigns.length}</p>
              <p className="text-xs text-muted-foreground">Campaigns Detected</p>
            </div>
          </div>
          <div className="glass-card flex items-center gap-4">
            <div className="w-11 h-11 rounded-xl bg-blue-950 border border-blue-800 flex items-center justify-center shrink-0">
              <Shield className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">{totalCasesAffected}</p>
              <p className="text-xs text-muted-foreground">Cases Affected</p>
            </div>
          </div>
          <div className="glass-card flex items-center gap-4">
            <div className="w-11 h-11 rounded-xl bg-yellow-950 border border-yellow-800 flex items-center justify-center shrink-0">
              <Network className="w-5 h-5 text-yellow-400" />
            </div>
            <div>
              <p className="text-2xl font-bold text-foreground">{totalSharedIOCs}</p>
              <p className="text-xs text-muted-foreground">Shared IOCs Across Campaigns</p>
            </div>
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="flex items-center justify-center h-40">
          <Loader2 className="w-6 h-6 animate-spin text-primary" />
        </div>
      ) : isError ? (
        <div className="flex items-center gap-2 text-orange-500 justify-center h-40">
          <AlertTriangle className="w-5 h-5" />
          <span className="text-sm">Failed to load campaigns</span>
        </div>
      ) : campaigns.length === 0 ? (
        <div className="text-center py-20">
          <GitFork className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
          <p className="text-foreground font-medium">No campaigns detected yet</p>
          <p className="text-muted-foreground text-sm mt-2 max-w-sm mx-auto">
            Campaigns are automatically detected when multiple cases share common indicators of compromise (IPs, domains, URLs).
          </p>
          <p className="text-muted-foreground text-sm mt-1">
            Analyze at least 2 related emails to trigger campaign detection.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">{campaigns.length} campaign{campaigns.length !== 1 ? 's' : ''} detected</p>
          {campaigns.map(campaign => (
            <CampaignCard key={campaign.id} campaign={campaign} />
          ))}
        </div>
      )}
    </div>
  )
}
