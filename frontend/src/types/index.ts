// ============================================================
// TraceVault — All TypeScript Types and Interfaces
// ============================================================

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'BENIGN'
export type CaseStatus = 'PENDING' | 'ANALYZING' | 'COMPLETED' | 'FAILED'
export type IOCType = 'IP' | 'DOMAIN' | 'URL' | 'EMAIL' | 'FILE_HASH' | 'ATTACHMENT'
export type AuthVerdict = 'PASS' | 'WARN' | 'FAIL' | 'CRITICAL'
export type UserRole = 'admin' | 'analyst' | 'viewer'

// ── Auth ────────────────────────────────────────────────────
export interface User {
  id: string
  email: string
  username: string
  full_name: string
  role: UserRole
  is_active: boolean
  created_at: string
}

export interface AuthToken {
  access_token: string
  token_type: string
  expires_in: number
  user: User
}

// ── Case ────────────────────────────────────────────────────
export interface Case {
  id: string
  case_id: string
  status: CaseStatus
  evidence_hash: string
  evidence_hash3: string
  file_size_bytes: number
  threat_score: number | null
  severity: Severity | null
  created_at: string
  updated_at: string
  created_by: string
  email_headers?: EmailHeaders
  relay_hops?: RelayHop[]
  auth_result?: AuthResult
  analysis_result?: AnalysisResult
  iocs?: IOC[]
  geo_intelligence?: GeoIntelligence[]
  blockchain_ledger?: BlockchainEntry[]
  campaign?: Campaign
}

export interface CasePagination {
  total: number
  page: number
  page_size: number
  total_pages: number
  has_next: boolean
  has_prev: boolean
}

export interface CaseListResponse {
  items: Case[]
  pagination: CasePagination
}

// ── Email Headers ────────────────────────────────────────────
export interface EmailHeaders {
  id: string
  case_id: string
  from_addr: string
  from_name: string
  from_domain: string
  reply_to: string
  reply_to_domain: string
  return_path: string
  return_path_domain: string
  message_id: string
  subject: string
  date_sent: string | null
  x_originating_ip: string | null
  x_mailer: string | null
  content_type: string | null
  raw_headers: Record<string, string>
  rfc_violations: string[]
  spoofing_indicators: string[]
}

export interface RelayHop {
  id: string
  case_id: string
  hop_index: number
  by_server: string | null
  from_server: string | null
  ip_address: string | null
  protocol: string | null
  timestamp: string | null
  is_public_ip: boolean
  is_suspicious: boolean
  raw_header: string
}

export interface AuthResult {
  id: string
  case_id: string
  spf_result: string
  spf_domain: string | null
  spf_explanation: string | null
  dkim_result: string
  dkim_domain: string | null
  dkim_selector: string | null
  dmarc_result: string
  dmarc_policy: string | null
  dmarc_subdomain_policy: string | null
  overall_verdict: AuthVerdict
  spoofing_risk: string
  raw_auth_header: string | null
}

// ── Analysis ─────────────────────────────────────────────────
export interface AnalysisResult {
  id: string
  case_id: string
  threat_score: number
  severity: Severity
  threat_categories: string[]
  rule_score: number
  ml_score: number
  gemini_score: number
  ai_explanation: string
  urgency_phrases: string[]
  impersonation_details: {
    is_impersonating: boolean
    impersonated_entity: string | null
    technique: string
  }
  social_engineering_patterns: string[]
  bec_indicators: string[]
  shap_features: Record<string, number>
  recommended_actions: string[]
  analyzed_at: string
  analysis_duration_ms: number
  triggered_rules?: string[]
}

// ── IOC ──────────────────────────────────────────────────────
export interface IOC {
  id: string
  case_id: string
  ioc_type: IOCType
  ioc_value: string
  defanged_value: string | null
  severity: Severity
  context: string | null
  is_lookalike: boolean
  lookalike_target: string | null
  is_shortened_url: boolean
  redirect_target: string | null
  metadata: Record<string, unknown>
  created_at: string
}

export interface IOCListResponse {
  iocs: IOC[]
  total: number
  page: number
  per_page: number
}

// ── Geo Intelligence ─────────────────────────────────────────
export interface GeoIntelligence {
  id: string
  case_id: string
  ip_address: string
  country: string | null
  country_code: string | null
  city: string | null
  region: string | null
  latitude: number | null
  longitude: number | null
  isp: string | null
  org: string | null
  asn: string | null
  hostname: string | null
  is_vpn: boolean
  is_tor: boolean
  is_hosting: boolean
  is_proxy: boolean
  ptr_record: string | null
  whois_data: Record<string, unknown>
  dns_records: Record<string, string[]>
  enrichment_source: string | null
}

// ── Blockchain ───────────────────────────────────────────────
export interface BlockchainEntry {
  id: string
  block_index: number
  prev_hash: string
  timestamp: string
  case_id: string | null
  action: string
  actor: string
  data: Record<string, unknown>
  data_hash: string
  block_hash: string
  polygon_tx_hash: string | null
  is_anchored: boolean
}

export interface BlockchainVerifyResult {
  is_valid: boolean
  tamper_detected_at: number | null
  verified_blocks: number
  total_blocks: number
  chain_head_hash: string | null
  evidence_intact: boolean
  computed_hash: string | null
  stored_hash: string | null
  error?: string
}

// ── Campaign ─────────────────────────────────────────────────
export interface Campaign {
  id: string
  campaign_id: string
  name: string | null
  description: string | null
  case_count: number
  shared_indicators: Array<{ type: string; value: string; weight: number }>
  first_seen: string
  last_seen: string
  threat_actor_hypothesis: string | null
  cases?: Case[]
}

// ── Dashboard ────────────────────────────────────────────────
export interface RecentCaseSummary {
  case_id: string
  subject: string | null
  severity: Severity | null
  status: string
  created_at: string
}

export interface DashboardStats {
  total_cases: number
  cases_by_severity: Record<string, number>
  cases_by_status: Record<string, number>
  total_iocs: number
  iocs_by_type: Record<string, number>
  total_campaigns: number
  blockchain_blocks: number
  chain_integrity: boolean
  recent_cases: RecentCaseSummary[]
  threat_trend: Array<{ date: string; count: number }>
}

// ── Graph ────────────────────────────────────────────────────
export interface GraphNode {
  data: {
    id: string
    label: string
    type: 'case' | 'ip' | 'domain' | 'url' | 'email' | 'file_hash' | 'attachment'
    severity?: Severity
    size?: number
  }
}

export interface GraphEdge {
  data: {
    source: string
    target: string
    label: string
    weight?: number
  }
}

export interface CytoscapeGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

// ── SSE Events ───────────────────────────────────────────────
export interface SSEEvent {
  step: string
  progress: number
  message: string
  data?: {
    threat_score?: number
    severity?: Severity
    ioc_count?: number
    campaign_id?: string
    is_part_of_campaign?: boolean
  }
}

export type AnalysisStep =
  | 'start'
  | 'parsing'
  | 'header_forensics'
  | 'auth_validation'
  | 'ioc_extraction'
  | 'ai_analysis'
  | 'geo_intelligence'
  | 'correlation'
  | 'blockchain'
  | 'finalizing'
  | 'complete'
  | 'error'

// ── API Query Params ─────────────────────────────────────────
export interface CaseListParams {
  page?: number
  per_page?: number
  severity?: Severity
  status?: CaseStatus
  q?: string
  date_from?: string
  date_to?: string
}

export interface IOCListParams {
  page?: number
  per_page?: number
  ioc_type?: IOCType
  severity?: Severity
  case_id?: string
  q?: string
}
