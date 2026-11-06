// Mirrors contracts/schemas/. Everything in these objects that came from the endpoint
// is attacker-controlled, so it is only ever rendered as text.

export type Layer = 'signature' | 'heuristic' | 'fim' | 'rule' | 'ml'
export type Zone = 'documents' | 'persistence' | 'lsass' | 'network' | 'none'
export type ActionName =
  | 'alert_only'
  | 'suspend'
  | 'block_network'
  | 'restore'
  | 'request_kill'
  | 'request_delete'
export type RequestAction = Extract<ActionName, 'request_kill' | 'request_delete'>
export type ActionStatus =
  | 'executed'
  | 'failed'
  | 'skipped'
  | 'awaiting_approval'
  | 'approved'
  | 'rejected'

export interface FileChange {
  kind: 'added' | 'modified' | 'removed'
  old_value: string | null
  new_value: string | null
}

export interface Event {
  event_id: string
  ts: string
  host: string
  source: 'etw' | 'sysmon' | 'fim'
  event_type: string
  pid: number
  ppid: number
  process: {
    image: string
    cmdline: string | null
    user: string | null
    sha256: string | null
    signed: boolean
    signer: string | null
  }
  target: {
    path: string | null
    old_path?: string | null
    registry_key: string | null
    pid: number | null
    access_mask: string | number | null
    access_rights?: string[] | null
    dest_ip: string | null
    dest_port: number | null
    change?: FileChange | null
  }
}

export interface Alert {
  alert_id: string
  ts: string
  layer: Layer
  rule_id: string
  technique_ids: string[]
  risk_score: number | null
  event_type: string
  /** For analysts only. The policy engine ignores it. Reasons can quote file content. */
  static_analysis?: { score: number | null; reasons: string[] }
  subject: {
    pid: number
    image: string
    signed: boolean
    signer: string | null
    trusted_path: boolean
    ancestors: { pid: number; image: string }[]
  }
  object: {
    zone: Zone
    path: string | null
    registry_key: string | null
    access: string[]
    file_sha256: string | null
  }
  evidence_event_ids: string[]
}

export interface AlertDetailResponse {
  alert: Alert
  evidence_events: Event[]
}

export interface Action {
  action: ActionName
  automatic: boolean
  status: ActionStatus
  reason?: string
  executed_at: string | null
  reviewed_by?: string
  reviewed_at?: string
}

export interface Decision {
  decision_id: string
  alert_id: string
  ts: string
  policy_rules: string[]
  actions: Action[]
  attributes: Record<string, unknown>
}

export interface Report {
  report_id: string
  alert_id: string
  summary: string
  techniques: { id: string; name: string; evidence: string }[]
  timeline: string[]
  validated: boolean
}

export interface FimChange {
  event_id: string
  ts: string
  path: string | null
  registry_key: string | null
  change: FileChange
  alert_id: string | null
  status: 'pending' | 'approved'
  reviewed_by?: string
  reviewed_at?: string
}

export interface Stats {
  events_total: number
  alerts_total: number
  alerts_not_scored: number
  alerts_by_layer: Record<Layer, number>
  alerts_by_zone: Record<Zone, number>
  actions_by_status: Record<ActionStatus, number>
  pending_approvals: number
  fim_changes_pending: number
  reports_total: number
  events_filtered_before_llm: number
  skipped_records: Record<'events' | 'alerts' | 'decisions' | 'reports', number>
}
