import { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useDropzone } from 'react-dropzone'
import {
  Upload, AlertCircle, CheckCircle2, Loader2,
  Shield, ChevronRight, RotateCcw, Eye
} from 'lucide-react'
import { casesAPI, analysisAPI } from '@/lib/api'
import { cn, formatFileSize, computeSHA256 } from '@/lib/utils'
import type { SSEEvent, AnalysisStep, Severity } from '@/types'

const STEPS: { id: AnalysisStep; label: string; description: string }[] = [
  { id: 'parsing',          label: 'Parse Email',       description: 'Parsing MIME structure and headers' },
  { id: 'header_forensics', label: 'Header Forensics',  description: 'Analyzing relay chain and anomalies' },
  { id: 'auth_validation',  label: 'Auth Validation',   description: 'Checking SPF, DKIM, and DMARC' },
  { id: 'ioc_extraction',   label: 'IOC Extraction',    description: 'Extracting indicators of compromise' },
  { id: 'ai_analysis',      label: 'AI Analysis',       description: 'Running Gemini + ML threat engine' },
  { id: 'geo_intelligence', label: 'Geo Intelligence',  description: 'Gathering infrastructure & location data' },
  { id: 'correlation',      label: 'Correlation',       description: 'Cross-referencing threat intelligence' },
  { id: 'blockchain',       label: 'Blockchain Log',    description: 'Recording to evidence ledger' },
]

type StepStatus = 'pending' | 'active' | 'done' | 'error'

interface UploadState {
  file: File | null
  rawText: string
  sha256: string
  useRawText: boolean
}

interface AnalysisState {
  caseId: string
  progress: number
  currentStep: AnalysisStep | null
  currentMessage: string
  stepStatuses: Record<string, StepStatus>
  isComplete: boolean
  isError: boolean
  finalScore: number | null
  finalSeverity: Severity | null
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'text-red-500',
  HIGH: 'text-orange-500',
  MEDIUM: 'text-yellow-500',
  LOW: 'text-blue-400',
  BENIGN: 'text-green-500',
}

export default function UploadPage() {
  const navigate = useNavigate()
  const [phase, setPhase] = useState<'upload' | 'analyzing' | 'complete'>('upload')
  const [upload, setUpload] = useState<UploadState>({
    file: null, rawText: '', sha256: '', useRawText: false,
  })
  const [analysis, setAnalysis] = useState<AnalysisState>({
    caseId: '', progress: 0, currentStep: null, currentMessage: '',
    stepStatuses: {}, isComplete: false, isError: false,
    finalScore: null, finalSeverity: null,
  })
  const [uploading, setUploading] = useState(false)
  const [uploadError, setUploadError] = useState('')

  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    const file = acceptedFiles[0]
    if (!file) return
    setUpload(u => ({ ...u, file, sha256: '' }))
    try {
      const hash = await computeSHA256(file)
      setUpload(u => ({ ...u, sha256: hash }))
    } catch { /* ignore */ }
  }, [])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'message/rfc822': ['.eml'] },
    maxSize: 25 * 1024 * 1024,
    multiple: false,
  })

  const handleSubmit = async () => {
    if (!upload.file && !upload.rawText.trim()) {
      setUploadError('Please select a .eml file or paste email content.')
      return
    }
    setUploading(true)
    setUploadError('')
    try {
      // 1. Upload and create case
      const caseData = await casesAPI.upload(
        upload.file,
        upload.useRawText ? upload.rawText : undefined
      )
      const caseId = caseData.case_id

      // 2. Trigger analysis
      await analysisAPI.trigger(caseId)

      // 3. Switch to analyzing phase
      setAnalysis(prev => ({
        ...prev,
        caseId,
        stepStatuses: Object.fromEntries(STEPS.map(s => [s.id, 'pending'])),
      }))
      setPhase('analyzing')

      // 4. Stream SSE progress
      analysisAPI.streamAnalysis(
        caseId,
        (event: SSEEvent) => {
          setAnalysis(prev => {
            const newStatuses = { ...prev.stepStatuses }
            // Mark previous active as done
            if (prev.currentStep && prev.currentStep !== event.step) {
              newStatuses[prev.currentStep] = 'done'
            }
            if (event.step !== 'start' && event.step !== 'complete' && event.step !== 'error') {
              newStatuses[event.step] = 'active'
            }
            return {
              ...prev,
              progress: event.progress,
              currentStep: event.step as AnalysisStep,
              currentMessage: event.message,
              stepStatuses: newStatuses,
              finalScore: event.data?.threat_score ?? prev.finalScore,
              finalSeverity: (event.data?.severity as Severity) ?? prev.finalSeverity,
            }
          })

          if (event.step === 'complete') {
            setAnalysis(prev => {
              const allDone = Object.fromEntries(STEPS.map(s => [s.id, 'done' as StepStatus])) as Record<string, StepStatus>
              return { ...prev, stepStatuses: allDone, isComplete: true, progress: 100 }
            })
            setPhase('complete')
          }

          if (event.step === 'error') {
            setAnalysis(prev => ({
              ...prev, isError: true,
            }))
          }
        },
        () => {},
        () => {
          setAnalysis(prev => ({ ...prev, isError: !prev.isComplete }))
        }
      )
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      setUploadError(msg || 'Upload failed. Please try again.')
    } finally {
      setUploading(false)
    }
  }

  const resetUpload = () => {
    setUpload({ file: null, rawText: '', sha256: '', useRawText: false })
    setAnalysis({
      caseId: '', progress: 0, currentStep: null, currentMessage: '',
      stepStatuses: {}, isComplete: false, isError: false,
      finalScore: null, finalSeverity: null,
    })
    setPhase('upload')
    setUploadError('')
  }

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">New Investigation</h1>
        <p className="text-muted-foreground text-sm mt-0.5">
          Upload a suspicious .eml file or paste raw email content for forensic analysis
        </p>
      </div>

      {/* PHASE: Upload */}
      {phase === 'upload' && (
        <div className="space-y-4">
          {/* Mode toggle */}
          <div className="flex gap-2">
            <button
              onClick={() => setUpload(u => ({ ...u, useRawText: false }))}
              className={cn(
                'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                !upload.useRawText ? 'bg-primary text-white' : 'bg-secondary text-muted-foreground hover:text-foreground'
              )}
            >
              Upload .eml File
            </button>
            <button
              onClick={() => setUpload(u => ({ ...u, useRawText: true }))}
              className={cn(
                'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                upload.useRawText ? 'bg-primary text-white' : 'bg-secondary text-muted-foreground hover:text-foreground'
              )}
            >
              Paste Raw Email
            </button>
          </div>

          {!upload.useRawText ? (
            <>
              {/* Dropzone */}
              <div
                {...getRootProps()}
                className={cn(
                  'border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all',
                  isDragActive
                    ? 'border-primary bg-primary/5'
                    : upload.file
                    ? 'border-green-600 bg-green-950/20'
                    : 'border-border hover:border-primary/50 hover:bg-secondary/50'
                )}
              >
                <input {...getInputProps()} />
                {upload.file ? (
                  <div className="space-y-2">
                    <CheckCircle2 className="w-12 h-12 text-green-500 mx-auto" />
                    <p className="font-medium text-foreground">{upload.file.name}</p>
                    <p className="text-sm text-muted-foreground">{formatFileSize(upload.file.size)}</p>
                    {upload.sha256 && (
                      <div className="mt-3 text-left bg-secondary rounded-lg p-3">
                        <p className="text-xs text-muted-foreground mb-1">SHA-256 (computed client-side)</p>
                        <p className="hash-display">{upload.sha256}</p>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="space-y-3">
                    <Upload className="w-12 h-12 text-muted-foreground mx-auto" />
                    <div>
                      <p className="text-foreground font-medium">
                        {isDragActive ? 'Drop the file here' : 'Drag & drop your .eml file'}
                      </p>
                      <p className="text-muted-foreground text-sm mt-1">
                        or click to browse · Max 25MB
                      </p>
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="space-y-2">
              <label className="text-sm text-muted-foreground">
                Paste raw email content (including headers)
              </label>
              <textarea
                rows={14}
                placeholder="Received: from mail.example.com...&#10;From: attacker@evil.com&#10;Subject: Urgent action required&#10;&#10;Email body here..."
                className="w-full px-4 py-3 rounded-xl bg-secondary border border-border text-sm text-foreground font-mono placeholder:text-muted-foreground/40 focus:outline-none focus:ring-2 focus:ring-primary resize-none"
                value={upload.rawText}
                onChange={e => setUpload(u => ({ ...u, rawText: e.target.value }))}
              />
            </div>
          )}

          {uploadError && (
            <div className="flex items-center gap-2 p-3 rounded-lg bg-destructive/10 border border-destructive/30 text-red-400 text-sm">
              <AlertCircle className="w-4 h-4 shrink-0" />
              {uploadError}
            </div>
          )}

          <button
            onClick={handleSubmit}
            disabled={uploading || (!upload.file && !upload.rawText.trim())}
            className="w-full py-3 rounded-xl bg-primary text-white font-semibold flex items-center justify-center gap-2 hover:bg-primary/90 disabled:opacity-50 transition-all"
          >
            {uploading ? (
              <><Loader2 className="w-5 h-5 animate-spin" /> Preserving Evidence...</>
            ) : (
              <><Shield className="w-5 h-5" /> Start Forensic Analysis</>
            )}
          </button>
        </div>
      )}

      {/* PHASE: Analyzing */}
      {(phase === 'analyzing' || phase === 'complete') && (
        <div className="space-y-6">
          {/* Case ID */}
          <div className="glass-card">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Case ID</p>
                <p className="font-mono text-primary font-bold">{analysis.caseId}</p>
              </div>
              {phase === 'complete' && (
                <div className="text-right">
                  <p className="text-xs text-muted-foreground">Threat Score</p>
                  <p className={cn(
                    'text-3xl font-bold',
                    SEVERITY_COLORS[analysis.finalSeverity ?? 'LOW']
                  )}>
                    {analysis.finalScore ?? '—'}<span className="text-sm text-muted-foreground">/100</span>
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Progress bar */}
          <div className="glass-card space-y-3">
            <div className="flex items-center justify-between text-sm">
              <span className="text-foreground font-medium">{analysis.currentMessage || 'Initializing...'}</span>
              <span className="text-muted-foreground">{analysis.progress}%</span>
            </div>
            <div className="h-2 bg-secondary rounded-full overflow-hidden">
              <div
                className="h-full bg-primary rounded-full transition-all duration-500"
                style={{ width: `${analysis.progress}%` }}
              />
            </div>
          </div>

          {/* Step indicator */}
          <div className="glass-card space-y-3">
            {STEPS.map((step, i) => {
              const status = analysis.stepStatuses[step.id] ?? 'pending'
              return (
                <div key={step.id} className="flex items-center gap-3">
                  <div className={cn(
                    'w-6 h-6 rounded-full flex items-center justify-center shrink-0 text-xs font-bold',
                    status === 'done'   && 'bg-green-900 text-green-400',
                    status === 'active' && 'bg-primary text-white',
                    status === 'error'  && 'bg-red-900 text-red-400',
                    status === 'pending'&& 'bg-secondary text-muted-foreground',
                  )}>
                    {status === 'done'   && <CheckCircle2 className="w-4 h-4" />}
                    {status === 'active' && <Loader2 className="w-4 h-4 animate-spin" />}
                    {status === 'error'  && <AlertCircle className="w-4 h-4" />}
                    {status === 'pending'&& <span>{i + 1}</span>}
                  </div>
                  <div className="flex-1">
                    <p className={cn(
                      'text-sm font-medium',
                      status === 'active' ? 'text-foreground' : 'text-muted-foreground'
                    )}>
                      {step.label}
                    </p>
                    {status === 'active' && (
                      <p className="text-xs text-muted-foreground">{step.description}</p>
                    )}
                  </div>
                  {status === 'done' && <CheckCircle2 className="w-4 h-4 text-green-500" />}
                </div>
              )
            })}
          </div>

          {/* Complete actions */}
          {phase === 'complete' && (
            <div className="glass-card border border-green-700/50 bg-green-950/20 space-y-4">
              <div className="flex items-center gap-3">
                <CheckCircle2 className="w-8 h-8 text-green-500" />
                <div>
                  <p className="font-semibold text-green-400">Analysis Complete!</p>
                  <p className="text-muted-foreground text-sm">
                    Severity: <span className={cn('font-bold', SEVERITY_COLORS[analysis.finalSeverity ?? 'LOW'])}>
                      {analysis.finalSeverity}
                    </span>
                    {' · '}Score: <strong className="text-foreground">{analysis.finalScore}/100</strong>
                  </p>
                </div>
              </div>
              <div className="flex gap-3">
                <button
                  onClick={() => navigate(`/cases/${analysis.caseId}`)}
                  className="flex-1 py-2.5 rounded-lg bg-primary text-white text-sm font-medium flex items-center justify-center gap-2 hover:bg-primary/90"
                >
                  <Eye className="w-4 h-4" />
                  View Investigation
                  <ChevronRight className="w-4 h-4" />
                </button>
                <button
                  onClick={resetUpload}
                  className="px-4 py-2.5 rounded-lg bg-secondary border border-border text-sm text-foreground flex items-center gap-2 hover:bg-secondary/80"
                >
                  <RotateCcw className="w-4 h-4" />
                  New Case
                </button>
              </div>
            </div>
          )}

          {analysis.isError && !analysis.isComplete && (
            <div className="glass-card border border-red-700/50 bg-red-950/20 flex items-center gap-3">
              <AlertCircle className="w-6 h-6 text-red-500" />
              <div className="flex-1">
                <p className="text-red-400 font-medium">Analysis encountered an error</p>
                <p className="text-muted-foreground text-sm">Partial results may still be available.</p>
              </div>
              <button
                onClick={() => navigate(`/cases/${analysis.caseId}`)}
                className="px-3 py-1.5 bg-secondary border border-border rounded text-sm text-foreground flex items-center gap-1"
              >
                <Eye className="w-4 h-4" /> View Case
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
