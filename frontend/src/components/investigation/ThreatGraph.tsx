import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ZoomIn, ZoomOut, Maximize2, Info, Loader2 } from 'lucide-react'
import { graphAPI } from '@/lib/api'
import { getCytoscapeNodeColor } from '@/lib/utils'
import type { Severity } from '@/types'

interface ThreatGraphProps {
  caseId?: string
}

interface SelectedNodeData {
  id: string
  label: string
  type: string
  severity?: Severity
}

type LayoutName = 'cola' | 'dagre' | 'circle'

export default function ThreatGraph({ caseId }: ThreatGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const cyRef = useRef<any>(null)
  const [selectedNode, setSelectedNode] = useState<SelectedNodeData | null>(null)
  const [layout, setLayout] = useState<LayoutName>('cola')

  const { data: graphData, isLoading, isError } = useQuery({
    queryKey: ['graph', caseId],
    queryFn: () => (caseId ? graphAPI.getForCase(caseId) : graphAPI.getGlobal()),
  })

  useEffect(() => {
    if (!graphData || !containerRef.current) return

    Promise.all([
      import('cytoscape'),
      import('cytoscape-cola'),
      import('cytoscape-dagre'),
    ]).then(([cytoscapeModule, colaModule, dagreModule]) => {
      const cytoscape = cytoscapeModule.default
      const cola = colaModule.default
      const dagre = dagreModule.default

      try { cytoscape.use(cola) } catch { /* already registered */ }
      try { cytoscape.use(dagre) } catch { /* already registered */ }

      if (cyRef.current) {
        cyRef.current.destroy()
      }

      const cy = cytoscape({
        container: containerRef.current,
        elements: [...graphData.nodes, ...graphData.edges],
        style: [
          {
            selector: 'node',
            style: {
              'background-color': (ele: any) => getCytoscapeNodeColor(ele.data('type')),
              'label': 'data(label)',
              'color': '#e2e8f0',
              'font-size': 10,
              'text-valign': 'bottom',
              'text-halign': 'center',
              'text-margin-y': 4,
              'width': (ele: any) => Math.max(Number(ele.data('size') ?? 20), 15),
              'height': (ele: any) => Math.max(Number(ele.data('size') ?? 20), 15),
              'border-width': 2,
              'border-color': '#ffffff33',
            },
          },
          {
            selector: 'node[type="case"]',
            style: {
              'shape': 'round-rectangle' as any,
              'background-color': '#3b82f6',
              'border-color': '#60a5fa',
            },
          },
          {
            selector: 'edge',
            style: {
              'width': 1.5,
              'line-color': '#374151',
              'target-arrow-color': '#374151',
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier',
              'font-size': 8,
              'color': '#9ca3af',
              'opacity': 0.7,
            },
          },
          {
            selector: 'edge[label="shared_ioc"]',
            style: {
              'line-color': '#6366f1',
              'target-arrow-color': '#6366f1',
              'line-style': 'dashed',
              'width': 2,
            },
          },
          {
            selector: 'node:selected',
            style: {
              'border-width': 3,
              'border-color': '#f0f4ff',
            },
          },
        ],
        layout: { name: layout === 'cola' ? 'cola' : layout === 'dagre' ? 'dagre' : 'circle', animate: true } as any,
        userZoomingEnabled: true,
        userPanningEnabled: true,
        minZoom: 0.1,
        maxZoom: 5,
      })

      cy.on('tap', 'node', (evt: any) => {
        const node = evt.target
        setSelectedNode({
          id: node.data('id'),
          label: node.data('label'),
          type: node.data('type'),
          severity: node.data('severity') as Severity | undefined,
        })
      })

      cy.on('tap', (evt: any) => {
        if (evt.target === cy) setSelectedNode(null)
      })

      cyRef.current = cy
    })

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy()
        cyRef.current = null
      }
    }
  }, [graphData, layout])

  const handleZoomIn  = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.2)
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8)
  const handleFit     = () => cyRef.current?.fit()

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <Loader2 className="w-8 h-8 animate-spin text-primary mx-auto mb-2" />
          <p className="text-muted-foreground text-sm">Building threat graph...</p>
        </div>
      </div>
    )
  }

  if (isError || !graphData) {
    return <div className="text-center py-16 text-muted-foreground">Failed to load threat graph</div>
  }

  if (graphData.nodes.length === 0) {
    return (
      <div className="text-center py-16 text-muted-foreground">
        <Info className="w-10 h-10 mx-auto mb-3" />
        <p>No IOC relationships to visualize yet.</p>
        <p className="text-sm mt-1">Complete analysis first to see the threat graph.</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {(['cola', 'dagre', 'circle'] as LayoutName[]).map(l => (
            <button
              key={l}
              onClick={() => setLayout(l)}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                layout === l ? 'bg-primary text-white' : 'bg-secondary text-muted-foreground hover:text-foreground'
              }`}
            >
              {l === 'cola' ? 'Force' : l === 'dagre' ? 'Hierarchical' : 'Circular'}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <button onClick={handleZoomIn} className="p-1.5 rounded bg-secondary hover:bg-secondary/80 text-muted-foreground hover:text-foreground"><ZoomIn className="w-4 h-4" /></button>
          <button onClick={handleZoomOut} className="p-1.5 rounded bg-secondary hover:bg-secondary/80 text-muted-foreground hover:text-foreground"><ZoomOut className="w-4 h-4" /></button>
          <button onClick={handleFit} className="p-1.5 rounded bg-secondary hover:bg-secondary/80 text-muted-foreground hover:text-foreground"><Maximize2 className="w-4 h-4" /></button>
        </div>
      </div>

      <div className="relative">
        <div ref={containerRef} className="cytoscape-container bg-secondary/30 rounded-xl border border-border" style={{ height: '500px' }} />

        {/* Legend */}
        <div className="absolute bottom-3 left-3 bg-card/90 backdrop-blur-sm border border-border rounded-lg p-3 space-y-1.5">
          {[
            { color: '#3b82f6', label: 'Case' },
            { color: '#ef4444', label: 'IP Address' },
            { color: '#f97316', label: 'Domain' },
            { color: '#eab308', label: 'URL' },
            { color: '#a855f7', label: 'Email' },
            { color: '#6b7280', label: 'File Hash' },
          ].map(({ color, label }) => (
            <div key={label} className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full shrink-0" style={{ backgroundColor: color }} />
              <span className="text-xs text-muted-foreground">{label}</span>
            </div>
          ))}
        </div>

        {/* Selected node */}
        {selectedNode && (
          <div className="absolute top-3 right-3 bg-card/95 backdrop-blur-sm border border-border rounded-lg p-3 max-w-56 shadow-lg">
            <p className="text-xs font-semibold text-muted-foreground mb-1 capitalize">{selectedNode.type}</p>
            <p className="text-sm text-foreground font-mono break-all">{selectedNode.label}</p>
            {selectedNode.severity && (
              <span className={`mt-2 inline-block text-xs px-2 py-0.5 rounded text-white ${
                selectedNode.severity === 'CRITICAL' ? 'bg-red-600' :
                selectedNode.severity === 'HIGH' ? 'bg-orange-600' :
                selectedNode.severity === 'MEDIUM' ? 'bg-yellow-600' : 'bg-blue-600'
              }`}>
                {selectedNode.severity}
              </span>
            )}
          </div>
        )}
      </div>

      <div className="text-xs text-muted-foreground text-center">
        {graphData.nodes.length} nodes · {graphData.edges.length} edges · Click a node for details
      </div>
    </div>
  )
}
