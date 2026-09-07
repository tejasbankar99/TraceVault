// Type declarations for Cytoscape layout plugins (no official @types packages)
declare module 'cytoscape-cola' {
  import cytoscape from 'cytoscape'
  const cola: cytoscape.Ext
  export = cola
}

declare module 'cytoscape-dagre' {
  import cytoscape from 'cytoscape'
  const dagre: cytoscape.Ext
  export = dagre
}
