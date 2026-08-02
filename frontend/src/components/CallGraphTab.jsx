import { useEffect, useMemo, useRef, useState } from 'react';
import { api, hex } from '../api.js';
import { Empty, ErrorBanner, Loading, ProvenanceBadge } from './common.jsx';

const NODE_W = 180;
const NODE_H = 48;
const COL_GAP = 80;
const ROW_GAP = 32;
const MAX_RENDERED_NODES = 160;

function graphLayout(nodes, edges) {
  const incoming = new Map(nodes.map((node) => [node.address, 0]));
  for (const edge of edges) incoming.set(edge.target, (incoming.get(edge.target) || 0) + 1);
  const depth = new Map();
  const roots = nodes.filter((node) => node.is_entry || incoming.get(node.address) === 0);
  const queue = roots.map((node) => [node.address, 0]);
  while (queue.length) {
    const [address, level] = queue.shift();
    if ((depth.get(address) ?? -1) >= level) continue;
    depth.set(address, level);
    for (const edge of edges.filter((item) => item.source === address)) {
      if (edge.target !== address) queue.push([edge.target, level + 1]);
    }
  }
  for (const node of nodes) if (!depth.has(node.address)) depth.set(node.address, 0);

  const rows = new Map();
  const positions = new Map();
  for (const node of nodes) {
    const column = Math.min(depth.get(node.address), 8);
    const row = rows.get(column) || 0;
    rows.set(column, row + 1);
    positions.set(node.address, {
      x: 28 + column * (NODE_W + COL_GAP),
      y: 28 + row * (NODE_H + ROW_GAP),
    });
  }
  const width = Math.max(460, ...[...positions.values()].map((item) => item.x + NODE_W + 30));
  const height = Math.max(250, ...[...positions.values()].map((item) => item.y + NODE_H + 30));
  return { positions, width, height };
}

export function CallGraphTab({ sha, selectedAddress, onSelect }) {
  const [graph, setGraph] = useState(null);
  const [query, setQuery] = useState('');
  const [error, setError] = useState(null);
  const svgRef = useRef(null);

  useEffect(() => {
    let active = true;
    setGraph(null);
    api.callgraph(sha)
      .then((result) => active && (setGraph(result), setError(null)))
      .catch((failure) => active && setError(failure.message));
    return () => { active = false; };
  }, [sha]);

  const rendered = useMemo(() => {
    if (!graph) return null;
    const nodes = graph.nodes.slice(0, MAX_RENDERED_NODES);
    const addresses = new Set(nodes.map((node) => node.address));
    return { nodes, edges: graph.edges.filter((edge) => addresses.has(edge.source) && addresses.has(edge.target)) };
  }, [graph]);

  if (error) return <ErrorBanner error={error} />;
  if (!rendered) return <Loading label="Building static direct-call graph…" />;
  if (!rendered.nodes.length) return <Empty label="No call relationships recovered" />;

  const { positions, width, height } = graphLayout(rendered.nodes, rendered.edges);
  const needle = query.toLowerCase();

  function download(content, type, extension) {
    const url = URL.createObjectURL(new Blob([content], { type }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `callgraph-${sha.slice(0, 12)}.${extension}`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  function serializedSvg() {
    const clone = svgRef.current.cloneNode(true);
    clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
    const style = document.createElementNS('http://www.w3.org/2000/svg', 'style');
    style.textContent = `
      .call-edge{fill:none;stroke:#667084;stroke-width:1.2}
      .call-node rect{fill:#171c25;stroke:#2b3341}.call-node-name{fill:#e5e9f0;font:11px monospace}
      .call-node-address{fill:#929bab;font:9px monospace}
    `;
    clone.prepend(style);
    return new XMLSerializer().serializeToString(clone);
  }

  function exportPng() {
    const source = serializedSvg();
    const image = new Image();
    image.onload = () => {
      const scale = Math.min(2, 4096 / Math.max(width, height));
      const canvas = document.createElement('canvas');
      canvas.width = Math.ceil(width * scale);
      canvas.height = Math.ceil(height * scale);
      const context = canvas.getContext('2d');
      context.fillStyle = '#090c11';
      context.fillRect(0, 0, canvas.width, canvas.height);
      context.scale(scale, scale);
      context.drawImage(image, 0, 0);
      canvas.toBlob((blob) => {
        if (!blob) return;
        const url = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = `callgraph-${sha.slice(0, 12)}.png`;
        anchor.click();
        URL.revokeObjectURL(url);
      }, 'image/png');
    };
    image.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(source)}`;
  }

  return (
    <div className="callgraph-view">
      <div className="toolbar">
        <input className="text function-search" type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Find graph node…" aria-label="Find call graph node" />
        <span className="muted">{graph.nodes.length} nodes · {graph.edges.length} static edges</span>
        <ProvenanceBadge kind="heuristic" />
        {(graph.truncated || graph.nodes.length > MAX_RENDERED_NODES) && <span className="badge medium">render bounded</span>}
        <span className="toolbar-spacer" />
        <button className="btn secondary graph-export" onClick={() => download(JSON.stringify(graph, null, 2), 'application/json', 'json')}>JSON</button>
        <button className="btn secondary graph-export" onClick={() => download(serializedSvg(), 'image/svg+xml', 'svg')}>SVG</button>
        <button className="btn secondary graph-export" onClick={exportPng}>PNG</button>
      </div>
      <div className="graph-canvas" tabIndex={0} role="region" aria-label="Static call graph">
        <svg ref={svgRef} width={width} height={height}>
          <defs>
            <marker id="call-arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
              <path d="M0,0 L7,3 L0,6 Z" fill="var(--text-faint)" />
            </marker>
          </defs>
          {rendered.edges.map((edge) => {
            const source = positions.get(edge.source);
            const target = positions.get(edge.target);
            if (!source || !target) return null;
            const x1 = source.x + NODE_W;
            const y1 = source.y + NODE_H / 2;
            const x2 = target.x;
            const y2 = target.y + NODE_H / 2;
            const bend = Math.max(24, (x2 - x1) / 2);
            return (
              <path
                key={`${edge.source}-${edge.target}`}
                className={`call-edge ${edge.recursive ? 'recursive' : ''}`}
                d={`M${x1},${y1} C${x1 + bend},${y1} ${x2 - bend},${y2} ${x2},${y2}`}
                markerEnd="url(#call-arrow)"
              />
            );
          })}
          {rendered.nodes.map((node) => {
            const point = positions.get(node.address);
            const name = node.name.length > 20 ? `${node.name.slice(0, 19)}…` : node.name;
            const matches = needle && (node.name.toLowerCase().includes(needle) || hex(node.address).includes(needle));
            return (
              <g
                key={node.address}
                className={`call-node ${selectedAddress === node.address ? 'selected' : ''} ${matches ? 'matched' : ''}`}
                role="button"
                tabIndex={0}
                onClick={() => onSelect(node.address)}
                onKeyDown={(event) => (event.key === 'Enter' || event.key === ' ') && onSelect(node.address)}
              >
                <rect x={point.x} y={point.y} width={NODE_W} height={NODE_H} rx="5" />
                <text className="call-node-name" x={point.x + 10} y={point.y + 19}>{name}</text>
                <text className="call-node-address" x={point.x + 10} y={point.y + 36}>{hex(node.address)}</text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
