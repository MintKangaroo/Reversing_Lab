import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { Empty, ErrorBanner, Loading } from './common.jsx';

// Simple, dependency-free layered layout: blocks are stacked in a single column in id
// order (which follows address order), and edges are drawn as bezier curves — forward
// edges down the centre, back-edges routed around the right gutter.
const BOX_WIDTH = 380;
const BOX_X = 60;
const LINE_H = 16;
const TITLE_H = 26;
const PAD = 10;
const GAP = 46;
const MAX_INSN = 12; // cap rows drawn per block to keep the graph readable

function layout(blocks) {
  const positions = new Map();
  let y = 20;
  for (const block of blocks) {
    const shown = Math.min(block.instructions.length, MAX_INSN);
    const height = TITLE_H + shown * LINE_H + PAD * 2;
    positions.set(block.id, { x: BOX_X, y, width: BOX_WIDTH, height, shown });
    y += height + GAP;
  }
  return { positions, totalHeight: y };
}

function edgePath(from, to) {
  const startX = from.x + from.width / 2;
  const startY = from.y + from.height;
  const endX = to.x + to.width / 2;
  const endY = to.y;
  if (endY >= startY) {
    // Forward edge: gentle S-curve straight down.
    const midY = (startY + endY) / 2;
    return `M ${startX} ${startY} C ${startX} ${midY}, ${endX} ${midY}, ${endX} ${endY}`;
  }
  // Back edge: bow out to the right gutter.
  const gutter = BOX_X + BOX_WIDTH + 50;
  return `M ${from.x + from.width} ${from.y + from.height / 2} C ${gutter} ${startY}, ${gutter} ${endY}, ${to.x + to.width} ${to.y + to.height / 2}`;
}

export function CfgTab({ sha }) {
  const [cfg, setCfg] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    setLoading(true);
    api
      .cfg(sha)
      .then((d) => active && (setCfg(d), setError(null)))
      .catch((e) => active && setError(e.message))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [sha]);

  if (loading) return <Loading />;
  if (error) return <ErrorBanner error={error} />;
  if (!cfg.blocks.length) return <Empty label="No control flow recovered for this region." />;

  const { positions, totalHeight } = layout(cfg.blocks);
  const svgWidth = BOX_X + BOX_WIDTH + 120;

  return (
    <div>
      <div className="toolbar">
        <span className="muted">
          Entry {`0x${cfg.entry_address.toString(16)}`} · {cfg.blocks.length} basic blocks · {cfg.edges.length} edges
        </span>
      </div>
      <div className="card" style={{ overflow: 'auto', maxHeight: '72vh' }}>
        <svg width={svgWidth} height={totalHeight} style={{ display: 'block' }}>
          <defs>
            <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
              <path d="M0,0 L6,3 L0,6 Z" fill="#8b949e" />
            </marker>
          </defs>

          {cfg.blocks.map((block) =>
            block.successors.map((succId, idx) => {
              const from = positions.get(block.id);
              const to = positions.get(succId);
              if (!from || !to) return null;
              const cls = block.successors.length > 1 ? (idx === 0 ? 'cfg-edge cfg-edge-taken' : 'cfg-edge cfg-edge-fall') : 'cfg-edge';
              return <path key={`${block.id}-${succId}`} className={cls} d={edgePath(from, to)} markerEnd="url(#arrow)" />;
            }),
          )}

          {cfg.blocks.map((block) => {
            const p = positions.get(block.id);
            return (
              <g key={block.id}>
                <rect className="cfg-block" x={p.x} y={p.y} width={p.width} height={p.height} rx="6" />
                <text className="cfg-block-title" x={p.x + PAD} y={p.y + 17}>
                  block {block.id} @ 0x{block.start_address.toString(16)}
                </text>
                {block.instructions.slice(0, p.shown).map((insn, i) => (
                  <text key={insn.address} className="cfg-insn" x={p.x + PAD} y={p.y + TITLE_H + PAD + i * LINE_H + 4}>
                    {`0x${insn.address.toString(16)}`}  {insn.text}
                  </text>
                ))}
                {block.instructions.length > p.shown && (
                  <text className="cfg-insn" x={p.x + PAD} y={p.y + TITLE_H + PAD + p.shown * LINE_H + 4} fill="#8b949e">
                    … {block.instructions.length - p.shown} more
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
