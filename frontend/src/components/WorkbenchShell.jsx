import { useEffect, useState } from 'react';

const MIN_LEFT = 210;
const MAX_LEFT = 460;
const MIN_RIGHT = 230;
const MAX_RIGHT = 440;
const MIN_BOTTOM = 110;
const MAX_BOTTOM = 360;

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function useStoredNumber(key, initial) {
  const [value, setValue] = useState(() => {
    const stored = Number(window.localStorage.getItem(key));
    return Number.isFinite(stored) && stored > 0 ? stored : initial;
  });

  useEffect(() => {
    window.localStorage.setItem(key, String(value));
  }, [key, value]);

  return [value, setValue];
}

function Splitter({ orientation, value, onChange, min, max, invert = false, label }) {
  function begin(event) {
    event.preventDefault();
    const startCursor = orientation === 'vertical' ? event.clientX : event.clientY;
    const startValue = value;
    document.body.classList.add('is-resizing');

    const move = (moveEvent) => {
      const cursor = orientation === 'vertical' ? moveEvent.clientX : moveEvent.clientY;
      const delta = (cursor - startCursor) * (invert ? -1 : 1);
      onChange(clamp(startValue + delta, min, max));
    };
    const finish = () => {
      document.body.classList.remove('is-resizing');
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', finish);
    };

    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', finish);
  }

  function adjust(event) {
    const decrease = event.key === 'ArrowLeft' || event.key === 'ArrowUp';
    const increase = event.key === 'ArrowRight' || event.key === 'ArrowDown';
    if (!decrease && !increase) return;
    event.preventDefault();
    const direction = decrease ? -1 : 1;
    onChange(clamp(value + direction * (event.shiftKey ? 40 : 12) * (invert ? -1 : 1), min, max));
  }

  return (
    <div
      className={`splitter splitter-${orientation}`}
      role="separator"
      aria-label={label}
      aria-orientation={orientation}
      aria-valuemin={min}
      aria-valuemax={max}
      aria-valuenow={Math.round(value)}
      tabIndex={0}
      onPointerDown={begin}
      onKeyDown={adjust}
    />
  );
}

export function WorkbenchShell({
  header,
  navigation,
  explorer,
  workspace,
  inspector,
  bottom,
}) {
  const [leftWidth, setLeftWidth] = useStoredNumber('rlab.panel.left', 272);
  const [rightWidth, setRightWidth] = useStoredNumber('rlab.panel.right', 292);
  const [bottomHeight, setBottomHeight] = useStoredNumber('rlab.panel.bottom', 178);

  return (
    <div
      className="app-frame"
      style={{
        '--left-panel': `${leftWidth}px`,
        '--right-panel': `${rightWidth}px`,
        '--bottom-panel': `${bottomHeight}px`,
      }}
    >
      <header className="global-header">{header}</header>
      <div className="workbench-grid">
        <nav className="activity-bar" aria-label="Primary navigation">{navigation}</nav>
        <aside className="explorer-panel" aria-label="Project explorer">{explorer}</aside>
        <Splitter
          orientation="vertical"
          value={leftWidth}
          onChange={setLeftWidth}
          min={MIN_LEFT}
          max={MAX_LEFT}
          label="Resize project explorer"
        />
        <main className="workspace-panel">{workspace}</main>
        <Splitter
          orientation="vertical"
          value={rightWidth}
          onChange={setRightWidth}
          min={MIN_RIGHT}
          max={MAX_RIGHT}
          invert
          label="Resize inspector"
        />
        <aside className="inspector-panel" aria-label="Analysis inspector">{inspector}</aside>
        <Splitter
          orientation="horizontal"
          value={bottomHeight}
          onChange={setBottomHeight}
          min={MIN_BOTTOM}
          max={MAX_BOTTOM}
          invert
          label="Resize activity panel"
        />
        <section className="bottom-panel" aria-label="Activity and findings">{bottom}</section>
      </div>
    </div>
  );
}
