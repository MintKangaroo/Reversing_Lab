// Metadata-driven views built on the parsed BinaryInfo: overview (header + security),
// sections, symbols, imports, exports.

import { hex } from '../api.js';
import { BoolBadge, DataTable } from './common.jsx';

export function Overview({ info }) {
  const fields = [
    ['Format', info.binary_format],
    ['Architecture', `${info.architecture} (${info.bits}-bit)`],
    ['Endianness', info.endianness],
    ['Entry point', hex(info.entry_point)],
    ['File size', `${info.file_size.toLocaleString()} bytes`],
    ['SHA-256', info.sha256],
  ];
  return (
    <div>
      <div className="card">
        <div className="grid">
          {fields.map(([k, v]) => (
            <div className="kv" key={k}>
              <span className="k">{k}</span>
              <span className="v">{v}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <div className="section-title">Security mitigations</div>
        <div className="grid">
          <div className="kv"><span className="k">PIE / ASLR</span><span className="v"><BoolBadge value={info.is_pie} on="enabled" off="disabled" /></span></div>
          <div className="kv"><span className="k">NX (no-execute)</span><span className="v"><BoolBadge value={info.has_nx} on="enabled" off="disabled" /></span></div>
          <div className="kv"><span className="k">RELRO</span><span className="v"><BoolBadge value={info.has_relro} on="enabled" off="disabled" /></span></div>
        </div>
      </div>

      {Object.keys(info.extra || {}).length > 0 && (
        <div className="card">
          <div className="section-title">Format-specific</div>
          <div className="grid">
            {Object.entries(info.extra).map(([k, v]) => (
              <div className="kv" key={k}>
                <span className="k">{k}</span>
                <span className="v">{v || '—'}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export function Sections({ info }) {
  return (
    <DataTable
      rows={info.sections}
      emptyLabel="No sections."
      columns={[
        { key: 'name', header: 'Name', mono: true },
        { key: 'virtual_address', header: 'Virtual Addr', mono: true, render: (r) => hex(r.virtual_address) },
        { key: 'size', header: 'Size', mono: true, render: (r) => r.size.toLocaleString() },
        { key: 'offset', header: 'File Offset', mono: true, render: (r) => hex(r.offset) },
        { key: 'entropy', header: 'Entropy', mono: true, render: (r) => r.entropy.toFixed(2) },
        { key: 'code', header: 'Code', render: (r) => (r.contains_code ? <span className="badge on">exec</span> : <span className="badge neutral">data</span>) },
        { key: 'flags', header: 'Flags', mono: true, render: (r) => r.flags.join(' | ') },
      ]}
    />
  );
}

export function Symbols({ info }) {
  return (
    <DataTable
      rows={info.symbols}
      emptyLabel="No symbols (stripped binary?)."
      columns={[
        { key: 'name', header: 'Name', mono: true },
        { key: 'value', header: 'Value', mono: true, render: (r) => hex(r.value) },
        { key: 'size', header: 'Size', mono: true },
        { key: 'kind', header: 'Type' },
        { key: 'binding', header: 'Binding' },
        { key: 'scope', header: 'Scope', render: (r) => (r.is_exported ? <span className="badge on">export</span> : r.is_imported ? <span className="badge neutral">import</span> : '') },
      ]}
    />
  );
}

export function Imports({ info }) {
  return (
    <DataTable
      rows={info.imports}
      emptyLabel="No imports."
      columns={[
        { key: 'name', header: 'Symbol', mono: true },
        { key: 'library', header: 'Library', mono: true, render: (r) => r.library || '—' },
        { key: 'address', header: 'Address', mono: true, render: (r) => (r.address != null ? hex(r.address) : '—') },
      ]}
    />
  );
}

export function Exports({ info }) {
  return (
    <DataTable
      rows={info.exports}
      emptyLabel="No exports."
      columns={[
        { key: 'name', header: 'Symbol', mono: true },
        { key: 'address', header: 'Address', mono: true, render: (r) => hex(r.address) },
        { key: 'ordinal', header: 'Ordinal', mono: true, render: (r) => (r.ordinal != null ? r.ordinal : '—') },
      ]}
    />
  );
}
