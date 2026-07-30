import { useEffect, useState } from 'react';
import { api } from '../api.js';
import { ErrorBanner, Loading } from './common.jsx';

const FLOW_GROUPS = new Set(['jump', 'call', 'ret', 'return']);

export function DisasmTab({ sha, address = null, onAddressSelect = () => {} }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    setLoading(true);
    api
      [address == null ? 'disassembly' : 'functionDisassembly'](sha, address == null ? 300 : address)
      .then((d) => active && (setData(d), setError(null)))
      .catch((e) => active && setError(e.message))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [sha, address]);

  if (loading) return <Loading />;
  if (error) return <ErrorBanner error={error} />;

  return (
    <div>
      <div className="toolbar">
        <span className="muted">
          Entry {`0x${data.start_address.toString(16)}`} · {data.instruction_count} instructions
          {data.truncated ? ' (truncated)' : ''}
        </span>
      </div>
      <div className="card disasm">
        {data.instructions.map((insn) => {
          const isFlow = insn.groups.some((g) => FLOW_GROUPS.has(g));
          return (
            <button className="row instruction-row" key={insn.address} onClick={() => onAddressSelect(insn.address)}>
              <span className="addr">{`0x${insn.address.toString(16)}`}</span>
              <span className="bytes">{insn.bytes_hex}</span>
              <span>
                <span className={isFlow ? 'flow' : 'mnemonic'}>{insn.mnemonic}</span>{' '}
                {insn.op_str}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
