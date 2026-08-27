import { render, screen } from '@testing-library/react';
import { Overview } from '../components/BinaryTabs.jsx';

const baseInfo = {
  binary_format: 'ELF',
  architecture: 'X86_64',
  bits: 64,
  endianness: 'little',
  entry_point: 0x401000,
  file_size: 4096,
  sha256: 'a'.repeat(64),
  is_pie: true,
  has_nx: true,
  has_relro: true,
  extra: {},
};

describe('Overview security mitigations', () => {
  it('renders the richer mitigation set with a build id and overlay size', () => {
    render(
      <Overview
        info={{
          ...baseInfo,
          mitigations: {
            stack_canary: true,
            control_flow_guard: null,
            signed: false,
            has_debug_info: false,
            build_id: 'deadbeef',
            tls: false,
            overlay_size: 512,
          },
        }}
      />,
    );
    expect(screen.getByText('Security mitigations')).toBeVisible();
    // Undetermined CFG renders as a neutral n/a badge, not a false "disabled".
    expect(screen.getByText('n/a')).toHaveClass('badge', 'neutral');
    expect(screen.getByText('deadbeef')).toBeVisible();
    expect(screen.getByText('512 bytes')).toBeVisible();
  });

  it('omits the build id row when absent', () => {
    render(<Overview info={{ ...baseInfo, mitigations: { overlay_size: 0 } }} />);
    expect(screen.queryByText('Build ID')).toBeNull();
    // A zero overlay reads as a clean "none".
    expect(screen.getByText('none')).toHaveClass('badge', 'on');
  });
});
