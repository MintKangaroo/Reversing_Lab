import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryWorkspace } from '../components/MemoryWorkspace.jsx';
import { api } from '../api.js';

vi.mock('../api.js', () => ({
  api: {
    toolingDetail: vi.fn(),
    uploadMemoryDump: vi.fn(),
    startMemoryAnalysis: vi.fn(),
    job: vi.fn(),
    cancelJob: vi.fn(),
    memorySummary: vi.fn(),
    memoryProcesses: vi.fn(),
    memoryModules: vi.fn(),
    memoryRegions: vi.fn(),
    inspectMemoryRegion: vi.fn(),
    memoryRegionArtifacts: vi.fn(),
    memoryRegionHex: vi.fn(),
    memoryRegionDisassembly: vi.fn(),
    downloadMemoryRegionArtifact: vi.fn(),
    memoryNetwork: vi.fn(),
    memoryFindings: vi.fn(),
  },
  hex: (value) => `0x${Number(value).toString(16)}`,
}));

beforeEach(() => {
  vi.clearAllMocks();
  api.toolingDetail.mockResolvedValue({ name: 'volatility3', available: true });
  api.uploadMemoryDump.mockResolvedValue({
    id: 'dump-1',
    filename: 'authorized.dmp',
    dump_format: 'windows-memory-dump',
    size: 4096,
    sha256: 'a'.repeat(64),
  });
  api.startMemoryAnalysis.mockResolvedValue({
    id: 'job-1', state: 'queued', progress: 0, message: 'Queued', error: null,
  });
  api.job.mockImplementation((id) => Promise.resolve(id === 'region-job-1' ? {
    id, state: 'completed', progress: 100, message: 'Inspection complete', error: null, result_ref: 'artifact-1',
  } : {
    id, state: 'completed', progress: 100, message: 'Completed', error: null,
  }));
  api.memorySummary.mockResolvedValue({
    provider: 'volatility3',
    metadata: { os_guess: 'Windows' },
    process_count: 1,
    module_count: 1,
    region_count: 1,
    network_count: 1,
    string_count: 4,
    urls: [],
    ip_addresses: [],
    domains: [],
    finding_count: 1,
    unavailable: ['thread details'],
    warnings: ['netscan unavailable'],
  });
  api.memoryProcesses.mockResolvedValue({
    items: [{
      pid: 44, ppid: 4, name: 'fixture.exe', thread_count: 2, module_count: 1,
      tree_depth: 1, orphaned: false,
      source_provider: 'volatility3',
    }],
    total: 1,
  });
  api.memoryModules.mockResolvedValue({
    items: [{
      pid: 44, base_address: 0x140000000, base_address_hex: '0x140000000', size: 8192, name: 'fixture.exe',
      path: 'C:\\fixture.exe', source_provider: 'volatility3',
    }],
    total: 1,
  });
  api.memoryRegions.mockResolvedValue({
    items: [{
      pid: 44, start: 0x1000, end: 0x1fff, start_hex: '0x1000', end_hex: '0x1fff', protection: 'PAGE_EXECUTE_READWRITE',
      private_memory: true, mapped_file: null, suspicious: true,
      reason: 'Writable and executable memory region (heuristic).',
      source_provider: 'volatility3',
    }],
    total: 1,
  });
  api.memoryNetwork.mockResolvedValue({
    items: [{
      pid: 44, process_name: 'fixture.exe', protocol: 'TCPV4',
      local_address: '10.0.0.5', local_port: 51514,
      remote_address: '1.1.1.1', remote_port: 443,
      state: 'ESTABLISHED', created_at: '2026-08-09 03:00:00',
      offset_hex: '0xffff800000002000', source_provider: 'volatility3',
    }],
    total: 1,
  });
  api.memoryFindings.mockResolvedValue([{ id: 'finding-1', title: 'Writable and executable memory region', severity: 'high', confidence: 0.9, summary: 'Review this region.', evidence: ['PID 44 at 0x1000.'], false_positive_note: 'JIT runtimes may create this mapping.' }]);
  api.inspectMemoryRegion.mockResolvedValue({
    id: 'region-job-1', state: 'queued', progress: 0, message: 'Queued', error: null,
  });
  api.memoryRegionArtifacts.mockResolvedValue([{
    id: 'artifact-1', pid: 44, start_hex: '0x1000', end_hex: '0x1fff',
    architecture: 'x86_64', size: 4096, content_sha256: 'b'.repeat(64), provider: 'volatility3',
  }]);
  api.memoryRegionHex.mockResolvedValue({
    offset: 0, length: 16, total_size: 4096, base_address_hex: '0x1000',
    rows: [{ offset: 0, address_hex: '0x1000', hex_bytes: ['48', '31', 'c0', 'c3'], ascii: 'H1..' }],
  });
  api.memoryRegionDisassembly.mockResolvedValue({
    architecture: 'x86_64', instruction_count: 2, truncated: false,
    instructions: [
      { address_hex: '0x1000', bytes_hex: '4831c0', mnemonic: 'xor', op_str: 'rax, rax' },
      { address_hex: '0x1003', bytes_hex: 'c3', mnemonic: 'ret', op_str: '' },
    ],
  });
});

it('loads normalized Volatility modules, regions, warnings, and evidence', async () => {
  const { container } = render(<MemoryWorkspace />);
  const input = container.querySelector('input[type="file"]');
  fireEvent.change(input, {
    target: { files: [new File(['PAGEDUMP'], 'authorized.dmp')] },
  });

  expect(await screen.findByText('authorized.dmp')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Start analysis' }));

  expect(await screen.findByText('netscan unavailable', {}, { timeout: 2000 })).toBeVisible();
  expect(api.memoryModules).toHaveBeenCalledWith('dump-1');
  expect(api.memoryNetwork).toHaveBeenCalledWith('dump-1');

  fireEvent.click(screen.getByRole('button', { name: 'processes (1)' }));
  expect(screen.getByText('↳ fixture.exe')).toBeVisible();

  fireEvent.click(screen.getByRole('button', { name: 'modules (1)' }));
  expect(screen.getByText('0x140000000')).toBeVisible();
  expect(screen.getAllByText('fixture.exe').length).toBeGreaterThan(0);

  fireEvent.click(screen.getByRole('button', { name: 'regions (1)' }));
  expect(screen.getByText('PAGE_EXECUTE_READWRITE')).toBeVisible();
  expect(screen.getByText(/Writable and executable memory region/)).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Review' }));
  const acknowledgement = screen.getByRole('checkbox', { name: /I understand this creates/ });
  const inspect = screen.getByRole('button', { name: 'Extract & inspect' });
  expect(inspect).toBeDisabled();
  fireEvent.click(acknowledgement);
  expect(inspect).toBeEnabled();
  fireEvent.click(inspect);
  await waitFor(() => expect(api.inspectMemoryRegion).toHaveBeenCalledWith(
    'dump-1', expect.objectContaining({ pid: 44, start: 0x1000 }), 'x86_64',
  ));
  expect(await screen.findByText('Region artifact ready', {}, { timeout: 2000 })).toBeVisible();
  expect(screen.getByText('rax, rax')).toBeVisible();

  fireEvent.click(screen.getByRole('button', { name: 'network (1)' }));
  expect(screen.getByText('1.1.1.1:443')).toBeVisible();
  fireEvent.change(screen.getByLabelText('Filter network by keyword'), {
    target: { value: '1.1.1.1' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
  await waitFor(() => expect(api.memoryNetwork).toHaveBeenLastCalledWith('dump-1', {
    keyword: '1.1.1.1',
  }));

  fireEvent.click(screen.getByRole('button', { name: 'findings (1)' }));
  fireEvent.click(screen.getByText('Evidence (1)'));
  await waitFor(() => expect(screen.getByText(/PID 44 at 0x1000/)).toBeVisible());
});
