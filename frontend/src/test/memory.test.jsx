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
    memoryHandles: vi.fn(),
    memoryThreads: vi.fn(),
    memoryRegions: vi.fn(),
    inspectMemoryRegion: vi.fn(),
    memoryRegionArtifacts: vi.fn(),
    memoryRegionHex: vi.fn(),
    memoryRegionDisassembly: vi.fn(),
    downloadMemoryRegionArtifact: vi.fn(),
    memoryNetwork: vi.fn(),
    memoryFindings: vi.fn(),
    downloadMemoryReport: vi.fn(),
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
    handle_count: 1,
    thread_count: 1,
    string_count: 4,
    urls: [],
    ip_addresses: [],
    domains: [],
    finding_count: 1,
    unavailable: ['environment variables'],
    warnings: ['netscan unavailable'],
  });
  api.memoryProcesses.mockResolvedValue({
    items: [{
      pid: 44, ppid: 4, name: 'fixture.exe', thread_count: 2, module_count: 1,
      tree_depth: 1, orphaned: false,
      command_line: 'C:\\fixture.exe --authorized-test',
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
  api.memoryHandles.mockResolvedValue({
    items: [{
      pid: 44, process_name: 'fixture.exe', object_type: 'File',
      object_offset_hex: '0xffff800000003000', handle_value_hex: '0x88',
      granted_access_hex: '0x12019f', name: '\\Device\\HarddiskVolume3\\fixture.bin',
      source_provider: 'volatility3',
    }],
    total: 1,
  });
  api.memoryThreads.mockResolvedValue({
    items: [{
      pid: 44, tid: 88, process_name: 'fixture.exe',
      object_offset_hex: '0xffff800000004000',
      start_address_hex: '0xfffff80000100000', start_path: 'ntoskrnl.exe',
      win32_start_address_hex: '0x180001000', win32_start_path: 'fixture.exe',
      create_time: '2026-08-12 09:00:00', exit_time: null,
      source_provider: 'volatility3',
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
  api.memoryRegionArtifacts.mockResolvedValue({
    items: [{
      id: 'artifact-1', pid: 44, start_hex: '0x1000', end_hex: '0x1fff',
      architecture: 'x86_64', size: 4096, content_sha256: 'b'.repeat(64), provider: 'volatility3',
    }],
    total: 1, offset: 0, limit: 200,
  });
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
  expect(api.memoryHandles).toHaveBeenCalledWith('dump-1');
  expect(api.memoryThreads).toHaveBeenCalledWith('dump-1');
  expect(api.memoryNetwork).toHaveBeenCalledWith('dump-1');

  fireEvent.click(screen.getByRole('button', { name: 'processes (1)' }));
  expect(screen.getByText('↳ fixture.exe')).toBeVisible();
  expect(screen.getByText('C:\\fixture.exe --authorized-test')).toBeVisible();

  fireEvent.click(screen.getByRole('button', { name: 'threads (1)' }));
  expect(screen.getByText('0xffff800000004000')).toBeVisible();
  expect(screen.getByText('0x180001000')).toBeVisible();
  fireEvent.change(screen.getByLabelText('Filter threads by TID'), {
    target: { value: '88' },
  });
  fireEvent.change(screen.getByLabelText('Filter threads by keyword'), {
    target: { value: 'fixture.exe' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
  await waitFor(() => expect(api.memoryThreads).toHaveBeenLastCalledWith('dump-1', {
    tid: '88',
    keyword: 'fixture.exe',
  }));

  fireEvent.click(screen.getByRole('button', { name: 'modules (1)' }));
  expect(screen.getByText('0x140000000')).toBeVisible();
  expect(screen.getAllByText('fixture.exe').length).toBeGreaterThan(0);

  fireEvent.click(screen.getByRole('button', { name: 'handles (1)' }));
  expect(screen.getByText('0xffff800000003000')).toBeVisible();
  expect(screen.getByText('0x12019f')).toBeVisible();
  fireEvent.change(screen.getByLabelText('Filter handles by object type'), {
    target: { value: 'File' },
  });
  fireEvent.change(screen.getByLabelText('Filter handles by keyword'), {
    target: { value: 'fixture.bin' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
  await waitFor(() => expect(api.memoryHandles).toHaveBeenLastCalledWith('dump-1', {
    object_type: 'File',
    keyword: 'fixture.bin',
  }));

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

it('exports the completed memory analysis as a report', async () => {
  const { container } = render(<MemoryWorkspace />);
  fireEvent.change(container.querySelector('input[type="file"]'), {
    target: { files: [new File(['PAGEDUMP'], 'authorized.dmp')] },
  });
  expect(await screen.findByText('authorized.dmp')).toBeVisible();
  fireEvent.click(screen.getByRole('button', { name: 'Start analysis' }));

  const markdown = await screen.findByRole('button', { name: 'Export MARKDOWN' }, { timeout: 2000 });
  fireEvent.click(markdown);
  await waitFor(() => expect(api.downloadMemoryReport).toHaveBeenCalledWith('dump-1', 'markdown'));
});
