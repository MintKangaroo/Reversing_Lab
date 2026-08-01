import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { AuthGate } from '../components/AuthGate.jsx';
import { api } from '../api.js';

vi.mock('../api.js', () => ({
  api: {
    setApiKey: vi.fn(),
    clearApiKey: vi.fn(),
    authMe: vi.fn(),
  },
}));

beforeEach(() => vi.clearAllMocks());

it('authenticates without persisting the raw key in browser storage', async () => {
  const principal = {
    id: 'analyst-one',
    role: 'analyst',
    authentication_enabled: true,
  };
  const onAuthenticated = vi.fn();
  api.authMe.mockResolvedValue(principal);
  render(<AuthGate onAuthenticated={onAuthenticated} />);

  fireEvent.change(screen.getByLabelText('Bearer API key'), {
    target: { value: 'one-use-tab-secret' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Unlock workbench' }));

  await waitFor(() => expect(onAuthenticated).toHaveBeenCalledWith(principal));
  expect(api.setApiKey).toHaveBeenCalledWith('one-use-tab-secret');
  expect(window.localStorage).toHaveLength(0);
});

it('forgets a rejected key and presents the backend error', async () => {
  api.authMe.mockRejectedValue(new Error('Bearer API key is invalid.'));
  render(<AuthGate onAuthenticated={vi.fn()} />);

  fireEvent.change(screen.getByLabelText('Bearer API key'), {
    target: { value: 'rejected-key' },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Unlock workbench' }));

  expect(await screen.findByRole('alert')).toHaveTextContent('Bearer API key is invalid.');
  expect(api.clearApiKey).toHaveBeenCalledOnce();
});
