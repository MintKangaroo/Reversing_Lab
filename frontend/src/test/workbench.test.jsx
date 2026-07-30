import { fireEvent, render, screen } from '@testing-library/react';
import { WorkbenchShell } from '../components/WorkbenchShell.jsx';

it('supports keyboard resizing for analysis panels', () => {
  render(
    <WorkbenchShell
      header="header"
      navigation="nav"
      explorer="explorer"
      workspace="workspace"
      inspector="inspector"
      bottom="bottom"
    />,
  );
  const splitter = screen.getByRole('separator', { name: 'Resize project explorer' });
  expect(splitter).toHaveAttribute('aria-valuenow', '272');
  fireEvent.keyDown(splitter, { key: 'ArrowRight' });
  expect(splitter).toHaveAttribute('aria-valuenow', '284');
});
