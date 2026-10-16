# Development and remote operation

- Use the existing checkout in `/workspace/remote222`. Cloud tasks are already
  isolated; do not create a Git worktree unless the user asks for one.
- This is a Python 3.12+ standard-library project. No dependency installation is
  needed for `python3 -m remote222.client` or the test suite.
- Run `python3 -m unittest discover -s tests -v` after relevant changes. Linux tests
  do not establish that Windows desktop operations work; use the documented
  Windows smoke check when the user's Windows agent is available.
- The user requested Windows 11 control with their ordinary account privileges,
  without an approval prompt on the PC for every command. Do not add silent
  persistence, elevation, or a system service. Operate only on user-requested tasks.
- Use `REMOTE222_URL` and `REMOTE222_TOKEN` injected by environment settings.
  Inspect presence only; never print the token or include it in chat, shell
  command arguments, source files, logs, screenshots, or saved instructions.
- Before a live remote operation, run `python3 -m remote222.client info` and verify
  the expected Windows machine. Do not start a Linux agent as a replacement for
  the user's Windows computer.
- For an uncertain network result, reuse the printed request ID with the same
  action and arguments. Never blindly issue a new ID for a potentially completed
  action. For `outcome_unknown`, inspect state before repeating an operation.
- Desktop text and keys target the foreground window. Check a screenshot before
  input; account for image scaling and virtual desktop offsets when clicking.
- Keep credentials local to the PC/environment secret store. The exact tunnel
  hostname is needed before declaring a proxy secret. Never use a wildcard
  destination for the credential or disable TLS verification.
