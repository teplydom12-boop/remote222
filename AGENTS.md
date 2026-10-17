# Development and remote operation

- Use the existing checkout in `/workspace/remote222`. Cloud tasks are already
  isolated; do not create a Git worktree unless the user asks for one.
- This is a Python 3.12+ standard-library project. No dependency installation is
  needed for `python3 -m remote222.client` or the test suite.
- Windows users normally run the single-file Remote222.exe from GitHub Releases.
  The default queue mode uses an account on the user's HTTPS broker. The user
  enters their username and password locally in Windows; the EXE saves a
  URL-bound session, never the password. Stop/close retains that sign-in;
  Logout requests revocation and removes it locally. An already running command
  can still finish after Stop. No autostart, elevation, or Windows service.
- For this workspace use the explicit controller profile
  `/workspace/.remote222-controller/session.json` outside the repository.
  After the VPS account upgrade and live HTTPS check, connect with:
  `python3 -m remote222.client --url https://95-163-231-24.sslip.io --session-file /workspace/.remote222-controller/session.json connect`.
  Show the user the printed `/connect` URL and short approval code. The user
  signs in and approves in their own browser; never request their password.
  Do not read, print, upload, or commit the session file or its bearer token.
- All subsequent operations must specify
  `--session-file /workspace/.remote222-controller/session.json` before the
  subcommand. This selects the saved URL and account session and ignores stale
  `REMOTE222_URL`, `REMOTE222_TOKEN`, and `REMOTE222_TRANSPORT` values. No cloud
  secret binding is needed for account mode. A replaced workspace or expired or
  revoked session requires a new browser approval. Check `session` for sign-in
  status; this does not check the Windows computer.
- At the start of a remote-control turn, or after reconnecting, run
  `python3 -m remote222.client --session-file /workspace/.remote222-controller/session.json info`
  and verify the expected Windows machine. Prepared browser commands also verify
  the approved machine within their operation; do not add redundant info and
  status round trips before each such command. A broker heartbeat is insufficient.
  Do not start a Linux agent as a substitute for the user's Windows computer.
- The account hostname resolves to VPS `95.163.231.24`; DNS alone does not prove
  that HTTPS, the account upgrade, or Windows connectivity works. Follow
  `docs/vps-account.md` for the existing VPS upgrade. Do not claim it is deployed
  without live evidence. Use only explicitly allowed network destinations and
  keep TLS verification enabled. Changing transport does not guarantee no 403.
- The user authorized ordinary Windows account privileges without confirmation
  for each command. Operate only on user-requested tasks. For uncertain network
  results, reuse the printed request ID with the same action and arguments.
  Never blindly issue a new ID for an action that may have completed. For
  `outcome_unknown`, inspect state before repeating an operation.
- The user requires code-based operation and observation: prefer system APIs,
  PowerShell, browser CDP/DOM and accessibility APIs. Do not take screenshots or
  use coordinate clicks unless the user explicitly requests that approach.
  Use the verified installed Google Chrome executable, rather than assuming the
  default-browser registration is Chrome. Reuse its dedicated automation profile
  and target; do not restart or modify the user's ordinary browser profile.
- Use the prepared `python3 -m remote222.browser` commands documented in
  `docs/browser-control.md` for routine browser work. Keep its private state at
  `/workspace/.remote222-controller/browser-state.json`. Install the helper once,
  reuse the approved Chrome profile, and combine navigation, readiness and export
  with `save --url ...` when appropriate. Do not construct a new CDP implementation
  or launch a new browser for each request. Ordinary shell/file/program operations
  remain available through `remote222.client`.
- The old direct Cloudflare mode remains available. Only for that mode use
  injected `REMOTE222_URL` and `REMOTE222_TOKEN`, and pass `--transport direct`.
  Inspect secret presence only; never print credentials or copy them into chat,
  shell arguments, source, logs, screenshots, or saved instructions. Restrict a
  legacy proxy secret to the exact destination hostname, never a wildcard.
- Build on Windows via `scripts/build_windows.py`, `requirements-build.txt`, or
  `.github/workflows/windows-exe.yml`. Never substitute a Linux binary for the
  Windows EXE or bypass the pinned cloudflared checksum. Run
  `python3 -m unittest discover -s tests -v` after relevant code changes. Linux
  checks do not establish Windows desktop behavior. The Windows workflow must
  run integration tests and the frozen EXE self-test before publishing; verify
  the user's actual desktop separately after connecting.
