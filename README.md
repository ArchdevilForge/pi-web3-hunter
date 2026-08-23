# Pi Web3 Hunter

Authorized Web3 security hunting for Pi. The package adds `/hunt-web3`, typed
tool adapters, a native Pi status widget, a JSONL CLI, and a hash-chained
evidence ledger.

## Install

```bash
npm install
npm link
pi install /absolute/path/to/pi-web3-hunter
```

Run untrusted targets inside a container or VM. Host scanner execution is
disabled unless Pi starts with `--web3-host-exec`; disable Pi's unrestricted
`bash` tool so scanner commands can only use this package's allowlist:

```bash
pi --exclude-tools bash --web3-host-exec
```

The allowlist covers `forge build`, filtered `forge test`, Slither, Echidna,
Medusa, and read-only `cast code`. It never accepts an arbitrary command or
runs a script from the target repository by path.

The bundled Fizz/X-Ray helper scripts are optional advanced workflows. They
need Pi's `bash` tool, so enable them only inside the container/VM; they resolve
scripts from this installed package, never from the target's current directory.

## Interactive

```text
/hunt-web3 . --program immunefi-program --authorized
```

For a deployed contract:

```text
/hunt-web3 0x0000000000000000000000000000000000000000 --chain-id 1 --program immunefi-program --authorized
```

## Headless

```bash
pi --mode json --print --exclude-tools bash --web3-host-exec \
  "/hunt-web3 . --program immunefi-program --authorized"
pi-web3-hunter preflight --json
```

The deterministic CLI also supports `init`, `status`, `run`, `finding`,
`report`, and `verify`; run `pi-web3-hunter help` for exact arguments.

State and evidence are stored under
`${XDG_STATE_HOME:-~/.local/state}/pi-web3-hunter/runs/` with mode `0700`.
Finding files, scanner output, and reports are hash-linked in the run ledger;
`verify` fails after any recorded artifact is changed.

Use only targets and methods explicitly allowed by the bounty program. Prefer
local source tests, local forks, and testnets; the extension blocks common
private-key and broadcast commands during an active run.
