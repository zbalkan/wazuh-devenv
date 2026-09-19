# wazuh-devenv

`wazuh-devenv` provisions and maintains a local Wazuh rule and decoder development environment.

The project is moving from a cloned-repository/Bash workflow to an installable Python CLI. The CLI owns environment preparation; default Wazuh regression content is distributed independently by [wazuh-rule-tests](https://github.com/zbalkan/wazuh-rule-tests), and logtest communication is provided by [wazuhtester](https://github.com/zbalkan/wazuhtester).

## Architecture

The tooling is deliberately separated by responsibility:

| Project | Responsibility |
| --- | --- |
| `wazuhtester` | reusable Wazuh logtest library, CLI, and pytest plugin |
| `wazuh-rule-tests` | versioned pytest regression corpus for built-in Wazuh rules |
| `wazuhcoverage` | Wazuh JSON archive coverage analysis |
| `wazuh-testgen` | generation of pytest rule-test content |
| `wazuh-devenv` | environment installation, configuration, managed content, and orchestration |

## Installation

For CLI use, install `wazuh-devenv` with an isolated application installer:

```bash
pipx install wazuh-devenv
```

A development checkout can be installed with:

```bash
python -m pip install -e ".[dev]"
```

The tool supports Linux. WSL is supported because the Wazuh manager and the tool run inside Linux.

## Initialize a workspace

Create or enter a project directory and run:

```bash
mkdir my-wazuh-rules
cd my-wazuh-rules
wazuhdevenv init
```

An explicit workspace path is also accepted:

```bash
wazuhdevenv init ~/projects/my-wazuh-rules
```

`init` is an idempotent reconciliation operation. A converged host does not reinstall already-present system prerequisites or require package-repository access merely to recheck them. It currently performs the responsibilities previously implemented by `install.sh`:

- detects APT, DNF, or YUM;
- installs or verifies Wazuh Manager;
- optionally pins the requested Wazuh version;
- disables the Wazuh package repository after installation;
- creates `rules/`, `decoders/`, and `tests/`;
- creates the workspace `.venv`;
- installs pytest and the released `wazuhtester` package into that venv;
- enables JSON archive output required by the development workflow;
- disables unnecessary manager modules used by the old development profile;
- configures the Wazuh `rule_test` service for development throughput;
- applies the known rule-60000 Windows EventChannel testing transformation;
- preflights existing Wazuh rule/decoder content without mutating the workspace, treats Wazuh's `local_rules.xml` and `local_decoder.xml` as disposable installation samples, copies other non-conflicting local content during the protected apply phase, and fails closed on genuine filename/content conflicts;
- bind-mounts workspace rules and decoders into `/var/ossec/etc`;
- persists the mounts in `/etc/fstab`;
- configures ownership and permissions;
- adds the invoking user to the `wazuh` group when required;
- validates Wazuh configuration using Wazuh's own `-t` checks;
- snapshots the service/configuration/mount state plus workspace ownership and modes before stopping Wazuh, and rolls back system changes, adopted content, and workspace metadata if provisioning fails;
- starts the manager and waits for a stable logtest socket;
- initializes `~/.wazuhdevenv`;
- downloads the compatible default rule-test corpus.

The CLI is intended to be run as the developer:

```bash
wazuhdevenv init
```

It invokes `sudo` only for operations that require system privileges.

To require an exact Wazuh version:

```bash
wazuhdevenv init --wazuh-version 4.14.8
```

For development before a corpus release is available:

```bash
wazuhdevenv init --skip-corpus
```

Wazuh installs sample `local_rules.xml` and `local_decoder.xml` files. In a
workspace provisioned by `wazuh-devenv`, these samples are not treated as user
content and are never copied into the project. Users can add their own rule or
decoder files later, including files with those names if they choose.

## Workspace

User-owned content stays in the project:

```text
my-wazuh-rules/
├── .venv/
├── rules/
├── decoders/
└── tests/
```

The workspace virtual environment belongs to the project. It is deliberately separate from the private environment used by `pipx` to run `wazuhdevenv`.

## Managed state

Tool-managed state defaults to:

```text
~/.wazuhdevenv/
├── state.json
├── corpus-manifest.json
├── tests/
├── cache/
├── staging/
└── logs/
```

Override the root for CI or disposable environments with:

```bash
export WAZUHDEVENV_HOME=/path/to/state
```

Do not store custom rules, decoders, or project tests under this directory.

## Update managed tests

```bash
wazuhdevenv update
```

`update`:

1. detects the installed Wazuh version;
2. reads `wazuh-rule-tests` GitHub Release manifests;
3. selects the newest compatible corpus;
4. downloads the ZIP and its SHA-256 checksum;
5. verifies the digest;
6. rejects unsafe ZIP paths, symlinks, and special files;
7. validates that the external and embedded manifests match;
8. extracts into staging;
9. atomically activates `~/.wazuhdevenv/tests`;
10. records the active corpus in `state.json`.

Check what would be selected without modifying state:

```bash
wazuhdevenv update --check
```

`update` does not upgrade Wazuh Manager, `wazuhdevenv`, `wazuhtester`, or user content.

## Development

Run the package tests:

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

The unit suite does not alter the host Wazuh installation.

## Legacy scripts

`install.sh`, `fix_permissions.sh`, and the old scripts under `src/` are retained temporarily while the Python CLI reaches integration parity. They are not the target architecture and will be removed after the new workflow is validated end-to-end.

## License

GNU General Public License version 2 only. See [LICENSE](LICENSE).
