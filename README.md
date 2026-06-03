# MCP Security Linter

A small TypeScript CLI that scans MCP JSON configuration files for risky server entries before you share them or run them locally.

It looks for:

- inline secret values in `env`
- broad filesystem access such as `/`, `C:\`, `--allow-all`, or `--root=/`
- shell wrappers such as `bash -c`, `cmd /c`, and `powershell -Command`
- destructive or remote-code-execution command patterns such as `curl ... | bash`

## Install

```bash
npm install -g mcp-security-linter
```

Or run from source:

```bash
npm install
npm run build
node dist/cli.js ./mcp.json
```

## Usage

```bash
mcpsec ./mcp.json
mcpsec ~/.cursor/mcp.json --fail-on medium
mcpsec . --format json
```

By default, the CLI exits with code `1` only for high severity findings. Use `--fail-on medium` or `--fail-on low` to make CI stricter.

Try the included risky fixture:

```bash
npm run build
node dist/cli.js examples/risky-mcp.json --fail-on medium
```

## GitHub Action

The repository includes a CI example at `examples/github-actions-ci.yml`.

```yaml
name: MCP config security

on:
  pull_request:
  push:
    branches: [main]

jobs:
  mcp-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm install -g mcp-security-linter
      - run: mcpsec . --fail-on medium
```

## Development

```bash
npm install
npm test
npm run build
```

## License

MIT
