# Configurable Security Scanner

A flexible security scanner that detects multiple types of threats based on JSON configuration files. When a new security threat emerges, simply add a new configuration file - no code changes needed!

## Quick Start

```bash
# Scan current directory for all configured threats
./security-scanner.sh

# Scan specific directory
./security-scanner.sh ~/projects

# Scan for specific threat only
./security-scanner.sh --threat shai-hulud

# Verbose output (shows safe packages too)
./security-scanner.sh --verbose
```

## How It Works

1. **Threat Configurations**: JSON files in `security-threats/` directory define what to scan for
2. **Multiple Check Types**: Each threat can check for:
   - File patterns (e.g., `setup_bun.js`, `*.malware`)
   - Directory patterns (e.g., `.truffler-cache`, `.dev-env`)
   - String markers in files (e.g., "Sha1-Hulud")
   - Package versions (vulnerable npm packages)
   - Running processes (suspicious processes)

3. **Automatic Detection**: The scanner automatically loads all `.json` files from the config directory

## Adding a New Threat

When a new security threat is discovered:

1. Create a new JSON file in `security-threats/` (e.g., `new-threat.json`)
2. Define the threat indicators (see example below)
3. Run the scanner - it will automatically detect the new threat!

### Example Threat Configuration

```json
{
  "name": "My New Threat",
  "description": "Description of the threat",
  "cve": "CVE-XXXX-XXXXX",
  "reference": "https://example.com/advisory",
  "file_patterns": [
    "suspicious-file.js",
    "*.malware"
  ],
  "directory_patterns": [
    ".suspicious-dir"
  ],
  "string_markers": [
    "malware signature",
    "suspicious string"
  ],
  "process_patterns": [
    "malware-process"
  ],
  "packages": [
    "vulnerable-package"
  ],
  "vulnerable_versions": [
    "1.0.0",
    "1.1.0"
  ],
  "patched_versions": [
    "1.0.1",
    "1.1.1"
  ],
  "remediation": [
    "Step 1: Do this",
    "Step 2: Do that"
  ]
}
```

## Current Threats Configured

- **Shai-Hulud 2.0**: npm supply chain malware (file/directory/string markers)
- **RSC Vulnerability**: React Server Components RCE (package version checks)

## Exit Codes

- `0`: No security issues detected
- `1`: Error (invalid config, missing files, etc.)
- `2`: Security issues detected

## Requirements

- `bash` 4.0+
- Standard Unix tools: `find`, `grep`, `ps`
- `jq` (optional, but recommended for better JSON parsing)
- `yq` (optional, for better pnpm-lock.yaml parsing)

## Package Manager Support

The scanner automatically detects and supports multiple package managers:

- **npm** - Reads from `package-lock.json`
- **yarn** - Reads from `yarn.lock` (v1 and v2+)
- **pnpm** - Reads from `pnpm-lock.yaml`

### Detection Order

1. Checks for lock files: `pnpm-lock.yaml` > `yarn.lock` > `package-lock.json`
2. Falls back to `package.json` `packageManager` field if present
3. If multiple lock files exist, uses the first found in priority order above

The scanner will automatically use the appropriate lock file format for version extraction.

### Version Detection Strategy

The scanner checks for package versions in this order:

1. **Root lock files** (package-lock.json, yarn.lock, pnpm-lock.yaml)
2. **Monorepo workspaces** (checks lock files in workspace subdirectories)
3. **Local node_modules** (reads package.json from installed packages)
   - Checks root node_modules
   - Checks node_modules in workspace directories
4. **Global caches** (only when `--check-global` or `--verbose` is used)
   - npm: `~/.npm` or `npm config get cache`
   - yarn: `~/.yarn/cache` or `yarn cache dir`
   - pnpm: `~/.pnpm-store` or `pnpm store path`

### Monorepo Support

The scanner automatically detects and scans monorepos:

- **npm/yarn workspaces**: Detects `workspaces` field in root `package.json`
- **pnpm workspaces**: Detects `pnpm-workspace.yaml` configuration
- **Fallback detection**: Finds all `package.json` files in subdirectories (max depth 4)

For each workspace, the scanner checks:
- Workspace-specific lock files
- Workspace-specific `node_modules` directories
- Workspace `package.json` files

In verbose mode, the scanner reports the number of detected workspaces.

### Global Cache Checking

Global cache checking can be configured in two ways:

1. **Per-threat configuration** (recommended): Add `"check_global_cache": true` to the threat JSON file
2. **Command-line flag**: Use `--check-global` to enable for all threats
3. **Verbose mode**: Automatically enabled when using `--verbose`

**Per-threat configuration example:**
```json
{
  "name": "My Threat",
  "check_global_cache": true,
  "packages": ["vulnerable-package"]
}
```

**Command-line override:**
```bash
./security-scanner.sh --check-global
```

This is useful when:
- Packages are installed globally
- Using workspaces/monorepos with shared dependencies
- Packages might be in cache but not in local lock files
- Specific threats require global cache checking

## Configuration Directory

Default: `./security-threats/`

Override with `--config-dir`:
```bash
./security-scanner.sh --config-dir /path/to/threats
```

## Examples

```bash
# Scan for all threats
./security-scanner.sh

# Scan only for Shai-Hulud
./security-scanner.sh --threat shai-hulud

# Scan multiple directories
./security-scanner.sh ~/project1 ~/project2

# Verbose mode (shows all checks, including safe packages and monorepo info)
./security-scanner.sh --verbose

# Check global package manager caches
./security-scanner.sh --check-global

# Scan monorepo (automatically detects workspaces)
./security-scanner.sh ~/monorepo

# Combine options
./security-scanner.sh --verbose --check-global ~/projects

# Custom config directory
./security-scanner.sh --config-dir ./my-threats ~/projects
```

## Integration

### CI/CD Pipeline

```yaml
# Example GitHub Actions
- name: Security Scan
  run: |
    chmod +x security-scanner.sh
    ./security-scanner.sh || exit 1
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit
./security-scanner.sh
if [ $? -eq 2 ]; then
    echo "Security issues detected! Commit blocked."
    exit 1
fi
```

## Benefits

✅ **No Code Changes**: Add new threats by creating JSON config files  
✅ **Unified Interface**: One script for all security checks  
✅ **Easy Maintenance**: Update threat definitions without touching code  
✅ **Extensible**: Add new check types by extending the scanner  
✅ **CI/CD Ready**: Exit codes work with automation tools  

## See Also

- `security-threats/README.md` - Detailed configuration guide
- `security-threats/*.json` - Example threat configurations

