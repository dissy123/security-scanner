# Security Threat Configurations

This directory contains JSON configuration files that define security threats to scan for.

## Adding a New Threat

Create a new JSON file (e.g., `my-threat.json`) with the following structure:

```json
{
  "name": "Threat Name",
  "description": "Brief description of the threat",
  "cve": "CVE-XXXX-XXXXX (optional)",
  "reference": "URL to advisory or documentation",
  "file_patterns": [
    "suspicious-file.js",
    "*.malware"
  ],
  "directory_patterns": [
    ".suspicious-dir",
    "malware-*"
  ],
  "string_markers": [
    "suspicious string",
    "malware signature"
  ],
  "process_patterns": [
    "malware-process",
    "suspicious.*"
  ],
  "packages": [
    "vulnerable-package",
    "@scope/package"
  ],
  "vulnerable_versions": [
    "1.0.0",
    "1.1.0"
  ],
  "patched_versions": [
    "1.0.1",
    "1.1.1"
  ],
  "min_vulnerable_version": "1.0.0",
  "remediation": [
    "Step 1: Do this",
    "Step 2: Do that",
    "Step 3: Contact security team"
  ]
}
```

## Configuration Fields

### Required Fields
- **name**: Display name of the threat
- **description**: Brief description

### Optional Fields

#### Global Cache Checking
- **check_global_cache**: Boolean (true/false) - Whether to check global package manager caches for this threat
  - Default: `false`
  - Set to `true` if the threat might involve globally installed packages
  - Can be overridden by `--check-global` command-line flag

#### File/Directory Patterns
- **file_patterns**: Array of file name patterns (supports glob patterns)
- **directory_patterns**: Array of directory name patterns

#### String Markers
- **string_markers**: Array of strings to search for in files (searches in .js, .json, .sh, .ts, .jsx, .tsx files)

#### Process Checks
- **process_patterns**: Array of process name patterns to check if running

#### Package Version Checks

**Option 1: Package-Specific Versions (Recommended)**

Use `package_versions` object to specify versions per package:

```json
"package_versions": {
  "package-name": {
    "vulnerable_versions": ["1.0.0", "1.1.0"],
    "patched_versions": ["1.0.1", "1.1.1"]
  },
  "another-package": {
    "min_vulnerable_version": "2.0.0",
    "vulnerable_ranges": [
      {"min": "2.0.0", "max": "2.999.999"},
      {"min": "3.0.0", "max": "3.5.0"}
    ],
    "patched_versions": ["2.10.0", "3.5.1"]
  }
}
```

**Option 2: Global Versions (Legacy, for backward compatibility)**

- **packages**: Array of npm package names to check
- **vulnerable_versions**: Array of specific vulnerable versions (applies to all packages)
- **patched_versions**: Array of patched versions (applies to all packages)
- **min_vulnerable_version**: Minimum version that is vulnerable (for range checks)

#### Remediation
- **remediation**: Array of remediation steps (displayed when threat is found)

## Examples

See:
- `shai-hulud-v2.json` - Malware detection with file/directory/string markers
- `rsc-vulnerability.json` - Package version vulnerability check with package-specific versions

### Package-Specific Version Example

The RSC vulnerability config shows how to handle different packages with different version ranges:

```json
{
  "package_versions": {
    "react-server-dom-webpack": {
      "vulnerable_versions": ["19.0.0", "19.1.0", "19.1.1", "19.2.0"],
      "patched_versions": ["19.0.1", "19.1.2", "19.2.1"]
    },
    "next": {
      "min_vulnerable_version": "14.3.0-canary.77",
      "vulnerable_ranges": [
        {"min": "14.3.0-canary.77", "max": "14.999.999"},
        {"min": "15.0.0", "max": "15.999.999"},
        {"min": "16.0.0", "max": "16.999.999"}
      ],
      "patched_versions": ["16.0.7", "15.5.7", "15.4.8", "15.3.6", "15.2.6", "15.1.9", "15.0.5"]
    }
  }
}
```

## Usage

The scanner automatically loads all `.json` files from this directory:

```bash
# Scan for all threats
./security-scanner.sh

# Scan for specific threat
./security-scanner.sh --threat shai-hulud

# Scan specific directory
./security-scanner.sh ~/projects

# Use custom config directory
./security-scanner.sh --config-dir ./my-threats
```

