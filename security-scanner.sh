#!/bin/bash

# Configurable Security Scanner
# Scans for multiple security threats based on configuration files
# Usage: ./security-scanner.sh [--threat THREAT_NAME] [--config-dir DIR] [DIRECTORY...]

set -euo pipefail

# Default configuration directory
CONFIG_DIR="${SECURITY_CONFIG_DIR:-./security-threats}"
SCAN_DIRS=(".")
THREAT_FILTER=""
VERBOSE=false
CHECK_GLOBAL_CACHE=false
SCAN_HOME=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --threat|-t)
            THREAT_FILTER="$2"
            shift 2
            ;;
        --config-dir|-c)
            CONFIG_DIR="$2"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --check-global|--global)
            CHECK_GLOBAL_CACHE=true
            shift
            ;;
        --scan-home)
            SCAN_HOME=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS] [DIRECTORY...]"
            echo ""
            echo "Options:"
            echo "  --threat, -t NAME     Scan only for specific threat"
            echo "  --config-dir, -c DIR   Directory containing threat configs (default: ./security-threats)"
            echo "  --verbose, -v         Verbose output"
            echo "  --check-global        Also check global package manager caches"
            echo "  --scan-home           Scan entire home directory (~)"
            echo "  --help, -h            Show this help"
            echo ""
            echo "Examples:"
            echo "  $0                                    # Scan current directory for all threats"
            echo "  $0 --threat shai-hulud ~/projects     # Scan ~/projects for Shai-Hulud only"
            echo "  $0 --scan-home                        # Scan entire home directory"
            echo "  $0 ~                                   # Scan home directory (alternative)"
            echo "  $0 --config-dir ./threats /path/to/scan"
            exit 0
            ;;
        -*)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
        *)
            SCAN_DIRS+=("$1")
            shift
            ;;
    esac
done

# Handle --scan-home flag
if [[ "$SCAN_HOME" == "true" ]]; then
    SCAN_DIRS=("$HOME")
fi

# Check if jq is available (optional but recommended)
HAS_JQ=false
if command -v jq &> /dev/null; then
    HAS_JQ=true
fi

# Global results
TOTAL_THREATS=0
FOUND_INDICATORS=0
SCANNED_THREATS=()

# Load threat configuration
load_threat_config() {
    local config_file="$1"
    
    if [[ ! -f "$config_file" ]]; then
        echo -e "${RED}Error: Config file not found: $config_file${NC}" >&2
        return 1
    fi
    
    if [[ "$HAS_JQ" == "true" ]]; then
        # Use jq for JSON parsing
        jq -c '.' "$config_file" 2>/dev/null || {
            echo -e "${RED}Error: Invalid JSON in $config_file${NC}" >&2
            return 1
        }
    else
        # Basic validation - check if file exists and is readable
        [[ -r "$config_file" ]] || return 1
    fi
}

# Get config value using jq or fallback to grep/sed
get_config_value() {
    local config_file="$1"
    local key="$2"
    
    if [[ "$HAS_JQ" == "true" ]]; then
        jq -r ".$key // empty" "$config_file" 2>/dev/null
    else
        # Fallback: simple grep/sed extraction
        grep -o "\"$key\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$config_file" 2>/dev/null | \
            sed 's/.*"'"$key"'"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || echo ""
    fi
}

# Get array values from config
get_config_array() {
    local config_file="$1"
    local key="$2"
    
    if [[ "$HAS_JQ" == "true" ]]; then
        jq -r ".$key[]? // empty" "$config_file" 2>/dev/null
    else
        # Fallback: extract array values
        grep -A 100 "\"$key\"" "$config_file" | \
            grep -o '"[^"]*"' | \
            sed 's/"//g' | \
            head -20 || echo ""
    fi
}

# Get package-specific config value
get_package_config_value() {
    local config_file="$1"
    local package="$2"
    local key="$3"
    
    if [[ "$HAS_JQ" == "true" ]]; then
        jq -r ".package_versions.\"$package\".$key[]? // .package_versions.\"$package\".$key // empty" "$config_file" 2>/dev/null
    else
        # Fallback: try to extract from package_versions object
        # This is more complex without jq, so we'll use a simpler approach
        grep -A 20 "\"$package\"" "$config_file" | \
            grep -A 5 "\"$key\"" | \
            grep -o '"[^"]*"' | \
            sed 's/"//g' | \
            head -20 || echo ""
    fi
}

# Get list of packages from package_versions or fallback to packages array
get_packages_list() {
    local config_file="$1"
    
    if [[ "$HAS_JQ" == "true" ]]; then
        # Try package_versions first (new format)
        local packages=$(jq -r '.package_versions | keys[]?' "$config_file" 2>/dev/null)
        if [[ -n "$packages" ]]; then
            echo "$packages"
            return
        fi
        # Fallback to packages array (old format)
        jq -r '.packages[]? // empty' "$config_file" 2>/dev/null
    else
        # Fallback: try to extract package names
        # This is simplified - jq is really recommended for complex configs
        grep -A 50 '"package_versions"' "$config_file" | \
            grep -o '"[^"]*"' | \
            sed 's/"//g' | \
            head -20 || \
        grep -A 20 '"packages"' "$config_file" | \
            grep -o '"[^"]*"' | \
            sed 's/"//g' | \
            head -20 || echo ""
    fi
}

# Build find exclusion patterns for common system directories
build_find_exclusions() {
    local scan_dir="$1"
    local exclusions=()
    
    # Always exclude common directories
    exclusions+=("! -path '*/node_modules/*'")
    exclusions+=("! -path '*/.git/*'")
    exclusions+=("! -path '*/.svn/*'")
    exclusions+=("! -path '*/.hg/*'")
    
    # If scanning home directory, exclude system directories
    if [[ "$scan_dir" == "$HOME" ]] || [[ "$scan_dir" == "$HOME/"* ]]; then
        exclusions+=("! -path '$HOME/Library/*'")
        exclusions+=("! -path '$HOME/.Trash/*'")
        exclusions+=("! -path '$HOME/.npm/*'")
        exclusions+=("! -path '$HOME/.yarn/*'")
        exclusions+=("! -path '$HOME/.pnpm-store/*'")
        exclusions+=("! -path '$HOME/.cache/*'")
        exclusions+=("! -path '$HOME/.local/share/Trash/*'")
        exclusions+=("! -path '$HOME/.config/*/Cache/*'")
        # Exclude common hidden system directories
        exclusions+=("! -path '$HOME/.DS_Store'")
        exclusions+=("! -path '$HOME/.localized'")
    fi
    
    # Return exclusions as a string (for use in eval or command substitution)
    printf '%s ' "${exclusions[@]}"
}

# Check for file patterns
check_file_patterns() {
    local config_file="$1"
    local scan_dir="$2"
    local threat_name="$3"
    local found=0
    
    local file_patterns=$(get_config_array "$config_file" "file_patterns")
    
    # If no patterns or only empty lines, return 0 (nothing found)
    if [[ -z "$file_patterns" ]] || [[ -z "$(echo "$file_patterns" | grep -v '^[[:space:]]*$')" ]]; then
        return 0
    fi
    
    # Build exclusion patterns
    local exclusions=$(build_find_exclusions "$scan_dir")
    
    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue
        
        # Use find to search for files matching pattern
        # Note: We use eval here to handle the exclusions properly
        while IFS= read -r -d '' file; do
            if [[ -f "$file" ]]; then
                echo -e "${RED}✗ Found suspicious file: $file${NC}"
                echo -e "  Pattern: $pattern"
                found=1
            fi
        done < <(eval "find \"$scan_dir\" -name \"$pattern\" -type f $exclusions -print0 2>/dev/null" || true)
    done <<< "$file_patterns"
    
    return $found
}

# Check for directory patterns
check_directory_patterns() {
    local config_file="$1"
    local scan_dir="$2"
    local threat_name="$3"
    local found=0
    
    local dir_patterns=$(get_config_array "$config_file" "directory_patterns")
    
    # If no patterns or only empty lines, return 0 (nothing found)
    if [[ -z "$dir_patterns" ]] || [[ -z "$(echo "$dir_patterns" | grep -v '^[[:space:]]*$')" ]]; then
        return 0
    fi
    
    # Build exclusion patterns
    local exclusions=$(build_find_exclusions "$scan_dir")
    
    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue
        
        while IFS= read -r -d '' dir; do
            if [[ -d "$dir" ]]; then
                echo -e "${RED}✗ Found suspicious directory: $dir${NC}"
                echo -e "  Pattern: $pattern"
                found=1
            fi
        done < <(eval "find \"$scan_dir\" -name \"$pattern\" -type d $exclusions -print0 2>/dev/null" || true)
    done <<< "$dir_patterns"
    
    return $found
}

# Check for string markers in files
check_string_markers() {
    local config_file="$1"
    local scan_dir="$2"
    local threat_name="$3"
    local found=0
    
    local markers=$(get_config_array "$config_file" "string_markers")
    
    # If no markers or only empty lines, return 0 (nothing found)
    if [[ -z "$markers" ]] || [[ -z "$(echo "$markers" | grep -v '^[[:space:]]*$')" ]]; then
        return 0
    fi
    
    while IFS= read -r marker; do
        [[ -z "$marker" ]] && continue
        
        # Build exclusion patterns
        local exclusions=$(build_find_exclusions "$scan_dir")
        
        # Search for marker in files (excluding binary files and system directories)
        while IFS= read -r file; do
            [[ -z "$file" ]] || [[ ! -f "$file" ]] && continue
            # Check if file is text (skip binary files)
            if file "$file" 2>/dev/null | grep -qE "(text|ASCII|UTF-8|JSON)"; then
                if grep -qF "$marker" "$file" 2>/dev/null; then
                    echo -e "${RED}✗ Found marker string in: $file${NC}"
                    echo -e "  Marker: $marker"
                    found=1
                fi
            fi
        done < <(eval "find \"$scan_dir\" -type f $exclusions \
                 \( -name \"*.js\" -o -name \"*.json\" -o -name \"*.sh\" -o -name \"*.ts\" \
                 -o -name \"*.jsx\" -o -name \"*.tsx\" -o -name \"*.txt\" \) 2>/dev/null" | head -1000)
    done <<< "$markers"
    
    return $found
}

# Detect package manager and return lock file path
detect_package_manager() {
    local scan_dir="$1"
    
    # Check for lock files in order of preference
    if [[ -f "$scan_dir/pnpm-lock.yaml" ]]; then
        echo "pnpm"
        return
    elif [[ -f "$scan_dir/yarn.lock" ]]; then
        echo "yarn"
        return
    elif [[ -f "$scan_dir/package-lock.json" ]]; then
        echo "npm"
        return
    fi
    
    # Check package.json for packageManager field
    if [[ -f "$scan_dir/package.json" ]]; then
        local pm=$(grep '"packageManager"' "$scan_dir/package.json" 2>/dev/null | \
            sed 's/.*"packageManager"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' | \
            cut -d'@' -f1)
        if [[ -n "$pm" ]]; then
            echo "$pm"
            return
        fi
    fi
    
    echo "unknown"
}

# Extract version from npm package-lock.json
extract_version_npm() {
    local pkg=$1
    local lock=$2
    
    if [[ ! -f "$lock" ]]; then
        return 1
    fi
    
    local lockfile_version=$(grep '"lockfileVersion"' "$lock" 2>/dev/null | head -n1 | \
        sed 's/.*"lockfileVersion": *\([0-9]*\).*/\1/')
    
    local version=""
    if [[ "$lockfile_version" == "3" ]]; then
        version=$(grep -A 3 "\"node_modules/$pkg\":" "$lock" 2>/dev/null | \
            grep '"version"' | head -n1 | sed 's/.*"version": *"\([^"]*\)".*/\1/')
        [[ -z "$version" ]] && \
            version=$(grep -A 3 "\"node_modules/.*/$pkg\":" "$lock" 2>/dev/null | \
            grep '"version"' | head -n1 | sed 's/.*"version": *"\([^"]*\)".*/\1/')
    else
        version=$(grep -A 5 "\"$pkg\":" "$lock" 2>/dev/null | \
            grep '"version"' | head -n1 | sed 's/.*"version": *"\([^"]*\)".*/\1/')
    fi
    
    echo "$version"
}

# Extract version from yarn.lock
extract_version_yarn() {
    local pkg=$1
    local lock=$2
    
    if [[ ! -f "$lock" ]]; then
        return 1
    fi
    
    # Yarn lock format (v1): "package-name@version:" or "@scope/package@version:"
    # Then version is on the next line as "  version \"x.y.z\""
    # Yarn lock format (v2/Berry): Similar but may have different structure
    
    # Escape package name for regex (handle scoped packages)
    local escaped_pkg=$(echo "$pkg" | sed 's/[\/\.]/\\&/g')
    
    # Try to find the package entry - look for lines starting with "package-name@"
    # or "@scope/package@"
    local entry_line=""
    
    # Try exact match with package name
    if [[ "$pkg" =~ ^@ ]]; then
        # Scoped package: @scope/package
        entry_line=$(grep -m 1 "^\"$escaped_pkg@" "$lock" 2>/dev/null)
    else
        # Regular package
        entry_line=$(grep -m 1 "^\"$escaped_pkg@" "$lock" 2>/dev/null)
    fi
    
    if [[ -z "$entry_line" ]]; then
        # Try without quotes (yarn v2+)
        if [[ "$pkg" =~ ^@ ]]; then
            entry_line=$(grep -m 1 "^$escaped_pkg@" "$lock" 2>/dev/null)
        else
            entry_line=$(grep -m 1 "^$escaped_pkg@" "$lock" 2>/dev/null)
        fi
    fi
    
    if [[ -z "$entry_line" ]]; then
        # Try finding by package name only (may have different version specifiers)
        local pkg_base=$(echo "$pkg" | sed 's/^@[^\/]*\///')
        entry_line=$(grep -m 1 "\"$pkg_base@" "$lock" 2>/dev/null | head -n1)
    fi
    
    if [[ -n "$entry_line" ]]; then
        # Extract version from the entry line or following lines
        # Format: "package@version:" -> extract version
        local version=$(echo "$entry_line" | sed 's/.*@\([^":]*\)[:"].*/\1/' | sed 's/^"//' | sed 's/"$//')
        
        # If that didn't work, look for version field in the next few lines
        if [[ -z "$version" ]] || [[ "$version" == "$pkg" ]]; then
            local line_num=$(grep -n "^\"$escaped_pkg@" "$lock" 2>/dev/null | head -n1 | cut -d: -f1)
            if [[ -n "$line_num" ]]; then
                version=$(sed -n "${line_num},$((line_num + 10))p" "$lock" | \
                    grep -m 1 "version" | sed 's/.*version[[:space:]]*"\([^"]*\)".*/\1/')
            fi
        fi
        
        echo "$version"
    fi
}

# Extract version from pnpm-lock.yaml
extract_version_pnpm() {
    local pkg=$1
    local lock=$2
    
    if [[ ! -f "$lock" ]]; then
        return 1
    fi
    
    # Check if yq is available (better YAML parsing)
    if command -v yq &> /dev/null; then
        # pnpm-lock.yaml structure: packages -> /package-name/version -> version
        # Try different path formats
        local version=$(yq eval ".packages.\"/$pkg/\" | keys[0]" "$lock" 2>/dev/null 2>&1 | \
            grep -v "null" | sed 's|.*/||' || echo "")
        if [[ -n "$version" ]] && [[ "$version" != "null" ]] && [[ -n "$(echo "$version" | grep -E '^[0-9]')" ]]; then
            echo "$version"
            return
        fi
    fi
    
    # Fallback: grep-based extraction
    # pnpm format: /package-name/version: or /@scope/package/version:
    # Also check for format: /package-name@version/:
    
    # Try format: /package-name/version:
    local version=$(grep -E "^[[:space:]]*/$pkg/" "$lock" 2>/dev/null | \
        head -n1 | sed 's|.*/\([^/]*\):|\1|' | sed 's/:$//' | sed 's/^[[:space:]]*//')
    
    # Try format: /package-name@version/:
    if [[ -z "$version" ]]; then
        version=$(grep -E "^[[:space:]]*/$pkg@" "$lock" 2>/dev/null | \
            head -n1 | sed "s|.*$pkg@\([^/]*\)/.*|\1|" | sed 's/:$//' | sed 's/^[[:space:]]*//')
    fi
    
    # Try scoped package format
    if [[ -z "$version" ]] && [[ "$pkg" =~ ^@ ]]; then
        version=$(grep -E "^[[:space:]]*/$pkg/" "$lock" 2>/dev/null | \
            head -n1 | sed 's|.*/\([^/]*\):|\1|' | sed 's/:$//' | sed 's/^[[:space:]]*//')
    fi
    
    echo "$version"
}

# Get global npm cache directory
get_npm_cache_dir() {
    if command -v npm &> /dev/null; then
        local cache=$(npm config get cache 2>/dev/null)
        if [[ -n "$cache" ]] && [[ "$cache" != "undefined" ]]; then
            echo "$cache"
            return
        fi
    fi
    
    # Default npm cache locations
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "$HOME/.npm"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "$HOME/.npm"
    else
        echo "$HOME/.npm"
    fi
}

# Get global yarn cache directory
get_yarn_cache_dir() {
    if command -v yarn &> /dev/null; then
        yarn cache dir 2>/dev/null || echo ""
    else
        # Default yarn cache locations
        if [[ "$OSTYPE" == "darwin"* ]]; then
            echo "$HOME/Library/Caches/Yarn"
        else
            echo "$HOME/.yarn/cache"
        fi
    fi
}

# Get global pnpm store directory
get_pnpm_store_dir() {
    if command -v pnpm &> /dev/null; then
        pnpm store path 2>/dev/null || echo ""
    else
        # Default pnpm store locations
        if [[ "$OSTYPE" == "darwin"* ]]; then
            echo "$HOME/Library/pnpm/store"
        else
            echo "$HOME/.pnpm-store"
        fi
    fi
}

# Extract version from node_modules package.json
extract_version_node_modules() {
    local pkg=$1
    local scan_dir=$2
    
    # Check local node_modules first
    local pkg_path=""
    if [[ "$pkg" =~ ^@ ]]; then
        # Scoped package: @scope/package
        local scope=$(echo "$pkg" | cut -d'/' -f1 | sed 's/^@//')
        local pkg_name=$(echo "$pkg" | cut -d'/' -f2)
        pkg_path="$scan_dir/node_modules/@$scope/$pkg_name"
    else
        # Regular package
        pkg_path="$scan_dir/node_modules/$pkg"
    fi
    
    if [[ -f "$pkg_path/package.json" ]]; then
        local version=$(grep '"version"' "$pkg_path/package.json" 2>/dev/null | \
            head -n1 | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        if [[ -n "$version" ]]; then
            echo "$version"
            return 0
        fi
    fi
    
    return 1
}

# Extract version from global npm cache
extract_version_npm_global() {
    local pkg=$1
    local cache_dir=$(get_npm_cache_dir)
    
    if [[ -z "$cache_dir" ]] || [[ ! -d "$cache_dir" ]]; then
        return 1
    fi
    
    # npm cache structure (v5+): _cacache/content-v2/sha512/...
    # npm cache structure (older): package-name/version/...
    local version=""
    
    # Method 1: Check _cacache structure (npm v5+)
    if [[ -d "$cache_dir/_cacache" ]]; then
        # Look for package.json files in cache (limit search depth for performance)
        local found_pkg_json=$(find "$cache_dir/_cacache" -maxdepth 6 -name "package.json" -type f 2>/dev/null | \
            xargs grep -l "\"name\"[[:space:]]*:[[:space:]]*\"$pkg\"" 2>/dev/null | head -n1)
        
        if [[ -n "$found_pkg_json" ]] && [[ -f "$found_pkg_json" ]]; then
            version=$(grep '"version"' "$found_pkg_json" 2>/dev/null | \
                head -n1 | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        fi
    fi
    
    # Method 2: Check old cache structure (package-name/version/)
    if [[ -z "$version" ]]; then
        local pkg_name=$(echo "$pkg" | sed 's/^@[^\/]*\///' | sed 's/\//-/g')
        if [[ -d "$cache_dir/$pkg_name" ]]; then
            # Find latest version directory
            local version_dir=$(ls -td "$cache_dir/$pkg_name"/*/ 2>/dev/null | head -n1)
            if [[ -n "$version_dir" ]] && [[ -f "$version_dir/package.json" ]]; then
                version=$(grep '"version"' "$version_dir/package.json" 2>/dev/null | \
                    head -n1 | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
            fi
        fi
    fi
    
    if [[ -n "$version" ]]; then
        echo "$version"
        return 0
    fi
    
    return 1
}

# Extract version from global yarn cache
extract_version_yarn_global() {
    local pkg=$1
    local cache_dir=$(get_yarn_cache_dir)
    
    if [[ -z "$cache_dir" ]] || [[ ! -d "$cache_dir" ]]; then
        return 1
    fi
    
    # Yarn cache structure varies by version
    # Look for package directories
    local pkg_name=$(echo "$pkg" | sed 's/^@[^\/]*\///' | sed 's/\//-/g')
    local found_pkg=$(find "$cache_dir" -type d -name "*$pkg_name*" 2>/dev/null | head -n1)
    
    if [[ -n "$found_pkg" ]] && [[ -f "$found_pkg/package.json" ]]; then
        local version=$(grep '"version"' "$found_pkg/package.json" 2>/dev/null | \
            head -n1 | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        if [[ -n "$version" ]]; then
            echo "$version"
            return 0
        fi
    fi
    
    return 1
}

# Extract version from global pnpm store
extract_version_pnpm_global() {
    local pkg=$1
    local store_dir=$(get_pnpm_store_dir)
    
    if [[ -z "$store_dir" ]] || [[ ! -d "$store_dir" ]]; then
        return 1
    fi
    
    # pnpm store structure: v3/files/... or similar
    # Look for package.json files
    local found_pkg_json=$(find "$store_dir" -name "package.json" -type f 2>/dev/null | \
        xargs grep -l "\"name\"[[:space:]]*:[[:space:]]*\"$pkg\"" 2>/dev/null | head -n1)
    
    if [[ -n "$found_pkg_json" ]] && [[ -f "$found_pkg_json" ]]; then
        local version=$(grep '"version"' "$found_pkg_json" 2>/dev/null | \
            head -n1 | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        if [[ -n "$version" ]]; then
            echo "$version"
            return 0
        fi
    fi
    
    return 1
}

# Find all workspace directories in a monorepo
find_workspace_dirs() {
    local root_dir="$1"
    local workspace_dirs=("$root_dir")
    
    # Check for workspace configurations
    local root_package_json="$root_dir/package.json"
    
    if [[ -f "$root_package_json" ]]; then
        # npm/yarn workspaces: check "workspaces" field
        if [[ "$HAS_JQ" == "true" ]]; then
            local workspaces=$(jq -r '.workspaces[]? // .workspaces.packages[]? // empty' "$root_package_json" 2>/dev/null)
            while IFS= read -r workspace_pattern; do
                [[ -z "$workspace_pattern" ]] && continue
                # Convert glob pattern to find command
                local pattern=$(echo "$workspace_pattern" | sed 's/\*/.*/g' | sed 's/\//\\\//g')
                while IFS= read -r -d '' dir; do
                    if [[ -f "$dir/package.json" ]]; then
                        workspace_dirs+=("$dir")
                    fi
                done < <(find "$root_dir" -maxdepth 3 -type d -name "$(basename "$workspace_pattern")" -print0 2>/dev/null || \
                    find "$root_dir" -path "$workspace_pattern" -type f -name "package.json" -exec dirname {} \; -print0 2>/dev/null | \
                    head -20)
            done <<< "$workspaces"
        fi
        
        # pnpm workspaces: check for pnpm-workspace.yaml
        if [[ -f "$root_dir/pnpm-workspace.yaml" ]]; then
            # Extract workspace patterns from pnpm-workspace.yaml
            local patterns=$(grep -E '^\s*-' "$root_dir/pnpm-workspace.yaml" 2>/dev/null | \
                sed 's/^[[:space:]]*-[[:space:]]*//' | sed 's/\*/.*/g')
            while IFS= read -r pattern; do
                [[ -z "$pattern" ]] && continue
                while IFS= read -r -d '' dir; do
                    if [[ -f "$dir/package.json" ]]; then
                        workspace_dirs+=("$dir")
                    fi
                done < <(find "$root_dir" -maxdepth 3 -type f -path "$pattern/package.json" -exec dirname {} \; -print0 2>/dev/null | \
                    head -20)
            done <<< "$patterns"
        fi
    fi
    
    # Also find all package.json files in subdirectories (fallback for unknown workspace configs)
    # Limit depth to avoid scanning too deep
    while IFS= read -r -d '' dir; do
        local already_added=false
        for existing_dir in "${workspace_dirs[@]}"; do
            if [[ "$dir" == "$existing_dir" ]]; then
                already_added=true
                break
            fi
        done
        if [[ "$already_added" == "false" ]]; then
            workspace_dirs+=("$dir")
        fi
    done < <(find "$root_dir" -maxdepth 4 -type f -name "package.json" ! -path "*/node_modules/*" \
        ! -path "*/.git/*" -exec dirname {} \; -print0 2>/dev/null | head -50)
    
    # Return unique directories
    printf '%s\n' "${workspace_dirs[@]}" | sort -u
}

# Extract version from any lock file (auto-detects format)
# Also checks node_modules, monorepo workspaces, and global caches as fallbacks
extract_version() {
    local pkg=$1
    local scan_dir=$2
    local check_global=${3:-false}  # Third parameter: whether to check global cache for this threat
    local package_file="$scan_dir/package.json"
    local version=""
    
    # Detect package manager
    local pm=$(detect_package_manager "$scan_dir")
    
    # First, try root lock files
    case "$pm" in
        npm)
            version=$(extract_version_npm "$pkg" "$scan_dir/package-lock.json")
            ;;
        yarn)
            version=$(extract_version_yarn "$pkg" "$scan_dir/yarn.lock")
            ;;
        pnpm)
            version=$(extract_version_pnpm "$pkg" "$scan_dir/pnpm-lock.yaml")
            ;;
        *)
            # Fallback: try all lock files
            if [[ -f "$scan_dir/package-lock.json" ]]; then
                version=$(extract_version_npm "$pkg" "$scan_dir/package-lock.json")
            fi
            if [[ -z "$version" ]] && [[ -f "$scan_dir/yarn.lock" ]]; then
                version=$(extract_version_yarn "$pkg" "$scan_dir/yarn.lock")
            fi
            if [[ -z "$version" ]] && [[ -f "$scan_dir/pnpm-lock.yaml" ]]; then
                version=$(extract_version_pnpm "$pkg" "$scan_dir/pnpm-lock.yaml")
            fi
            ;;
    esac
    
    # If not found, check workspace subdirectories (monorepo support)
    if [[ -z "$version" ]]; then
        local workspace_dirs=$(find_workspace_dirs "$scan_dir")
        while IFS= read -r workspace_dir; do
            [[ -z "$workspace_dir" ]] || [[ "$workspace_dir" == "$scan_dir" ]] && continue
            
            # Check lock file in workspace
            if [[ -f "$workspace_dir/package-lock.json" ]]; then
                version=$(extract_version_npm "$pkg" "$workspace_dir/package-lock.json")
                [[ -n "$version" ]] && break
            fi
            if [[ -f "$workspace_dir/yarn.lock" ]]; then
                version=$(extract_version_yarn "$pkg" "$workspace_dir/yarn.lock")
                [[ -n "$version" ]] && break
            fi
            if [[ -f "$workspace_dir/pnpm-lock.yaml" ]]; then
                version=$(extract_version_pnpm "$pkg" "$workspace_dir/pnpm-lock.yaml")
                [[ -n "$version" ]] && break
            fi
            
            # Check node_modules in workspace
            version=$(extract_version_node_modules "$pkg" "$workspace_dir")
            [[ -n "$version" ]] && break
        done <<< "$workspace_dirs"
    fi
    
    # If not found in lock file, try root node_modules
    if [[ -z "$version" ]]; then
        version=$(extract_version_node_modules "$pkg" "$scan_dir")
    fi
    
    # If still not found, try global caches (if enabled via flag, threat config, or verbose mode)
    local should_check_global=false
    if [[ "$CHECK_GLOBAL_CACHE" == "true" ]]; then
        should_check_global=true
    elif [[ "$check_global" == "true" ]]; then
        should_check_global=true
    elif [[ "$VERBOSE" == "true" ]]; then
        should_check_global=true
    fi
    
    if [[ -z "$version" ]] && [[ "$should_check_global" == "true" ]]; then
        case "$pm" in
            npm)
                version=$(extract_version_npm_global "$pkg")
                ;;
            yarn)
                version=$(extract_version_yarn_global "$pkg")
                ;;
            pnpm)
                version=$(extract_version_pnpm_global "$pkg")
                ;;
            *)
                # Try all global caches
                version=$(extract_version_npm_global "$pkg")
                [[ -z "$version" ]] && version=$(extract_version_yarn_global "$pkg")
                [[ -z "$version" ]] && version=$(extract_version_pnpm_global "$pkg")
                ;;
        esac
    fi
    
    echo "$version"
}

# Get tool version (node, npm, yarn, pnpm)
get_tool_version() {
    local tool="$1"
    local version=""
    
    case "$tool" in
        node)
            if command -v node &> /dev/null; then
                version=$(node --version 2>/dev/null | sed 's/^v//')
            fi
            ;;
        npm)
            if command -v npm &> /dev/null; then
                version=$(npm --version 2>/dev/null)
            fi
            ;;
        yarn)
            if command -v yarn &> /dev/null; then
                version=$(yarn --version 2>/dev/null)
            fi
            ;;
        pnpm)
            if command -v pnpm &> /dev/null; then
                version=$(pnpm --version 2>/dev/null)
            fi
            ;;
    esac
    
    echo "$version"
}

# Get tool-specific config value from tool_versions
get_tool_config_value() {
    local config_file="$1"
    local tool="$2"
    local key="$3"
    
    if [[ "$HAS_JQ" == "true" ]]; then
        jq -r ".tool_versions.\"$tool\".$key[]? // .tool_versions.\"$tool\".$key // empty" "$config_file" 2>/dev/null
    else
        # Fallback: try to extract from tool_versions object
        grep -A 20 "\"$tool\"" "$config_file" | \
            grep -A 5 "\"$key\"" | \
            grep -o '"[^"]*"' | \
            sed 's/"//g' | \
            head -20 || echo ""
    fi
}

# Get list of tools from tool_versions
get_tools_list() {
    local config_file="$1"
    
    if [[ "$HAS_JQ" == "true" ]]; then
        jq -r '.tool_versions | keys[]?' "$config_file" 2>/dev/null
    else
        # Fallback: try to extract tool names
        grep -A 50 '"tool_versions"' "$config_file" | \
            grep -o '"[^"]*"' | \
            sed 's/"//g' | \
            head -10 || echo ""
    fi
}

# Check tool versions (node, npm, yarn, pnpm)
check_tool_versions() {
    local config_file="$1"
    local scan_dir="$2"
    local threat_name="$3"
    local found=0
    
    # Check if tool_versions exists in config
    local has_tool_versions=false
    if [[ "$HAS_JQ" == "true" ]]; then
        if jq -e '.tool_versions' "$config_file" > /dev/null 2>&1; then
            has_tool_versions=true
        fi
    else
        if grep -q '"tool_versions"' "$config_file"; then
            has_tool_versions=true
        fi
    fi
    
    if [[ "$has_tool_versions" == "false" ]]; then
        return 0
    fi
    
    # Get list of tools to check
    local tools=$(get_tools_list "$config_file")
    
    # If no tools or only empty lines, return 0 (nothing to check)
    if [[ -z "$tools" ]] || [[ -z "$(echo "$tools" | grep -v '^[[:space:]]*$')" ]]; then
        return 0
    fi
    
    while IFS= read -r tool; do
        [[ -z "$tool" ]] && continue
        
        # Get installed version
        local version=$(get_tool_version "$tool")
        
        if [[ -z "$version" ]]; then
            [[ "$VERBOSE" == "true" ]] && \
                echo -e "${GREEN}✓ $tool not installed${NC}"
            continue
        fi
        
        # Clean version (remove 'v' prefix if present, remove any extra whitespace)
        local clean_version=$(echo "$version" | sed 's/^v//' | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
        
        # Get tool-specific versions
        local vulnerable_versions=""
        local patched_versions=""
        local min_vulnerable=""
        
        if [[ "$HAS_JQ" == "true" ]]; then
            vulnerable_versions=$(jq -r ".tool_versions.\"$tool\".vulnerable_versions[]? // empty" "$config_file" 2>/dev/null)
            patched_versions=$(jq -r ".tool_versions.\"$tool\".patched_versions[]? // empty" "$config_file" 2>/dev/null)
            min_vulnerable=$(jq -r ".tool_versions.\"$tool\".min_vulnerable_version // empty" "$config_file" 2>/dev/null)
            
            # Check vulnerable_ranges
            local has_ranges=$(jq -e ".tool_versions.\"$tool\".vulnerable_ranges" "$config_file" > /dev/null 2>&1 && echo "true" || echo "false")
            if [[ "$has_ranges" == "true" ]]; then
                local in_range=false
                local range_count=$(jq ".tool_versions.\"$tool\".vulnerable_ranges | length" "$config_file" 2>/dev/null)
                for ((i=0; i<range_count; i++)); do
                    local range_min=$(jq -r ".tool_versions.\"$tool\".vulnerable_ranges[$i].min" "$config_file" 2>/dev/null)
                    local range_max=$(jq -r ".tool_versions.\"$tool\".vulnerable_ranges[$i].max" "$config_file" 2>/dev/null)
                    if [[ -n "$range_min" ]] && [[ -n "$range_max" ]]; then
                        local v_base=$(echo "$clean_version" | cut -d'-' -f1)
                        local min_base=$(echo "$range_min" | cut -d'-' -f1)
                        local max_base=$(echo "$range_max" | cut -d'-' -f1)
                        local min_check=$(printf '%s\n%s\n' "$v_base" "$min_base" | sort -V | tail -n1)
                        local max_check=$(printf '%s\n%s\n' "$v_base" "$max_base" | sort -V | head -n1)
                        if [[ "$min_check" == "$v_base" ]] && [[ "$max_check" == "$v_base" ]]; then
                            in_range=true
                            break
                        fi
                    fi
                done
                if [[ "$in_range" == "true" ]]; then
                    vulnerable_versions="$clean_version"
                fi
            fi
        else
            # Fallback without jq - try simple extraction
            vulnerable_versions=$(get_tool_config_value "$config_file" "$tool" "vulnerable_versions")
            patched_versions=$(get_tool_config_value "$config_file" "$tool" "patched_versions")
            min_vulnerable=$(get_tool_config_value "$config_file" "$tool" "min_vulnerable_version")
        fi
        
        # Check if vulnerable
        local is_vulnerable=false
        local is_patched=false
        
        # First, check if version is patched (patched takes precedence)
        if [[ -n "$patched_versions" ]]; then
            while IFS= read -r patched_ver; do
                [[ -z "$patched_ver" ]] && continue
                if [[ "$clean_version" == "$patched_ver" ]]; then
                    is_patched=true
                    break
                fi
            done <<< "$patched_versions"
        fi
        
        # Only check for vulnerability if not patched
        if [[ "$is_patched" == "false" ]]; then
            # Check against vulnerable versions list
            if [[ -n "$vulnerable_versions" ]]; then
                while IFS= read -r vuln_ver; do
                    [[ -z "$vuln_ver" ]] && continue
                    if [[ "$clean_version" == "$vuln_ver" ]]; then
                        is_vulnerable=true
                        break
                    fi
                done <<< "$vulnerable_versions"
            fi
            
            # Check against minimum version (if not already vulnerable)
            if [[ "$is_vulnerable" == "false" ]] && [[ -n "$min_vulnerable" ]]; then
                local v_base=$(echo "$clean_version" | cut -d'-' -f1)
                local m_base=$(echo "$min_vulnerable" | cut -d'-' -f1)
                local result=$(printf '%s\n%s\n' "$v_base" "$m_base" | sort -V | head -n1)
                
                if [[ "$v_base" == "$result" ]] && [[ "$v_base" != "$m_base" ]]; then
                    # version < min_vulnerable, not vulnerable
                    is_vulnerable=false
                elif [[ "$v_base" != "$m_base" ]]; then
                    # version >= min_vulnerable, check if patched (already checked above)
                    # If we get here and is_patched is still false, it's vulnerable
                    is_vulnerable=true
                fi
            fi
        fi
        
        if [[ "$is_vulnerable" == "true" ]]; then
            echo -e "${RED}✗ VULNERABLE: $tool@$clean_version${NC}"
            found=1
        elif [[ -n "$clean_version" ]]; then
            if [[ "$is_patched" == "true" ]]; then
                [[ "$VERBOSE" == "true" ]] && \
                    echo -e "${GREEN}✓ SAFE: $tool@$clean_version (patched)${NC}"
            elif [[ "$VERBOSE" == "true" ]]; then
                echo -e "${GREEN}✓ SAFE: $tool@$clean_version${NC}"
            fi
        fi
    done <<< "$tools"
    
    return $found
}

# Check package versions
check_package_versions() {
    local config_file="$1"
    local scan_dir="$2"
    local threat_name="$3"
    local found=0
    
    local package_file="$scan_dir/package.json"
    
    if [[ ! -f "$package_file" ]]; then
        return 0
    fi
    
    # Detect package manager
    local pm=$(detect_package_manager "$scan_dir")
    if [[ "$VERBOSE" == "true" ]] && [[ "$pm" != "unknown" ]]; then
        echo -e "${BLUE}ℹ Detected package manager: $pm${NC}"
    fi
    
    # Check if this is a monorepo
    local workspace_dirs=$(find_workspace_dirs "$scan_dir")
    local workspace_count=$(echo "$workspace_dirs" | grep -v "^$scan_dir$" | grep -c . || echo "0")
    if [[ "$workspace_count" -gt 0 ]] && [[ "$VERBOSE" == "true" ]]; then
        echo -e "${BLUE}ℹ Detected monorepo with $workspace_count workspace(s)${NC}"
    fi
    
    # Get packages to check (support both new package_versions format and old packages format)
    local packages=$(get_packages_list "$config_file")
    
    # If no packages or only empty lines, return 0 (nothing to check)
    if [[ -z "$packages" ]] || [[ -z "$(echo "$packages" | grep -v '^[[:space:]]*$')" ]]; then
        return 0
    fi
    
    # Check if using new package_versions format
    local use_package_versions=false
    if [[ "$HAS_JQ" == "true" ]]; then
        if jq -e '.package_versions' "$config_file" > /dev/null 2>&1; then
            use_package_versions=true
        fi
    else
        # Fallback: check if package_versions key exists
        if grep -q '"package_versions"' "$config_file"; then
            use_package_versions=true
        fi
    fi
    
    # Get global versions (for backward compatibility with old format)
    local global_vulnerable_versions=""
    local global_patched_versions=""
    local global_min_vulnerable=""
    
    if [[ "$use_package_versions" == "false" ]]; then
        global_vulnerable_versions=$(get_config_array "$config_file" "vulnerable_versions")
        global_patched_versions=$(get_config_array "$config_file" "patched_versions")
        global_min_vulnerable=$(get_config_value "$config_file" "min_vulnerable_version")
    fi
    
    # Get check_global_cache setting from threat config
    local threat_check_global="false"
    local config_check_global=$(get_config_value "$config_file" "check_global_cache")
    if [[ "$config_check_global" == "true" ]] || [[ "$config_check_global" == "1" ]]; then
        threat_check_global="true"
    fi
    
    while IFS= read -r package; do
        [[ -z "$package" ]] && continue
        
        # Try to extract version from lock file (supports npm, yarn, pnpm)
        # Pass threat-specific check_global_cache setting
        local version=$(extract_version "$package" "$scan_dir" "$threat_check_global")
        
        # Fallback to package.json if lock file doesn't have it
        if [[ -z "$version" ]]; then
            version=$(grep -i "\"$package\"" "$package_file" 2>/dev/null | \
                sed 's/.*"\([^"]*\)".*/\1/' | sed 's/.*: *"\([^"]*\)".*/\1/')
        fi
        
        if [[ -z "$version" ]]; then
            [[ "$VERBOSE" == "true" ]] && \
                echo -e "${GREEN}✓ $package not found${NC}"
            continue
        fi
        
        # Clean version
        local clean_version=$(echo "$version" | sed 's/[\^~>=<]//g')
        
        # Get package-specific versions or use global
        local vulnerable_versions=""
        local patched_versions=""
        local min_vulnerable=""
        
        if [[ "$use_package_versions" == "true" ]]; then
            # New format: get package-specific versions
            if [[ "$HAS_JQ" == "true" ]]; then
                vulnerable_versions=$(jq -r ".package_versions.\"$package\".vulnerable_versions[]? // empty" "$config_file" 2>/dev/null)
                patched_versions=$(jq -r ".package_versions.\"$package\".patched_versions[]? // empty" "$config_file" 2>/dev/null)
                min_vulnerable=$(jq -r ".package_versions.\"$package\".min_vulnerable_version // empty" "$config_file" 2>/dev/null)
                
                # Check vulnerable_ranges for Next.js style ranges
                local has_ranges=$(jq -e ".package_versions.\"$package\".vulnerable_ranges" "$config_file" > /dev/null 2>&1 && echo "true" || echo "false")
                if [[ "$has_ranges" == "true" ]]; then
                    # Handle version ranges (simplified - check if version is in any range)
                    local in_range=false
                    local range_count=$(jq ".package_versions.\"$package\".vulnerable_ranges | length" "$config_file" 2>/dev/null)
                    for ((i=0; i<range_count; i++)); do
                        local range_min=$(jq -r ".package_versions.\"$package\".vulnerable_ranges[$i].min" "$config_file" 2>/dev/null)
                        local range_max=$(jq -r ".package_versions.\"$package\".vulnerable_ranges[$i].max" "$config_file" 2>/dev/null)
                        # Simple range check (version >= min && version <= max)
                        # This is simplified - proper version comparison would be better
                        if [[ -n "$range_min" ]] && [[ -n "$range_max" ]]; then
                            local v_base=$(echo "$clean_version" | cut -d'-' -f1)
                            local min_base=$(echo "$range_min" | cut -d'-' -f1)
                            local max_base=$(echo "$range_max" | cut -d'-' -f1)
                            # Check if version is in range: min <= version <= max
                            # Version >= min
                            local min_check=$(printf '%s\n%s\n' "$v_base" "$min_base" | sort -V | tail -n1)
                            # Version <= max  
                            local max_check=$(printf '%s\n%s\n' "$v_base" "$max_base" | sort -V | head -n1)
                            if [[ "$min_check" == "$v_base" ]] && [[ "$max_check" == "$v_base" ]]; then
                                in_range=true
                                break
                            fi
                        fi
                    done
                    if [[ "$in_range" == "true" ]]; then
                        vulnerable_versions="$clean_version"  # Mark as vulnerable
                    fi
                fi
            else
                # Fallback without jq - use global or try simple extraction
                vulnerable_versions="$global_vulnerable_versions"
                patched_versions="$global_patched_versions"
                min_vulnerable="$global_min_vulnerable"
            fi
        else
            # Old format: use global versions
            vulnerable_versions="$global_vulnerable_versions"
            patched_versions="$global_patched_versions"
            min_vulnerable="$global_min_vulnerable"
        fi
        
        # Check if vulnerable
        local is_vulnerable=false
        
        # Check against vulnerable versions list
        if [[ -n "$vulnerable_versions" ]]; then
            while IFS= read -r vuln_ver; do
                [[ -z "$vuln_ver" ]] && continue
                if [[ "$clean_version" == "$vuln_ver" ]]; then
                    is_vulnerable=true
                    break
                fi
            done <<< "$vulnerable_versions"
        fi
        
        # Check against minimum version (if not already vulnerable)
        if [[ "$is_vulnerable" == "false" ]] && [[ -n "$min_vulnerable" ]]; then
            # Simple version comparison
            local v_base=$(echo "$clean_version" | cut -d'-' -f1)
            local m_base=$(echo "$min_vulnerable" | cut -d'-' -f1)
            local result=$(printf '%s\n%s\n' "$v_base" "$m_base" | sort -V | head -n1)
            
            if [[ "$v_base" == "$result" ]] && [[ "$v_base" != "$m_base" ]]; then
                # version < min_vulnerable, not vulnerable
                is_vulnerable=false
            elif [[ "$v_base" != "$m_base" ]]; then
                # version >= min_vulnerable, potentially vulnerable
                # Check if it's patched
                local is_patched=false
                while IFS= read -r patched_ver; do
                    [[ -z "$patched_ver" ]] && continue
                    if [[ "$clean_version" == "$patched_ver" ]]; then
                        is_patched=true
                        break
                    fi
                done <<< "$patched_versions"
                
                if [[ "$is_patched" == "false" ]]; then
                    is_vulnerable=true
                fi
            fi
        fi
        
        if [[ "$is_vulnerable" == "true" ]]; then
            echo -e "${RED}✗ VULNERABLE: $package@$clean_version${NC}"
            found=1
        elif [[ -n "$clean_version" ]]; then
            # Check if it's patched
            local is_patched=false
            while IFS= read -r patched_ver; do
                [[ -z "$patched_ver" ]] && continue
                if [[ "$clean_version" == "$patched_ver" ]]; then
                    is_patched=true
                    break
                fi
            done <<< "$patched_versions"
            
            if [[ "$is_patched" == "true" ]]; then
                [[ "$VERBOSE" == "true" ]] && \
                    echo -e "${GREEN}✓ SAFE: $package@$clean_version (patched)${NC}"
            elif [[ "$VERBOSE" == "true" ]]; then
                echo -e "${GREEN}✓ SAFE: $package@$clean_version${NC}"
            fi
        fi
    done <<< "$packages"
    
    return $found
}

# Check running processes
check_processes() {
    local config_file="$1"
    local threat_name="$3"
    local found=0
    
    local processes=$(get_config_array "$config_file" "process_patterns")
    
    # If no processes or only empty lines, return 0 (nothing found)
    if [[ -z "$processes" ]] || [[ -z "$(echo "$processes" | grep -v '^[[:space:]]*$')" ]]; then
        return 0
    fi
    
    while IFS= read -r pattern; do
        [[ -z "$pattern" ]] && continue
        
        if pgrep -f "$pattern" > /dev/null 2>&1; then
            echo -e "${RED}✗ Suspicious process running: $pattern${NC}"
            found=1
        fi
    done <<< "$processes"
    
    return $found
}

# Scan for a single threat
scan_threat() {
    local config_file="$1"
    local scan_dir="$2"
    local threat_name=$(basename "$config_file" .json)
    
    local name=$(get_config_value "$config_file" "name")
    local description=$(get_config_value "$config_file" "description")
    local cve=$(get_config_value "$config_file" "cve")
    local reference=$(get_config_value "$config_file" "reference")
    
    [[ -z "$name" ]] && name="$threat_name"
    
    echo -e "${CYAN}Checking: $name${NC}"
    [[ -n "$cve" ]] && echo -e "  CVE: $cve"
    [[ -n "$description" ]] && echo -e "  $description"
    echo "----------------------------------------"
    
    local threat_found=0
    
    # Run all checks (functions return 1 if threat found, 0 if nothing found)
    # Use || to execute when function returns non-zero (threat found)
    check_file_patterns "$config_file" "$scan_dir" "$threat_name" || threat_found=1
    check_directory_patterns "$config_file" "$scan_dir" "$threat_name" || threat_found=1
    check_string_markers "$config_file" "$scan_dir" "$threat_name" || threat_found=1
    check_package_versions "$config_file" "$scan_dir" "$threat_name" || threat_found=1
    check_tool_versions "$config_file" "$scan_dir" "$threat_name" || threat_found=1
    check_processes "$config_file" "$scan_dir" "$threat_name" || threat_found=1
    
    if [[ $threat_found -eq 1 ]]; then
        echo ""
        echo -e "${RED}⚠️  INDICATORS FOUND for $name!${NC}"
        
        # Print remediation steps
        local remediation=$(get_config_array "$config_file" "remediation")
        if [[ -n "$remediation" ]]; then
            echo ""
            echo "Recommended actions:"
            while IFS= read -r step; do
                [[ -n "$step" ]] && echo "  - $step"
            done <<< "$remediation"
        fi
        
        [[ -n "$reference" ]] && echo "  Reference: $reference"
        echo ""
        
        FOUND_INDICATORS=$((FOUND_INDICATORS + 1))
    else
        echo -e "${GREEN}✓ No indicators found${NC}"
        echo ""
    fi
    
    SCANNED_THREATS+=("$name")
    TOTAL_THREATS=$((TOTAL_THREATS + 1))
    
    return $threat_found
}

# Main scanning function
main() {
    echo "=========================================="
    echo "  Configurable Security Scanner"
    echo "=========================================="
    echo ""
    
    if [[ ! -d "$CONFIG_DIR" ]]; then
        echo -e "${RED}Error: Config directory not found: $CONFIG_DIR${NC}" >&2
        echo "Create threat config files in $CONFIG_DIR/*.json" >&2
        exit 1
    fi
    
    # Find all threat config files
    local config_files=()
    if [[ -n "$THREAT_FILTER" ]]; then
        # Filter by threat name
        for file in "$CONFIG_DIR"/*.json; do
            [[ -f "$file" ]] || continue
            local threat_name=$(basename "$file" .json)
            if [[ "$threat_name" == *"$THREAT_FILTER"* ]]; then
                config_files+=("$file")
            fi
        done
    else
        # All threats
        for file in "$CONFIG_DIR"/*.json; do
            [[ -f "$file" ]] && config_files+=("$file")
        done
    fi
    
    if [[ ${#config_files[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No threat configurations found in $CONFIG_DIR${NC}" >&2
        exit 1
    fi
    
    echo -e "${BLUE}Found ${#config_files[@]} threat configuration(s)${NC}"
    echo ""
    
    # Scan each directory (deduplicate)
    local prev_dir=""
    for scan_dir in "${SCAN_DIRS[@]}"; do
        # Expand ~ to home directory
        scan_dir="${scan_dir/#\~/$HOME}"
        
        # Normalize path and skip if same as previous
        local normalized_dir=$(cd "$scan_dir" 2>/dev/null && pwd || echo "$scan_dir")
        if [[ "$normalized_dir" == "$prev_dir" ]]; then
            continue
        fi
        prev_dir="$normalized_dir"
        
        if [[ ! -d "$scan_dir" ]]; then
            echo -e "${YELLOW}Warning: Directory not found: $scan_dir${NC}" >&2
            continue
        fi
        
        # Warn if scanning home directory (can be slow)
        if [[ "$normalized_dir" == "$HOME" ]] || [[ "$normalized_dir" == "$HOME/"* ]]; then
            echo -e "${YELLOW}⚠ Warning: Scanning home directory - this may take a while${NC}"
            echo -e "${YELLOW}  System directories (Library, .cache, etc.) will be excluded${NC}"
            echo ""
        fi
        
        echo -e "${CYAN}Scanning: $scan_dir${NC}"
        echo "=========================================="
        echo ""
        
        # Scan each threat
        for config_file in "${config_files[@]}"; do
            scan_threat "$config_file" "$scan_dir" || true
            
            # Check if this threat config has scan_home enabled
            local config_scan_home=$(get_config_value "$config_file" "scan_home")
            if [[ "$config_scan_home" == "true" ]] || [[ "$config_scan_home" == "1" ]]; then
                # Check if home directory is different from current scan_dir
                local home_normalized=$(cd "$HOME" 2>/dev/null && pwd || echo "$HOME")
                if [[ "$normalized_dir" != "$home_normalized" ]]; then
                    # Scan home directory for this specific threat
                    if [[ "$VERBOSE" == "true" ]]; then
                        echo -e "${BLUE}ℹ Threat config requires home directory scan${NC}"
                    fi
                    scan_threat "$config_file" "$HOME" || true
                fi
            fi
        done
    done
    
    # Summary
    echo "=========================================="
    echo "  Scan Summary"
    echo "=========================================="
    echo -e "Threats scanned: ${#SCANNED_THREATS[@]}"
    echo -e "Indicators found: $FOUND_INDICATORS"
    echo ""
    
    if [[ $FOUND_INDICATORS -gt 0 ]]; then
        echo -e "${RED}⚠️  SECURITY ISSUES DETECTED!${NC}"
        exit 2
    else
        echo -e "${GREEN}✓ No security issues detected${NC}"
        exit 0
    fi
}

main "$@"

