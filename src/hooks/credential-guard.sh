#!/bin/bash
# Credential Guard Hook
# Blocks file reads that contain credentials and directs the agent to use safe_read_file instead.

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')

# Get file path depending on the tool
if [ "$TOOL_NAME" = "Read" ]; then
    FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')
elif [ "$TOOL_NAME" = "Bash" ]; then
    COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
    # Check if command reads files (cat, head, tail, less, more)
    if echo "$COMMAND" | grep -qE '^\s*(cat|head|tail|less|more)\s+'; then
        FILE_PATH=$(echo "$COMMAND" | grep -oE '(cat|head|tail|less|more)\s+(.+)' | awk '{print $2}' | tr -d '"'"'")
    else
        exit 0
    fi
else
    exit 0
fi

# Skip if no file path found
[ -z "$FILE_PATH" ] && exit 0

# Skip non-existent files
[ ! -f "$FILE_PATH" ] && exit 0

# Scan for credential patterns
PATTERNS=(
    'AKIA[0-9A-Z]{16}'
    'ghp_[A-Za-z0-9]{36}'
    'github_pat_[A-Za-z0-9_]{82}'
    'sk-[A-Za-z0-9]{48}'
    'sk-ant-[A-Za-z0-9\-]{36,}'
    'sk_(test|live)_[A-Za-z0-9]{24,}'
    'xoxb-[A-Za-z0-9\-]+'
    'xoxp-[A-Za-z0-9\-]+'
    '-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----'
    '(postgres|mysql|mongodb)(ql)?://[^:]+:[^@]+@'
    'glpat-[A-Za-z0-9\-]{20}'
    'SG\.[A-Za-z0-9\-_.]{22}\.'
)

for pattern in "${PATTERNS[@]}"; do
    if grep -qE "$pattern" "$FILE_PATH" 2>/dev/null; then
        echo "Credential Guard: credentials detected in '$FILE_PATH'. Use the MCP tool 'safe_read_file' instead to read this file safely with automatic redaction." >&2
        exit 2
    fi
done

exit 0
