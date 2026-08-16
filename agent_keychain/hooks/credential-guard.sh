#!/bin/bash
# Credential Guard Hook
# Blocks reads of credential material before it reaches the AI agent and
# directs the agent to use the MCP `safe_read_file` tool instead.
#
# Three layers of defense (best-effort, not a sandbox — see SECURITY.md):
#   1. Path blocklist: any command that references a known sensitive
#      credential path is blocked regardless of which tool/verb is used.
#      This catches grep, awk, python -c, `< file` redirection, etc.
#   2. Vault access: block commands that read secrets straight out of the
#      vault, bypassing the proxy. Moving a secret into the keychain only
#      removes it from the paths an agent stumbles onto — the keychain is
#      still reachable by anything running as the same user, so the
#      retrieval APIs need blocking too.
#   3. Content scan: for files named on the command line, scan the actual
#      contents for credential patterns and block if any are found.

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')

# --- Read tool: scan the exact file being read -------------------------------
if [ "$TOOL_NAME" = "Read" ]; then
    FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')
    COMMAND=""
elif [ "$TOOL_NAME" = "Bash" ]; then
    COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
    FILE_PATH=""
else
    exit 0
fi

# Credential patterns used for content scanning.
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

# Known sensitive credential paths (matched as substrings of the command).
# Referencing any of these — by any tool — is blocked outright.
SENSITIVE_PATH_PATTERNS=(
    '\.aws/credentials'
    '\.aws/config'
    '\.ssh/id_[a-z0-9]+'        # private keys (id_rsa, id_ed25519, ...)
    '\.ssh/identity'
    '\.npmrc'
    '\.git-credentials'
    '\.docker/config\.json'
    '\.kube/config'
    '\.config/gh/hosts\.yml'
    '(^|[^A-Za-z0-9._/])\.env([^A-Za-z0-9]|$)'   # .env / project .env
    '\.agent-keychain/store\.json'               # our own file-backend vault
)

# Ways to pull a secret straight out of the vault, bypassing the proxy.
# Matched against the command text. These target the *retrieval* calls
# specifically — not any mention of the module — so that reading or
# searching the source stays unblocked while an actual read-out does not.
VAULT_ACCESS_PATTERNS=(
    'security[[:space:]]+(find-generic-password|find-internet-password|dump-keychain)'
    'get_password[[:space:]]*\('     # keyring.get_password(...)
    '\.retrieve[[:space:]]*\('       # KeychainVault.retrieve(...)
)

# The file backend's location is configurable; block wherever it actually is.
if [ -n "$AGENT_KEYCHAIN_STORE" ]; then
    SENSITIVE_PATH_PATTERNS+=("$(echo "$AGENT_KEYCHAIN_STORE" | sed 's/[.[\*^$]/\\&/g')")
fi

block() {
    echo "Credential Guard: $1 Use the MCP tool 'safe_read_file' instead to read files safely with automatic redaction." >&2
    exit 2
}

block_vault() {
    echo "Credential Guard: $1 Secrets are never handed out — use the MCP tool 'secure_http_request' to make an authenticated call, or 'agent-keychain exec' for a non-HTTP tool. Neither returns the secret itself." >&2
    exit 2
}

scan_file_contents() {
    # Block if the given existing file contains any credential pattern.
    local f="$1"
    [ -f "$f" ] || return 0
    for pattern in "${PATTERNS[@]}"; do
        if grep -qE "$pattern" "$f" 2>/dev/null; then
            block "credentials detected in '$f'."
        fi
    done
}

# --- Read tool path ----------------------------------------------------------
if [ "$TOOL_NAME" = "Read" ]; then
    [ -z "$FILE_PATH" ] && exit 0
    scan_file_contents "$FILE_PATH"
    exit 0
fi

# --- Bash tool path ----------------------------------------------------------
[ -z "$COMMAND" ] && exit 0

# Layer 1: path blocklist — reference to a known sensitive path is blocked
# regardless of the command verb (grep, awk, python -c, redirection, ...).
for pattern in "${SENSITIVE_PATH_PATTERNS[@]}"; do
    if echo "$COMMAND" | grep -qE "$pattern"; then
        block "command references a known credential path."
    fi
done

# Layer 2: vault access — block reading a secret straight out of the store.
# The keychain is not a boundary against something running as the same user,
# so the retrieval paths have to be blocked explicitly.
for pattern in "${VAULT_ACCESS_PATTERNS[@]}"; do
    if echo "$COMMAND" | grep -qE "$pattern"; then
        block_vault "command reads a secret directly from the vault, bypassing the proxy."
    fi
done

# Verbs that surface file *contents* (and thus could leak secrets to the agent).
# Content scanning only applies to these — so `rm`/`mv`/`chmod` on a file that
# happens to contain a secret are not blocked (they never reveal the contents).
READ_VERBS='cat|head|tail|less|more|bat|grep|egrep|fgrep|rg|ag|awk|sed|nl|tac|od|xxd|hexdump|strings|cut|sort|uniq|tr|rev|base64|dd|vi|vim|view|nano|emacs|jq|yq'

# Layer 3: content scan — split the command into segments on pipes/chains,
# strip flags, and scan tokens that resolve to existing files. Only segments
# whose verb reads contents (or that use `<` input redirection) are scanned.
SEGMENTS=$(echo "$COMMAND" | tr '|;' '\n' | sed 's/&&/\n/g; s/||/\n/g')

while IFS= read -r segment; do
    [ -z "$segment" ] && continue
    verb=$(echo "$segment" | awk '{print $1}')
    if ! echo "$verb" | grep -qE "^($READ_VERBS)$" && ! echo "$segment" | grep -q '<'; then
        continue
    fi
    # Tokenize; consider both plain args and `< file` redirection targets.
    for token in $segment; do
        # Skip option flags like -n, --color.
        case "$token" in
            -*) continue ;;
            '<'|'>'|'>>') continue ;;
        esac
        # Strip surrounding quotes and a leading redirection operator.
        clean=$(echo "$token" | sed "s/^[<>]*//; s/[\"']//g")
        [ -z "$clean" ] && continue
        scan_file_contents "$clean"
    done
done <<< "$SEGMENTS"

exit 0
