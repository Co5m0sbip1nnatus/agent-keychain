#!/bin/bash
# Credential Guard Hook
# Blocks reads of credential material before it reaches the AI agent and
# directs the agent to use the MCP `safe_read_file` tool instead.
#
# Layers of defense (best-effort, not a sandbox — see SECURITY.md):
#   1. Path blocklist: any command that references a known sensitive
#      credential path is blocked regardless of which tool/verb is used.
#      This catches grep, awk, python -c, `< file` redirection, etc.
#   2. Vault access: block commands that read secrets straight out of the
#      vault, bypassing the proxy. Moving a secret into the keychain only
#      removes it from the paths an agent stumbles onto — the keychain is
#      still reachable by anything running as the same user, so the
#      retrieval APIs need blocking too.
#   2b. Credential emitters: commands whose documented function is printing
#      a secret (gh auth token, gcloud auth print-access-token, ...).
#   2c. Env hunting: env/printenv/echo aimed at secret-named variables —
#      env output is not a file, so the content scan never sees it.
#   3. Content scan: for files named on the command line (~ expanded), scan
#      the actual contents for credential patterns and block if any found.

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')

# --- Self-protection ---------------------------------------------------------
# The guard must guard itself: a benign agent that hits a block will
# helpfully try to "fix" the obstacle by editing the hook, deregistering it
# from settings, or running `agent-keychain uninstall`. All of that is a
# human decision, so it is blocked here.
#
# Lifted in exactly two cases (checked against the HOOK's own environment,
# which an agent cannot set from a command line):
#   - AGENT_KEYCHAIN_UNGUARD is set by the operator, or
#   - the session is developing agent-keychain itself (the hook source
#     lives in the project) — otherwise the tool could not work on its
#     own guard.
SELF_PROTECT=1
[ -n "$AGENT_KEYCHAIN_UNGUARD" ] && SELF_PROTECT=0
[ -f "$CLAUDE_PROJECT_DIR/agent_keychain/hooks/credential-guard.sh" ] && SELF_PROTECT=0

PROTECTED_PATHS='credential-guard\.sh|\.claude/settings(\.local)?\.json'
# Verbs/redirects that can modify a file. Pure reads of the hook stay
# allowed — it contains no secrets.
WRITEISH='(^|[;&|[:space:]])(rm|mv|cp|chmod|chattr|truncate|tee|sed|perl|ruby|python[0-9.]*)([[:space:]]|$)|>>?'

block_self() {
    echo "Credential Guard: $1 The guard and its registration are protected; changing or removing them is a decision for the human operator." >&2
    exit 2
}

# --- Read tool: scan the exact file being read -------------------------------
if [ "$TOOL_NAME" = "Read" ]; then
    FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')
    COMMAND=""
elif [ "$TOOL_NAME" = "Bash" ]; then
    COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
    FILE_PATH=""
elif [ "$TOOL_NAME" = "Edit" ] || [ "$TOOL_NAME" = "Write" ] || [ "$TOOL_NAME" = "MultiEdit" ] || [ "$TOOL_NAME" = "NotebookEdit" ]; then
    # Write-capable tools are only inspected for self-protection.
    TARGET=$(echo "$INPUT" | jq -r '.tool_input.file_path // .tool_input.notebook_path // empty')
    if [ "$SELF_PROTECT" = 1 ] && echo "$TARGET" | grep -qE "$PROTECTED_PATHS"; then
        block_self "this edit would modify the credential guard or its registration."
    fi
    exit 0
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
    # Name-hint: an exported variable with a secret-ish NAME marks the file
    # as credential-bearing even when the value has no recognizable format.
    # (Careful wording here: a literal example would match the pattern below
    # and make the hook flag its own source.)
    'export[[:space:]]+[A-Za-z_]*(TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY|CREDENTIAL)[A-Za-z_]*='
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
    '(^|[^A-Za-z0-9._])\.env([^A-Za-z0-9]|$)'    # .env anywhere: ~/.env, dir/.env
                                                 # (leading class must NOT exclude
                                                 #  '/', or path/.env slips through)
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

# Commands whose documented FUNCTION is printing a credential to stdout.
# A benign agent runs these while "checking your setup" -- and the secret
# lands straight in its context. Route through `agent-keychain exec` instead.
EMITTER_PATTERNS=(
    'gh[[:space:]]+auth[[:space:]]+token'
    'aws[[:space:]]+configure[[:space:]]+export-credentials'
    'gcloud[[:space:]]+auth[[:space:]]+(application-default[[:space:]]+)?print-(access|identity)-token'
    'kubectl[[:space:]]+config[[:space:]]+view[[:space:]].*--raw'
)

# Environment-variable hunting: env output is not a file, so the content
# scan never sees it. Targeted patterns only -- a bare `env` for ordinary
# debugging stays allowed (documented residual; see SECURITY.md).
ENV_HUNT_PATTERNS=(
    '(env|printenv|set)[[:space:]]*\|[^|]*(-i[[:space:]])?[^|]*([Tt][Oo][Kk][Ee][Nn]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Aa][Pp][Ii]_?[Kk][Ee][Yy])'
    'printenv[[:space:]]+[A-Za-z_]*(TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY|CREDENTIAL)'
    '(echo|printf)[[:space:]][^|;&]*\$\{?[A-Za-z_]*(TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY|CREDENTIAL)'
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

block_emitter() {
    echo "Credential Guard: $1 Its output would put a secret into the agent context. If the authenticated action itself is needed, run it via 'agent-keychain exec' (output is DLP-scrubbed), or ask the human to run it." >&2
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

# Self-protection first: tampering with the guard, its registration, or
# running uninstall is a human decision. Reads of the hook stay allowed.
if [ "$SELF_PROTECT" = 1 ]; then
    if echo "$COMMAND" | grep -qE 'agent-keychain[[:space:]]+uninstall'; then
        block_self "uninstalling the credential guard from a command is not allowed."
    fi
    if echo "$COMMAND" | grep -qE "$PROTECTED_PATHS" && echo "$COMMAND" | grep -qE "$WRITEISH"; then
        block_self "command could modify the credential guard or its registration."
    fi
fi

# Layer 1: path blocklist — reference to a known sensitive path is blocked
# regardless of the command verb (grep, awk, python -c, redirection, ...).
# Known-clean .env variants (.env.example etc.) are exempted first, so the
# real thing (.env, .env.local, .env.production) still blocks even when an
# exempt name appears in the same command.
CHKCMD=$(echo "$COMMAND" | sed -E 's/\.env\.(example|sample|template|dist)[A-Za-z0-9._-]*//g')
for pattern in "${SENSITIVE_PATH_PATTERNS[@]}"; do
    if echo "$CHKCMD" | grep -qE "$pattern"; then
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

# Layer 2b: credential-emitting commands — printing a secret is their function.
for pattern in "${EMITTER_PATTERNS[@]}"; do
    if echo "$COMMAND" | grep -qE "$pattern"; then
        block_emitter "this command prints a credential to stdout."
    fi
done

# Layer 2c: environment-variable hunting — env output never passes the
# content scan (it is not a file), so the hunt itself is what gets blocked.
for pattern in "${ENV_HUNT_PATTERNS[@]}"; do
    if echo "$COMMAND" | grep -qE "$pattern"; then
        block_emitter "command extracts secrets from environment variables."
    fi
done

# Verbs that surface file *contents* (and thus could leak secrets to the agent).
# Content scanning only applies to these — so `rm`/`mv`/`chmod` on a file that
# happens to contain a secret are not blocked (they never reveal the contents).
READ_VERBS='cat|head|tail|less|more|bat|grep|egrep|fgrep|rg|ag|awk|sed|nl|tac|od|xxd|hexdump|strings|cut|sort|uniq|tr|rev|base64|dd|vi|vim|view|nano|emacs|jq|yq'

# Layer 3: content scan — split the command into segments on pipes/chains,
# strip flags, and scan tokens that resolve to existing files. Only segments
# whose verb reads contents (or that use `<` input redirection) are scanned.
#
# Segmentation runs on a copy with quoted spans blanked out: a `|` inside a
# quoted grep pattern is not a pipe, and splitting on it used to push the
# file argument into a segment whose "verb" was pattern text — skipping the
# scan entirely. Quoted tokens are scanned separately below.
SEGSRC=$(echo "$COMMAND" | sed "s/'[^']*'//g" | sed 's/"[^"]*"//g')
SEGMENTS=$(echo "$SEGSRC" | tr '|;' '\n' | sed 's/&&/\n/g; s/||/\n/g')

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
        # Expand a leading ~ — [ -f "~/.gitconfig" ] never matches the real
        # file, so unexpanded tildes used to bypass the content scan entirely.
        case "$clean" in
            "~") clean="$HOME" ;;
            "~/"*) clean="$HOME/${clean#\~/}" ;;
        esac
        scan_file_contents "$clean"
    done
done <<< "$SEGMENTS"

# Quoted tokens were blanked out of the segmentation above; if the command
# involves a content-reading verb anywhere, scan them as candidate files
# (e.g. cat 'my secrets.txt').
if echo "$SEGSRC" | grep -qE "(^|[[:space:]|;&(])($READ_VERBS)([[:space:]]|$)" || echo "$SEGSRC" | grep -q '<'; then
    while IFS= read -r qtoken; do
        [ -z "$qtoken" ] && continue
        case "$qtoken" in
            "~") qtoken="$HOME" ;;
            "~/"*) qtoken="$HOME/${qtoken#\~/}" ;;
        esac
        scan_file_contents "$qtoken"
    done <<< "$(echo "$COMMAND" | grep -oE "'[^']*'|\"[^\"]*\"" | sed "s/^[\"']//; s/[\"']$//")"
fi

exit 0
