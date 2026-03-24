# ============================================================
# OPA Rego Policy — Secure Agentic Browser Action Validation
# ============================================================
#
# Package: browser.action
#
# This policy evaluates two kinds of input:
#   1. action_intent   — the LLM's structured intent payload
#   2. network_request — an intercepted outbound HTTP request
#
# Decision document: data.browser.action
#   • allow  (boolean)  — true only if ALL rules pass
#   • reasons (set)     — human-readable denial reasons (empty when allowed)
# ============================================================

package browser.action

import rego.v1

# ----- helpers ------------------------------------------------

_origin(url) := origin if {
    parts := split(url, "/")
    count(parts) >= 3
    origin := concat("/", [parts[0], "", parts[2]])
}

_host(url) := host if {
    parts := split(url, "/")
    count(parts) >= 3
    host_port := parts[2]
    host := split(host_port, ":")[0]
}

_domain_allowed(url) if {
    host := _host(url)
    some domain in input.allowed_domains
    endswith(host, domain)
}

# ----- default ------------------------------------------------

default allow := false

# Allow only when there are zero denial reasons
allow if {
    count(reasons) == 0
}

# ----- denial reasons ----------------------------------------

# 1. POST requests must target the same origin as the current page
reasons contains "cross-origin POST blocked" if {
    req := input.network_request
    req != null
    req.method == "POST"
    intent := input.action_intent
    intent != null
    intent.current_page_origin != ""
    _origin(req.url) != intent.current_page_origin
}

# 2. Navigations to domains not on the allowlist
reasons contains "navigation to disallowed domain" if {
    req := input.network_request
    req != null
    req.resource_type == "document"
    not _domain_allowed(req.url)
}

# 3. Block interactions with sensitive selectors
_sensitive_selectors := {
    "input[type=password]",
    "input[type='password']",
    "form[action*=login]",
    "form[action*='login']",
    "#password",
    "#passwd",
    ".password-field",
}

reasons contains "interaction with sensitive selector blocked" if {
    intent := input.action_intent
    intent != null
    some sel in _sensitive_selectors
    contains(intent.selector, sel)
}

# 4. Block clicks on elements flagged as hidden by the sanitizer
reasons contains "interaction with hidden element blocked" if {
    intent := input.action_intent
    intent != null
    intent.is_hidden_element == true
}

# 5. Block potential data exfiltration
reasons contains "outbound body exceeds size limit to unknown domain" if {
    req := input.network_request
    req != null
    req.body_size > input.max_outbound_body_bytes
    not _domain_allowed(req.url)
}
