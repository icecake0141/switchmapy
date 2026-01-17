<!--
Copyright 2025 OpenAI
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

This file was created or modified with the assistance of an AI (Large Language Model).
Review required for correctness, security, and licensing.
-->

# XSS Regression Test Documentation

## Overview

This document describes the XSS (Cross-Site Scripting) regression tests added to `test_build_site.py` to prevent future security vulnerabilities in HTML rendering.

## Background: The Vulnerability (Issue #1)

### The Problem

The original code used this Jinja2 autoescape configuration:

```python
Environment(
    loader=FileSystemLoader(str(template_dir)),
    autoescape=select_autoescape(["html"]),  # Only matches .html files
)
```

This configuration **only** enabled autoescaping for files ending in `.html`. Since all templates use the `.html.j2` extension, they were **NOT autoescaped**, creating a stored XSS vulnerability.

### The Fix

The fix changed the configuration to include the `j2` extension:

```python
Environment(
    loader=FileSystemLoader(str(template_dir)),
    autoescape=select_autoescape(["html", "j2"]),  # Now matches .html.j2
)
```

## Test Coverage

The regression test suite includes 8 tests covering all XSS attack surfaces:

### 1. `test_build_site_escapes_xss_in_user_controlled_data`

**Purpose:** Comprehensive test of XSS escaping across multiple fields and HTML pages.

**Coverage:**
- Switch vendor field with `<script>` tags
- Port descriptions with `<img onerror>` payloads
- Port descriptions with `onclick` event handlers
- Failed switch names with XSS payloads

**Validates:**
- XSS payloads are escaped in index.html, switch pages, and ports pages
- Script tags appear as `&lt;script&gt;` instead of `<script>`
- All three major output pages (index, switch, ports) properly escape

**Would fail without fix:** ✓ Yes - XSS payloads would render unescaped

### 2. `test_build_site_escapes_switch_name_in_multiple_contexts`

**Purpose:** Test switch name escaping in various HTML contexts.

**Coverage:**
- Switch names in page titles
- Switch names in headers (h1, h2)
- Switch names in link text
- Switch names in href attributes

**Validates:**
- Ampersands (`&`) are escaped to `&amp;`
- Quotes (`"`) are escaped to `&quot;` or `&#34;`
- Proper escaping in both element content and attributes

**Would fail without fix:** ✓ Yes - Special characters would not be escaped

### 3. `test_build_site_escapes_mac_list_in_search_json`

**Purpose:** Test MAC list data in search JSON output.

**Coverage:**
- MAC hostnames with XSS payloads
- IP addresses with injection attempts
- JSON serialization of untrusted data

**Validates:**
- JSON properly encodes/escapes HTML characters
- Search index.json contains escaped data
- JavaScript rendering via textContent is safe

**Would fail without fix:** ✓ Partially - HTML in templates would be vulnerable, JSON encoding provides some protection

### 4. `test_build_site_escapes_all_port_fields`

**Purpose:** Comprehensive test of all port-related fields.

**Coverage:**
- port.name (interface name)
- port.descr (description)
- port.admin_status
- port.oper_status
- port.vlan

**Validates:**
- All SNMP-sourced port data is properly escaped
- Multiple XSS vectors are blocked (script, img, onclick)
- Quotes are escaped as `&#34;` HTML entities

**Would fail without fix:** ✓ Yes - All fields would render unescaped

### 5. `test_build_site_escapes_management_ip_and_vendor`

**Purpose:** Test switch-level metadata fields.

**Coverage:**
- Switch vendor strings from SNMP
- Management IP addresses

**Validates:**
- SNMP vendor strings with XSS are escaped
- Management IPs with injection attempts are escaped

**Would fail without fix:** ✓ Yes - Vendor strings would render unescaped

### 6. `test_build_site_escapes_failed_switches_list`

**Purpose:** Test failed switch names on index page.

**Coverage:**
- Failed switch names displayed in error list

**Validates:**
- Switch names in error conditions are still escaped
- Unescaped script tags do not appear in output

**Would fail without fix:** ✓ Yes - Failed switch names would render unescaped

### 7. `test_build_site_prevents_attribute_injection_in_links`

**Purpose:** Test attribute injection prevention in href attributes.

**Coverage:**
- Switch names used in href attributes
- Attempts to close attributes and inject onclick handlers

**Validates:**
- Quotes in switch names don't break out of href
- onclick attributes cannot be injected
- Proper HTML attribute escaping

**Would fail without fix:** ✓ Yes - Attribute injection would succeed

### 8. `test_build_site_copies_binary_assets`

**Purpose:** Non-security test for asset copying (already existed).

**Would fail without fix:** N/A - Not security-related

## Attack Surfaces Covered

### User-Controlled Data Sources

All tests cover data that can come from untrusted sources:

1. **SNMP Responses:**
   - Switch names
   - Port descriptions (ifDescr)
   - Vendor strings (sysDescr)
   - Port names (ifName)
   - Admin/operational status
   - VLAN IDs

2. **CSV/ARP Data:**
   - MAC addresses
   - IP addresses
   - Hostnames (from reverse DNS)

3. **Configuration Files:**
   - Switch names
   - Management IP addresses

### HTML Contexts Tested

- Text content (between tags)
- Attribute values (href, onclick potential)
- JSON data (for JavaScript consumption)
- Page titles
- Link text

## Regression Verification

### Proof That Tests Catch the Vulnerability

A verification script demonstrates that:

1. **With vulnerable config** (`select_autoescape(["html"])`):
   - XSS payloads like `<script>alert(1)</script>` render **unescaped**
   - Tests would **FAIL** with assertion errors

2. **With fixed config** (`select_autoescape(["html", "j2"])`):
   - XSS payloads are **escaped** as `&lt;script&gt;alert(1)&lt;/script&gt;`
   - Tests **PASS**

See `/tmp/test_vulnerable.py` for the verification script used during development.

## Test Execution

All tests pass with the current (fixed) code:

```bash
$ pytest tests/test_build_site.py -v
# 8 tests PASSED
```

Full test suite (26 tests) also passes:

```bash
$ pytest tests/ -v
# 26 tests PASSED
```

## Future Maintenance

### Adding New Templates

When adding new Jinja2 templates:

1. Ensure they have `.html.j2` or `.j2` extension
2. Verify autoescape is enabled for the extension
3. Add regression tests for any user-controlled data

### Adding New User-Controlled Fields

When exposing new data sources:

1. Identify if data comes from SNMP, CSV, or user configuration
2. Add test cases with XSS payloads in the new field
3. Verify both HTML and JSON outputs

### Modifying Autoescape Configuration

**WARNING:** Changing `select_autoescape()` configuration can reintroduce vulnerabilities.

If modification is needed:
1. Run the full test suite first
2. Verify all XSS tests still pass
3. Consider adding tests for the new configuration

## References

- **Issue #1:** Initial XSS vulnerability report and fix
- **Jinja2 Documentation:** https://jinja.palletsprojects.com/en/3.1.x/api/#autoescaping
- **OWASP XSS Guide:** https://owasp.org/www-community/attacks/xss/
