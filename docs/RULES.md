# Rules and evidence

The scanner revision is `firmguard-1.0-rules-1`; the advisory revision is `2026-11-02-curated-1`. Increment these identifiers when changing detection or version semantics. Compare releases with identical revisions.

Credential rules recognize password/passwd/pwd, admin/root passwords, Wi-Fi keys, PSK, API keys/tokens and private-key headers. Assignments in comments, empty values, null/redacted placeholders and `${...}` or `{{...}}` references are ignored. Values are never included in findings. This intentionally favors explanation over complex language parsing and can produce false positives/negatives.

Configuration rules inspect explicit directives only. SSH rules apply to files named `sshd_config`; anonymous FTP applies to `vsftpd.conf`; account-field checks apply to `passwd`/`shadow`. General key-value rules inspect Telnet, TLS verification and debug settings. SNMP, forwarding and permission metadata are also checked. SSH Match blocks are labelled conditional; includes, precedence and defaults are not interpreted. Permission values come from archive metadata and can differ from installed device permissions.

ELF inspection uses [pyelftools](https://github.com/eliben/pyelftools) and numeric dynamic tags. NX uses PT_GNU_STACK; missing headers remain unknown. PIE applies to ET_EXEC versus ET_DYN executable evidence, not ordinary shared libraries. Full RELRO requires GNU_RELRO plus immediate binding. Canary/FORTIFY are recognized-symbol evidence, not proof of instrumentation on every function. There is no ASLR runtime test or binary execution.

The supported version inventory families are listed in the README. dpkg/opkg-style records must have recognized Package and Version fields. Other software or metadata formats are not inventoried. Version strings and package metadata can refer to unused code and can be forged.

## Curated advisory ranges

| Product | Rule range | Reference |
|---|---|---|
| OpenSSL | 1.0.1 through 1.0.1f; fixed at 1.0.1g | [CVE-2014-0160](https://www.cve.org/CVERecord?id=CVE-2014-0160), [upstream release notes](https://github.com/openssl/openssl/blob/master/NEWS.md) |
| dnsmasq | 2.0 to before 2.78 (the rule intentionally limits its lower bound to the 2.x series) | [CVE-2017-14491](https://www.cve.org/CVERecord?id=CVE-2017-14491), [NVD record](https://nvd.nist.gov/vuln/detail/CVE-2017-14491) |

These historical ranges are supplied for reproducible offline checks, not as a current vulnerability feed. Vendor backports/build options are not resolved. Beta/prerelease, epoch, distribution and vendor-suffixed versions remain unmapped by these upstream comparisons. “No curated match” is not a claim of no CVEs, current support, or an up-to-date release. A patch suffix inside the known OpenSSL release series is ordered alphabetically. All listed product families can appear in inventory even when no advisory rule covers them.

Extend the reviewed JSON rules and the corresponding boundary tests together, and increment the advisory revision. The app does not send samples or version evidence to an online service.
