# Rule reference

Every rule, its category and the points it adds. Weights live in `src/phishcheck/data/rules.json`.

## Sender / headers

| Rule | Points | Fires when |
|---|---|---|
| `H_REPLYTO_MISMATCH` | 15 | Replies go to a different address |
| `H_RETURNPATH_MISMATCH` | 8 | Hidden sending address (Return-Path) is different (ignored when DMARC passes) |
| `H_DISPLAY_EMAIL_SPOOF` | 20 | Sender name shows a fake email address |
| `H_DISPLAY_BRAND_SPOOF` | 20 | Sender name claims a brand the domain does not belong to |
| `H_FREEMAIL_BRAND` | 15 | Brand name sent from a free personal account |
| `H_SENDER_LOOKALIKE` | 25 | Sender domain imitates a brand |
| `H_SPF_FAIL` | 15 | SPF fail / permerror |
| `H_SPF_SOFTFAIL` | 8 | SPF softfail |
| `H_DKIM_FAIL` | 15 | DKIM fail |
| `H_DMARC_FAIL` | 20 | DMARC fail |
| `H_NO_AUTH` | 5 | No Authentication-Results header |
| `H_MSGID_MISMATCH` | 5 | Message-ID from an unrelated domain (ignored when DMARC passes) |
| `H_NO_RECEIVED` | 0 | No Received headers (informational) |

## Links

| Rule | Points | Fires when |
|---|---|---|
| `L_TEXT_HREF_MISMATCH` | 25 | Link text hides the real destination |
| `L_IP_URL` | 20 | Link goes to a bare IP address |
| `L_SHORTENER` | 10 | Shortened link hides the destination |
| `L_PUNYCODE` | 20 | Website name uses special look-alike characters |
| `L_LOOKALIKE` | 30 | Link imitates a well-known brand |
| `L_SUSPICIOUS_TLD` | 10 | Link uses a domain ending often abused by scammers |
| `L_AT_SIGN` | 20 | Link contains an @ symbol |
| `L_MANY_SUBDOMAINS` | 10 | Link has an unusually long chain of sub-domains |
| `L_NO_HTTPS` | 5 | Link is not encrypted (http instead of https) |

## Wording

| Rule | Points | Fires when |
|---|---|---|
| `C_URGENCY` | 10 | Pressure to act quickly |
| `C_CREDENTIALS` | 15 | Asks for passwords, OTP or payment details |
| `C_INDIA_SCAM` | 15 | Uses wording from common Indian scams |
| `C_PRIZE` | 15 | Promises a prize or reward |
| `C_GENERIC_GREETING` | 5 | Generic greeting instead of your name |
| `C_ENABLE_CONTENT` | 15 | Tells you to enable macros |

## Attachments

| Rule | Points | Fires when |
|---|---|---|
| `A_DANGEROUS_EXT` | 40 | Executable or script attachment |
| `A_DOUBLE_EXT` | 30 | Double extension (invoice.pdf.exe) |
| `A_MACRO` | 25 | Macro-enabled or VBA-containing Office file |
| `A_HTML_ATTACHMENT` | 20 | HTML / SVG attachment |
| `A_ARCHIVE` | 10 | Archive attachment |

Wording rules add 5 extra points when three or more different phrases from the same list appear.

`H_NO_HEADERS` (0 points) is reported when only a message body was pasted.

Optional VirusTotal rules (only with `--virustotal` and `VT_API_KEY`): `VT_FILE` 50 points, `VT_URL` 40 points.
