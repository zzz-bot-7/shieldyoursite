# Scan Policy

Shield reports a project score, not a compliance certification or a clone of another scanner.

## Graded Controls

| Control | Weight |
|---|---:|
| Strict-Transport-Security | 20 |
| Content-Security-Policy | 25 |
| Frame protection | 15 |
| X-Content-Type-Options | 15 |
| Referrer-Policy | 10 |
| Permissions-Policy | 10 |
| X-XSS-Protection lifecycle | 5 |

Pass receives full weight. Warning receives exactly half weight, including half-points. Fail receives zero. The final normalized score is rounded to the nearest whole number after all controls are summed.
Controls that do not apply receive no weight, and the score is normalized over
the remaining controls. On HTTPS responses, HSTS is not applicable to IP-literal
targets because RFC 6797 defines HSTS hosts by domain name. Plain HTTP still
fails the transport check.

| Score | Grade |
|---:|---|
| 100 | A+ |
| 90-99 | A |
| 80-89 | B |
| 70-79 | C |
| 60-69 | D |
| 40-59 | E |
| 0-39 | F |

## Contextual Controls

The following are reported but not graded because correct deployment depends on the response and application:

- Cache-Control
- Cross-Origin-Embedder-Policy
- Cross-Origin-Opener-Policy
- Cross-Origin-Resource-Policy
- X-Permitted-Cross-Domain-Policies

## Important Decisions

- HSTS with `max-age=0` fails because it removes HSTS state.
- CSP is inspected for effective script directives. Wildcards, broad schemes,
  broad wildcard hosts, unsafe evaluation, and uncontrolled inline scripts warn.
- Frame protection can be supplied by CSP `frame-ancestors` or valid
  X-Frame-Options. Broad schemes and wildcard hosts warn.
- `X-Content-Type-Options` passes only with `nosniff`.
- `unsafe-url` fails Referrer-Policy.
- Permissions-Policy warns if any declared feature uses the unrestricted `*`
  allowlist.
- Missing X-XSS-Protection passes. Nonzero values warn because the header is deprecated.
- Resource detection parses URL hosts. Text appearing in a query or path is not treated as a provider match.

## Scan Limits

- A scan sends one GET request, follows at most five public-network-only redirects, and evaluates only the final successful response.
- Requests have a 5-second connection timeout and a 15-second total timeout.
- HTML body analysis stops at 2 MiB. Security-header evaluation still uses the final response headers.
- Platform detection uses fixed header signatures. Its confidence is heuristic, not proof of the hosting platform.
- Resource detection checks selected HTML element URLs against a fixed provider catalog. It does not observe JavaScript execution, CSS loads, browser network activity, or unlisted providers.
- False positives and false negatives are expected at these heuristic boundaries. Confirm material findings against the target configuration and browser behavior.

## Sources

- [OWASP Secure Headers Project](https://github.com/OWASP/www-project-secure-headers)
- [RFC 6797: HTTP Strict Transport Security](https://www.rfc-editor.org/rfc/rfc6797)
- [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/)
- [Fetch Standard](https://fetch.spec.whatwg.org/)
- [RFC 7034: X-Frame-Options](https://www.rfc-editor.org/rfc/rfc7034)
- [Referrer Policy](https://www.w3.org/TR/referrer-policy/)
- [Permissions Policy](https://www.w3.org/TR/permissions-policy/)
