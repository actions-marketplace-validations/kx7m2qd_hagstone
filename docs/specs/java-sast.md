# Java SAST (roadmap step 3, first language)

Status: 11 rules built 2026-11-20. Gate: `npm run bench:owasp:java` (per category, CI) and the
`bench/cases/spring-app` case in `npm run bench`.

## Rules (`rules/java/`)

| Rule | CWE | Sources → sinks |
|---|---|---|
| `java-sql-injection` | 89 | request → `Statement.execute*`, `prepareStatement(concat)`, JdbcTemplate, JPA/Hibernate `createQuery`/`createNativeQuery` |
| `java-command-injection` | 78 | request → `Runtime.exec`, `ProcessBuilder` (command, arguments, environment) |
| `java-path-traversal` | 22 | request, `MultipartFile.getOriginalFilename()` → `File`, file streams, `Paths.get`, `Path.resolve` |
| `java-ldap-injection` | 90 | request → `DirContext.search` base / filter (not `{0}` arguments) |
| `java-xpath-injection` | 643 | request → `XPath.compile` / `evaluate` |
| `java-xss` | 79 | request → `response.getWriter()` / `getOutputStream()` writes |
| `java-trust-boundary` | 501 | request → `HttpSession.setAttribute` / `putValue` |
| `java-weak-hash` | 328 | `MessageDigest` MD2/MD4/MD5/SHA-1, commons-codec and Guava equivalents |
| `java-weak-cipher` | 327 | DES/3DES/RC2/RC4/Blowfish, ECB, bare `"AES"` (not RSA/ECB) |
| `java-weak-random` | 330 | `java.util.Random` / `Math.random` / `RandomStringUtils` → cookie, session, header, `set*Token` |
| `java-insecure-cookie` | 614 | `setSecure(false)`, cookie added without `setSecure(true)`, `ResponseCookie.secure(false)` |

Shared: sources are servlet request getters (javax + jakarta) and Spring MVC / JAX-RS parameter
annotations, matched at the parameter's declaration so dataflow (and guards) apply; numeric, boolean,
UUID and date parameters are not sources. Sanitizers: numeric parsing, and an allowlist or regex
guard that rejects the value (`if (!allowed.contains(x)) throw …`, `if (!x.matches(re)) return`).

## Decisions (measured on the OWASP Benchmark for Java v1.2, 2,740 tests)

- **`--taint-intrafile` for Java only.** Average score 0.53 → 0.72 for Java (`--no-intrafile` reproduces the lower one) (helpers in the same file
  return constants in most "safe" tests). For Python it adds false positives and drops 5 categories
  below their gate, so the scan runs two Opengrep passes in parallel (`rulePasses`).
- **No container propagators.** A `List.add` propagator changed nothing with intrafile on.
- **Accepted false positives:** the benchmark's `list.remove(0)` index shifting and `switch` on a
  constant char. Modelling them would be tuning to the benchmark.
- **Accepted misses:** hash/crypto algorithms read from a properties file at run time (~30% of those
  categories), and `SeparateClassRequest` (request read in another file: 87 of 119 injection misses).
  Special-casing benchmark helpers is not allowed.
- **JdbcTemplate by name** when its type isn't visible (a static field of another class): receivers
  named `*jdbc*` with JdbcTemplate method names.

## Real projects (2026-11-20)

- spring-petclinic: 0 Java findings.
- WebGoat: 21, all in vulnerable lessons; spot-checked three (WebWolf upload path, weak random secret,
  audit-log SQL through a helper): all real. Not yet covered: XXE, deserialization, SSRF, open
  redirect, SpEL/script injection, JWT, Spring Security misconfiguration.

## Next

1. Cross-file taint for Java (controller → service → repository), since Opengrep has none.
2. Rules for the uncovered classes above, then MyBatis `${}` in XML mappers and eGovFrame.
3. Real-CVE-fix cases for Java (like `bench:cves`).
