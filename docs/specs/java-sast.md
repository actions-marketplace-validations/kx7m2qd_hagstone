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
  categories). Special-casing benchmark helpers is not allowed.
- **Cross-file taint (2026-11-25, `src/engines/java-xfile.ts`).** Opengrep has none, so we build method
  summaries with Opengrep itself: "parameter k of `Class.method` reaches a sink" and "`Class.method`
  returns request data", then inject calls to those methods as sinks/sources into copies of the Java
  rules, repeating until nothing new is found (max 5 rounds). Findings at an injected sink move to the
  inner sink, with the call site kept in the data flow. Calls are matched by receiver type (the class,
  project supertypes, subtypes; never siblings or library supertypes such as `HttpServlet`), and a
  summary is kept only if another file calls the method and names that type; simple class names
  declared in several files are skipped. Without that filter the benchmark produced ~1,150 summaries
  (every `doGet` and per-file `doSomething`), 1.1 GB of rules and a crash; with it, 4 summaries.
  Result: every injection category has 0 misses; average 0.72 → 0.77 (cmdi 0.67 → 0.74, sqli 0.68 →
  0.73, pathtraver 0.56 → 0.64, trustbound 0.40 → 0.54, xss 0.75 → 0.85, ldapi 0.67 → 0.75). xpathi
  0.78 → 0.75: two more `switch`/`list.remove(0)` false positives now reachable from
  `SeparateClassRequest` (accepted, above). Benchmark scan ~3 min. `--no-xfile` on `bench:owasp`
  turns it off.
- **Cross-file precision guards (from real projects).** (1) Overloads: when the declaring file has
  several methods with that name, the injected sink requires the argument's declared type
  (`MD5.getHashString(String)` must not match the `File` overload's sink). (2) A method whose request
  data comes only from its own parameters (a controller's `@RequestParam`) is not a source for its
  callers; their arguments decide. (3) A call from test or example code is never relocated into
  production code.
- **JdbcTemplate by name** when its type isn't visible (a static field of another class): receivers
  named `*jdbc*` with JdbcTemplate method names.

## Real projects (2026-11-20; cross-file re-run 2026-11-25)

- 2026-11-25, cross-file on: petclinic still 0; WebGoat 21 → 22, the new one a real command injection
  (`@RequestParam("base")` in `CommandInjectionTask2` → `/bin/sh -c` in `CommandExecutionService`).
  Before the guards above it was 25 (an overload mix-up in `MD5`, two test-file calls into
  controllers). WebGoat Java scan 5 s → ~35 s (summary rounds).

- spring-petclinic: 0 Java findings.
- WebGoat: 21, all in vulnerable lessons; spot-checked three (WebWolf upload path, weak random secret,
  audit-log SQL through a helper): all real. Not yet covered: XXE, deserialization, SSRF, open
  redirect, SpEL/script injection, JWT, Spring Security misconfiguration.

## Next

1. Rules for the uncovered classes above, then MyBatis `${}` in XML mappers and eGovFrame.
2. Real-CVE-fix cases for Java (like `bench:cves`).
