# Dependency Security Audit Notes — lodash & axios

**Scope:** `lodash` and `axios`, flagged by this sprint's dependency scanner.
**Advisory source:** GitHub's public security advisory database (github.com/advisories).
**Method:** For each package, the advisory affecting it with the highest severity was selected from the database.

---

## 1. lodash

| Field | Value |
| --- | --- |
| Package name | `lodash` (npm) |
| Official repository | [lodash/lodash](https://github.com/lodash/lodash) |
| GHSA id | **GHSA-jf85-cpcp-j695** |
| CVE | **CVE-2019-10744** |
| Severity | **Critical** (CVSS 3.1 score 9.1, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`) |
| Affected versions | `< 4.17.12` |
| First fixed version | **4.17.12** |
| Fix present in release history? | **Partially.** The git tag `4.17.12` exists in `lodash/lodash` (tagged 2019-07-09), but the repository publishes GitHub Releases only for a small subset of versions — its Releases page currently lists just `4.18.1`, `4.18.0`, and `4.0.0`. So the fix is present as a **tag** but does **not** appear as a formal GitHub Release. |
| Latest release seen during this check | **4.18.1** (published 2026-04-01) |
| Recommendation | Upgrade lodash to at least 4.17.12 (preferably the latest 4.18.1) to clear the critical prototype-pollulation finding in `defaultsDeep`. |

**Notes on the advisory:** Versions of `lodash` before 4.17.12 are vulnerable to prototype pollution. The `defaultsDeep` function allows a malicious user to modify the prototype of `Object` via `{constructor: {prototype: {...}}}`, causing the addition or modification of an existing property that will exist on all objects. CWE-20 / CWE-1321.

---

## 2. axios

| Field | Value |
| --- | --- |
| Package name | `axios` (npm) |
| Official repository | [axios/axios](https://github.com/axios/axios) |
| GHSA id | **GHSA-m8m8-qj5v-23w3** |
| CVE | **CVE-2026-101905** |
| Severity | **High** |
| Affected versions | `>= 1.15.2, < 1.20.0` |
| First fixed version | **1.20.0** |
| Fix present in release history? | **Yes.** `v1.20.0` is a published GitHub Release on the `v1.x` line, and its notes explicitly cover the runtime-option hardening security fix. |
| Latest release seen during this check | **v1.20.0** (published 2026-08-24) — the latest release on the default `v1.x` line. (A separate `0.x` maintenance line exists; its newest release, `v0.34.0`, is dated later but is not the main line.) |
| Recommendation | Upgrade axios to at least 1.20.0 to close the high-severity socket-hijack gadget in the Node HTTP adapter. |

**Notes on the advisory:** Axios' Node HTTP adapter can act as a read-side prototype-pollution gadget for Node's sensitive `createConnection` request option. The adapter creates a null-prototype options object, but Node's HTTP client can copy or normalize request options into ordinary objects before connection creation. If `Object.prototype.createConnection` has been polluted elsewhere in the same process, Node can call the inherited function and create a socket to an attacker-controlled endpoint — enabling credential exfiltration and response manipulation while the request URL still appears to target the legitimate origin. CWE-441 / CWE-1321. Axios is the gadget, not the pollution source: the precondition is a separate same-process prototype-pollution primitive.

---

## Release-history verification detail

- **lodash:** the fix version `4.17.12` resolves to a real git tag in the repo, but the project does not maintain a complete GitHub Releases list, so it never appears there. Anyone confirming the fix via the Releases page alone would miss it; use the tags list or npm instead.
- **axios:** the fix version `1.20.0` is directly visible as a GitHub Release, and the release notes reference the security hardening that landed in it.
