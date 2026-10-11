# Contributing to Kazeshini

Thank you for contributing to Kazeshini!

## Developer Certificate of Origin (DCO)

All commits contributed to Kazeshini must include a `Signed-off-by` line indicating
agreement with the [Developer Certificate of Origin (DCO)](https://developercertificate.org/):

```text
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it; and

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

To automatically sign your commits:
```bash
git commit -s -m "feat(sensors): add network socket sensor"
```

## Commit Guidelines
- Use [Conventional Commits](https://www.conventionalcommits.org/):
  - `feat(...)`: new feature or capability
  - `fix(...)`: bug fix
  - `docs(...)`: documentation changes
  - `test(...)`: test improvements
  - `refactor(...)`: non-functional code changes
- Keep commits focused and logically atomic.

## Coding Standards
- Standard library first. Any new dependency must be proposed and justified in [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md).
- Add SPDX headers (`// SPDX-License-Identifier: Apache-2.0`) on all source files.
- Run `make test` and `make lint` before submitting PRs.

