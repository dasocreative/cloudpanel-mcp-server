# Recorded samples

Output of a real CloudPanel server, used by the `clpctl` simulator and the parser tests.

- Recorded from CloudPanel **2.5.4**, over SSH without a terminal, exit status 0.
- `usage-listing.txt`: `clpctl` with no argument (28 commands). Unmodified; the example values are CloudPanel's own (`john.doe`, `www.domain.com`).
- `vhost-templates-list.txt`: `clpctl vhost-templates:list`. Unmodified (public template names).
- `user-list.txt`: the layout of `clpctl user:list`. The rows are **synthetic**; the real rows were masked before anyone read them.

Anything else in the simulator is derived from the official documentation (docs/COMMAND-REFERENCE.md) or from observations
recorded there.
