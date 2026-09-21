# 🧰 toolbox

One registry indexes every script you own; a web UI and a CLI both read from it.
A strict folder monitor discovers tagged folders on disk and dispatches only the
targets they explicitly declare.

## Design (why it's organized this way)
- **`lib/registry.js`** — the script registry. Scans the locations in `config.json`,
  reads a metadata header from each script, and writes `registry.json`.
- **`lib/monitor.js`** — the strict folder dispatcher: discover → state → dispatch → track.
- **`server.js`** — web UI: live monitor (Ready/Thinking/Gone + dispatch state +
  output tails) and a category dropdown + Run button, on `127.0.0.1:7842`.
- **`bin/tb`** — the CLI, over both the registry and the monitor.

Scripts are indexed **in place** — nothing is moved or copied, so existing paths keep working.

## Folder monitor (strict dispatch)

A second half of the toolbox watches *folders* and acts only on explicit,
disk-declared state. The rules are deliberately conservative:

- **Discovery is disk-only.** Only folders whose *name* carries a tag are seen:
  - `(r) name` → **Ready** — eligible to dispatch, but only if it defines a target.
  - `(t) name` → **Thinking** — inspect-only, never dispatched.
  - anything else → **untouched** (never enters the monitor).
- **State is explicit.** Nothing is inferred from contents or heuristics; the tag
  in the folder name is the only state signal.
- **Dispatch is specific.** A Ready folder fires *exactly* the target in its
  `tb.launch.json` (or a `launchTargets` config match) — never a catch-all.
  Ready alone does not fire: no defined target means no dispatch.
- **Monitoring is concrete.** Only folders that were actually discovered and
  dispatched are tracked. Dispatched-then-removed folders keep their history and
  are marked `gone`; never-dispatched phantoms are dropped.

A Ready folder defines its target with `tb.launch.json`:
    { "script": "<id-or-path>", "nodes": ["<id>", ...], "args": [] }

Runs are logged under `runs/` (`<dispatch>__<node>.log` / `.exit`), so state and
output tails survive restarts.

## CLI (2nd interface)
    tb index [--force]   # discover tagged folders, dispatch (r) targets, reconcile
    tb status            # only what was really discovered / dispatched
    tb watch [secs]      # re-index on a loop (persistent monitor)
    tb list              # every script, grouped by category
    tb run <id> [args]   # run one by id (full stdio)
    tb scan              # re-index after adding/removing scripts
    tb serve             # start the web UI
    tb path <id>         # print a script's path

## Web UI
    tb serve             # then open http://127.0.0.1:7842
The **monitor** panel shows each discovered folder's state and, for Ready folders,
its dispatch + per-run status and output tail. It refreshes live; **Re-index** runs
the same reconcile as `tb index`. The **manual run** dropdown is grouped by category,
and Run streams the script's output back.

Note the asymmetry on purpose: the monitor refreshes *state* continuously but only
discovers on an explicit Re-index, so nothing new is ever dispatched implicitly.

## Make a script show up nicely
Drop a header comment anywhere in the first ~25 lines:
    # @tb name: My Tool
    # @tb desc: what it does in one line
    # @tb category: system
Without it, the name comes from the filename, the category from the parent folder,
and the description from the first real comment line.

## Add / change indexed locations
Edit `config.json` → `sources` (supports `~`), then `tb scan`.

## Notes
- Server binds to **127.0.0.1 only** (never exposed to the network).
- The web Run button only executes scripts already in the registry (allowlist by id).
- Runs use your own user permissions — same as running the script yourself.
- Long-running scripts are killed after `runTimeoutSec` (default 45s) in the WEB ui;
  use `tb run` in the terminal for interactive or long-lived ones.
