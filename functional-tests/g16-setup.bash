# Full mosaic circuit mode (MOSAIC_CIRCUIT_MODE=full): generate the REAL g16
# Groth16 circuit (134 GB v5c.ckt) from this run's counterproof vkey using
# alpenlabs/g16's g16-pipeline. Generation takes about an hour, dominated by
# ckt-lvl-prealloc (measurements in README.md, "Full mosaic circuit mode"), so it
# runs in the background overlapping the remaining cargo builds; run_test.sh waits
# on it right before entry.py starts and exports MOSAIC_CIRCUIT_PATH for the
# mosaic node configs.
#
# Sourced from run_test.sh after sp1-setup.bash (CWD = repo root); defines
# functions and the globals below, nothing else runs on source. Knobs (all optional):
#   G16_REF          alpenlabs/g16 ref (default: G16_DEFAULT_REF in circuit-gen.yml)
#   G16_DIR          existing g16 checkout (CI pre-clones it for rust-cache);
#                    else cloned into functional-tests/.g16-src
#   G16_RUNS_DIR     pipeline output dir (default functional-tests/_dd/.g16-runs)
#   G16_MIN_FREE_GB  disk preflight threshold (default 600)

G16_GEN_PID=""
G16_GEN_LOG=""
G16_GEN_START=0
G16_VKEY=""

g16_start_generation() {
    # The circuit embeds this run's counterproof vkey, emitted by the SP1 guest
    # build in sp1-setup.bash — it must already exist.
    local vkey="guest-builder/sp1/elfs/counterproof-vkey.bin"
    if [ ! -f "$vkey" ]; then
        echo "ERROR: $vkey not found; full circuit mode needs the SP1 guest build (BRIDGE_PROOF_SP1=1)" >&2
        exit 1
    fi
    G16_VKEY="$(realpath "$vkey")"

    # Single source of truth for the pin: circuit-gen.yml's G16_DEFAULT_REF.
    if [ -z "${G16_REF:-}" ]; then
        G16_REF="$(sed -n 's/^[[:space:]]*G16_DEFAULT_REF:[[:space:]]*//p' .github/workflows/circuit-gen.yml | head -n 1)"
    fi
    if [ -z "$G16_REF" ]; then
        echo "ERROR: G16_REF unset and G16_DEFAULT_REF not found in .github/workflows/circuit-gen.yml" >&2
        exit 1
    fi

    G16_RUNS_DIR="${G16_RUNS_DIR:-$(realpath functional-tests)/_dd/.g16-runs}"
    mkdir -p "$G16_RUNS_DIR"
    G16_GEN_LOG="$G16_RUNS_DIR/g16-gen.log"

    # Disk preflight. Generation alone peaks near 400 GB before the prune below, and the
    # test phase then shares this mount with the garbled tables and FoundationDB (numbers
    # in README.md). 600, not 320: a 320 GB threshold passes preflight and then runs the
    # mount dry mid-generation.
    local min_free_gb="${G16_MIN_FREE_GB:-600}"
    local free_gb
    free_gb=$(df -Pk "$G16_RUNS_DIR" | awk 'NR==2 { print int($4 / 1048576) }')
    if [ "$free_gb" -lt "$min_free_gb" ]; then
        echo "ERROR: ${free_gb} GB free on the $G16_RUNS_DIR mount; need >= ${min_free_gb} GB (tune with G16_MIN_FREE_GB)" >&2
        exit 1
    fi

    # CI pre-clones g16 (G16_DIR) so Swatinem/rust-cache covers its build; local
    # runs clone into functional-tests/.g16-src (same pattern as .asm-src in
    # sp1-setup.bash).
    if [ -n "${G16_DIR:-}" ]; then
        if [ ! -d "$G16_DIR" ]; then
            echo "ERROR: G16_DIR=$G16_DIR does not exist" >&2
            exit 1
        fi
    else
        G16_DIR="$(realpath functional-tests)/.g16-src"
        local current_commit target_commit
        current_commit="$(git -C "$G16_DIR" rev-parse HEAD 2>/dev/null || true)"
        target_commit="$(git -C "$G16_DIR" rev-parse "$G16_REF^{commit}" 2>/dev/null || true)"
        if [ -z "$target_commit" ] || [ "$current_commit" != "$target_commit" ]; then
            rm -rf "$G16_DIR"
            git clone https://github.com/alpenlabs/g16 "$G16_DIR"
            git -C "$G16_DIR" checkout "$G16_REF"
        fi
    fi
    G16_DIR="$(realpath "$G16_DIR")"

    # Foreground build so compile errors fail fast and the background job is pure
    # execution. Pre-build g16gen too: the pipeline spawns it via `cargo run` at
    # runtime (mirrors circuit-gen.yml). `rustup show` installs g16's pinned
    # toolchain.
    ( cd "$G16_DIR" && rustup show && cargo build --release -p g16-pipeline -p g16gen )

    echo "starting g16 circuit generation in background (g16 $G16_REF, log: $G16_GEN_LOG)"
    # `exec` makes G16_GEN_PID the pipeline process itself. It must also lead its own
    # process group, or the EXIT-trap kill reaps only the pipeline and orphans the
    # g16gen children it spawns via `cargo run` — a multi-hour CPU-bound leak.
    #
    # `set -m` (job control) puts each background job in a new process group whose
    # PGID equals its PID, which is what `kill -- -$PID` in the cleanup needs. It is
    # portable, unlike setsid, which does not exist on macOS. stdin is closed because
    # a background job in its own group gets SIGTTIN if it ever reads the terminal.
    set -m
    ( cd "$G16_DIR" && exec ./target/release/g16-pipeline gen \
        --vkey "$G16_VKEY" --runs-dir "$G16_RUNS_DIR" ) < /dev/null > "$G16_GEN_LOG" 2>&1 &
    G16_GEN_PID=$!
    set +m
    G16_GEN_START=$SECONDS
}

g16_wait_for_circuit() {
    echo "waiting for background g16 circuit generation (pid $G16_GEN_PID)"
    local rc=0
    wait "$G16_GEN_PID" || rc=$?
    G16_GEN_PID=""
    if [ "$rc" -ne 0 ]; then
        echo "ERROR: g16-pipeline gen failed (exit $rc); last 100 log lines:" >&2
        tail -n 100 "$G16_GEN_LOG" >&2 || true
        exit "$rc"
    fi
    echo "g16 circuit generation finished after $(( (SECONDS - G16_GEN_START) / 60 )) min"

    # Locate v5c.ckt: latest/ symlink, else newest run-* (mirrors _locate_v5c in
    # .github/scripts/circuit_gen.py).
    local ckt="$G16_RUNS_DIR/latest/v5c.ckt"
    if [ ! -e "$ckt" ]; then
        ckt="$(ls -1 "$G16_RUNS_DIR"/run-*/v5c.ckt 2>/dev/null | sort | tail -n 1 || true)"
    fi
    if [ -z "$ckt" ] || [ ! -f "$ckt" ]; then
        echo "ERROR: no v5c.ckt under $G16_RUNS_DIR; see $G16_GEN_LOG" >&2
        exit 1
    fi
    export MOSAIC_CIRCUIT_PATH="$(realpath "$ckt")"
    echo "MOSAIC_CIRCUIT_PATH=$MOSAIC_CIRCUIT_PATH ($(du -h "$MOSAIC_CIRCUIT_PATH" | cut -f1))"

    # Prune the large intermediates: only v5c.ckt is consumed by mosaic, and
    # garbled tables + FoundationDB need this disk during the test phase.
    find "$(dirname "$MOSAIC_CIRCUIT_PATH")" -maxdepth 1 -type f \
        ! -name 'v5c.ckt' -size +100M -print -delete || true
    df -h "$G16_RUNS_DIR" | tail -n 1
}

# Installed as an EXIT trap by run_test.sh in full mode: if a foreground build
# fails while the gen is still running, don't orphan a multi-hour CPU-bound
# process.
g16_cleanup_on_exit() {
    if [ -n "${G16_GEN_PID:-}" ] && kill -0 "$G16_GEN_PID" 2>/dev/null; then
        echo "reaping background g16 generation (pid $G16_GEN_PID)"
        # `set -m` at launch made the pid its own process-group leader, so the group
        # kill takes the g16gen children with it. The single-pid kill is a belt-and-
        # braces fallback in case job control was unavailable.
        kill -- "-$G16_GEN_PID" 2>/dev/null || kill "$G16_GEN_PID" 2>/dev/null || true
    fi
}
