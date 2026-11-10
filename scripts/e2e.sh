#!/usr/bin/env bash
# Local loopback regression run for exvia.
#
# Usage:
#   ./scripts/e2e.sh                    # port 28443, self-managed temp dir
#   PORT=28443 DIR=/tmp/exvia-e2e ./scripts/e2e.sh
#
# Starts a relay on 127.0.0.1:$PORT with a temporary data dir, generates the
# long-lived CLI identities, enrolls one agent, then runs the checks with an
# isolated HOME. Each result is recorded; any failure makes the script exit
# non-zero. Child processes are cleaned up on exit.
#
# Keep this on its own high port and never point it at a live relay or a real
# config directory. The custom cert name and WS prefix exercise the deployment
# settings; the scratch HOME is deliberately left out of the agent allowlist.
set -u
cd "$(dirname "$0")/.."

# 每个用例用独立 HOME 隔离身份，而 XDG_* 指向固定路径时配置会越过 HOME
# 串号（GitHub runner 就显式设置了 XDG_CONFIG_HOME）：HOME_A/HOME_B 会共享同
# 一把 CLI 身份，跨用户可见性、allowlist、cfgdir 探针全部失真。这里只认 HOME。
unset XDG_CONFIG_HOME XDG_DATA_HOME XDG_STATE_HOME XDG_CACHE_HOME

# 交互会话测试（如 stdin EOF 收尾）依赖登录 shell 对 EOF 的确定性响应；
# agent 的 pty 会话用 $SHELL 拉起登录 shell，固定为 bash 使整套回归不随
# 运行环境的登录 shell 配置变化（个别 shell 配置会忽略 EOF，会话不退出）
export SHELL=/bin/bash

PORT="${PORT:-28443}"
METRICS_PORT="${METRICS_PORT:-28444}"
DIR="${DIR:-$(mktemp -d /tmp/exvia-e2e-XXXXXX)}"
BIN="${BIN:-$PWD/target/release}"
# custom values exercise the deployment settings
WS_PREFIX="${WS_PREFIX:-/svc/ops}"
CERT_NAME="${CERT_NAME:-relay.internal.example}"
DATA="$DIR/relay"                 # temp relay data dir
AGENT_DIR="$DIR/agent"
HOME_A="$DIR/home-admin"          # admin HOME
HOME_B="$DIR/home-bob"
HOME_E="$DIR/home-eve"
HOME_X="$DIR/home-scratch"        # scratch HOME for failure checks
HOME_T="$DIR/home-trust"          # key added through the trust session
mkdir -p "$DATA" "$AGENT_DIR" "$HOME_A" "$HOME_B" "$HOME_E" "$HOME_X" "$HOME_T"

RELAY_LOG="$DIR/relay.log"
AGENT_LOG="$DIR/agent.log"

# ---- result tally (keep going after a failure) ----
pass=0
fail=0
RES=()
record() { # record name rc(0=pass) [note]
    local name=$1 rc=$2 note=${3:-}
    if [[ $rc -eq 0 ]]; then
        RES+=("PASS | $name${note:+ | $note}")
        pass=$((pass + 1))
    else
        RES+=("FAIL | $name${note:+ | $note}")
        fail=$((fail + 1))
    fi
}

# ---- child processes ----
PIDS=()
spawn() { # spawn log cmd... (background, record pid)
    local log=$1; shift
    "$@" >"$log" 2>&1 &
    PIDS+=($!)
}
cleanup() {
    if (( ${#PIDS[@]} > 0 )); then
        for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    fi
    wait 2>/dev/null
}
trap cleanup EXIT INT TERM

wait_log() { # wait_log log keyword [timeout]
    local log=$1 kw=$2 t=${3:-30} i=0
    while (( i < t * 10 )); do
        grep -q "$kw" "$log" 2>/dev/null && return 0
        sleep 0.1; i=$((i + 1))
    done
    return 1
}
wait_line() { # wait_line cmd keyword [timeout] - retry until output contains keyword
    local cmd=$1 kw=$2 t=${3:-20} i=0 out
    while (( i < t * 2 )); do
        out=$(eval "$cmd" 2>/dev/null) && [[ $out == *"$kw"* ]] && return 0
        sleep 0.5; i=$((i + 1))
    done
    return 1
}

cli() { # cli HOME args... (CLI call with isolated HOME)
    local h=$1; shift
    HOME="$h" "$BIN/exvia" "$@"
}
# BSD stat -f on macOS, GNU stat -c with coreutils
mode_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null; }
mtime_of() { stat -c '%Y' "$1" 2>/dev/null || stat -f '%m' "$1" 2>/dev/null; }
# GNU coreutils on Linux, perl's Digest::SHA elsewhere (macOS); an empty
# result must never pass a checksum assertion by comparing empty to empty
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "error: need sha256sum or shasum for checksum assertions" >&2
        return 1
    fi
}
wait_port() { # wait_port port [timeout tenths]
    local p=$1 i=0 n=${2:-40}
    while (( i < n )); do
        if command -v nc >/dev/null 2>&1; then
            nc -z 127.0.0.1 "$p" 2>/dev/null && return 0
        else
            # 无 nc 的最小环境（如 CI runner）退回 bash 内建 /dev/tcp 探测
            (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
        fi
        sleep 0.1; i=$((i+1))
    done
    return 1
}

echo "==== exvia e2e (port ${PORT}, dir ${DIR}) ===="

# a missing hasher would make every checksum assertion pass vacuously
# (empty == empty); refuse to run instead
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || {
    echo "error: need sha256sum or shasum for checksum assertions" >&2
    exit 1
}
# python3 backs the forward/reverse endpoint echo servers and the JSON probes
command -v python3 >/dev/null 2>&1 || {
    echo "error: need python3 (endpoint echo servers and JSON probes)" >&2
    exit 1
}

# ---------- workspace unit tests ----------
if cargo test --workspace >"$DIR/cargo-test.log" 2>&1; then
    record "cargo test --workspace" 0
else
    record "cargo test --workspace" 1 "see $DIR/cargo-test.log"
fi

# ---------- start relay ----------
if nc -z 127.0.0.1 "$PORT" 2>/dev/null; then
    echo "error: port $PORT is in use, refusing to start" >&2
    exit 1
fi
spawn "$RELAY_LOG" "$BIN/exvia-relay" serve --listen "127.0.0.1:$PORT" --data-dir "$DATA" \
    --ws-prefix "$WS_PREFIX" --cert-name "$CERT_NAME" \
    --metrics-listen "127.0.0.1:$METRICS_PORT"
if ! wait_log "$RELAY_LOG" "Listening on" 30; then
    echo "error: relay failed to start, log:" >&2
    cat "$RELAY_LOG" >&2
    exit 1
fi
# fingerprint and admin token (generated on first start)
FP=$(awk '/Certificate fingerprint/ {print $NF}' "$RELAY_LOG" | head -1)
ADMIN_TOKEN=$(cat "$DATA/admin-token.txt")
echo "fingerprint: $FP"
SERVER="wss://127.0.0.1:$PORT"

# ---------- generate CLI identities and collect the agent allowlist ----------
# Each login reuses cli-identity.json; a new key would fall out of the allowlist.
# HOME_X is deliberately left out of the allowlist.
TRUSTED_ARGS=()
for h in "$HOME_A" "$HOME_B" "$HOME_E"; do
    k=$(cli "$h" pubkey 2>>"$DIR/pubkey.log") || {
        echo "error: exvia pubkey failed (HOME=$h), log:" >&2; cat "$DIR/pubkey.log" >&2; exit 1;
    }
    [[ -n $k ]] || { echo "error: exvia pubkey returned an empty value (HOME=$h)" >&2; exit 1; }
    TRUSTED_ARGS+=(--trusted-cli-key "$k")
done
KEY_A=$(cli "$HOME_A" pubkey)
echo "trusted CLI pubkeys: $((${#TRUSTED_ARGS[@]} / 2)) (scratch HOME excluded)"

# ---------- admin token login and empty ls ----------
rc=0
cli "$HOME_A" login --server "$SERVER" --fingerprint "$FP" --token "$ADMIN_TOKEN" \
    --ws-prefix "$WS_PREFIX" >"$DIR/t1-login.log" 2>&1 || rc=1
ls_out=$(cli "$HOME_A" ls 2>"$DIR/t1-ls.err") || rc=1
# an empty table has a header but no online rows
[[ $ls_out == *"MACHINE_ID"* && $ls_out != *"●"* ]] || rc=1
record "login with admin token, empty ls" $rc

# ---------- token create, enroll, ls shows an online machine ----------
TOK=$("$BIN/exvia-relay" token create --data-dir "$DATA" | head -1)
"$BIN/exvia-agent" enroll --server "$SERVER" --token "$TOK" --fingerprint "$FP" \
    --identity "$AGENT_DIR/identity.json" --ws-prefix "$WS_PREFIX" \
    "${TRUSTED_ARGS[@]}" >"$DIR/t2-enroll.log" 2>&1
rc=$?
if (( rc == 0 )); then
    spawn "$AGENT_LOG" "$BIN/exvia-agent" run --identity "$AGENT_DIR/identity.json"
    AGENT_PID=${PIDS[${#PIDS[@]}-1]}
    if wait_line "cli $HOME_A ls" "●" 20; then
        MID=$(cli "$HOME_A" ls | awk 'NR==2 {print $1}')
        [[ -n ${MID:-} ]] || rc=1
    else
        rc=1
    fi
fi
record "token create, enroll, ls online" $rc "machine=$MID"

# ---------- ping with default count=4 ----------
ping_out=$(cli "$HOME_A" ping "$MID" 2>"$DIR/t3-ping.err")
rc=$?
n_seq=$(printf '%s\n' "$ping_out" | grep -c 'seq=')
(( rc == 0 && n_seq == 4 )) || rc=1
record "ping default count=4" $rc

# ---------- exec stdout/stderr split and exit code 7 ----------
code=0
cli "$HOME_A" exec "$MID" -- /bin/sh -c 'echo to-out; echo to-err 1>&2; exit 7' \
    >"$DIR/t4.out" 2>"$DIR/t4.err" || code=$?
rc=0
(( code == 7 )) || rc=1
grep -q 'to-out' "$DIR/t4.out" || rc=1
grep -q 'to-err' "$DIR/t4.err" || rc=1
grep -q 'to-err' "$DIR/t4.out" && rc=1   # stderr must not leak into stdout
record "exec stdout/stderr split, exit code 7" $rc "exit=$code"

# ---------- shell PTY ----------
printf 'echo hello-pty\nexit\n' | cli "$HOME_A" shell "$MID" >"$DIR/t5.log" 2>&1
rc=$?
grep -q 'hello-pty' "$DIR/t5.log" || rc=1
record "shell PTY over a pipe" $rc

# ---------- put/get 5MB with matching checksums ----------
dd if=/dev/urandom of="$DIR/t6-src.bin" bs=1048576 count=5 2>/dev/null
rc=0
cli "$HOME_A" put "$MID" "$DIR/t6-src.bin" "$DIR/t6-remote.bin" >"$DIR/t6-put.log" 2>&1 || rc=1
cli "$HOME_A" get "$MID" "$DIR/t6-remote.bin" "$DIR/t6-back.bin" >"$DIR/t6-get.log" 2>&1 || rc=1
s1=$(sha256_of "$DIR/t6-src.bin")
s2=$(sha256_of "$DIR/t6-remote.bin")
s3=$(sha256_of "$DIR/t6-back.bin")
[[ $s1 == "$s2" && $s2 == "$s3" ]] || rc=1
record "put/get 5MB checksums" $rc

# ---------- put --resume: finish an interrupted upload from the leftover partial ----------
# 断流后 agent 把分片留在目标旁边（名字带内容哈希），--resume 只补剩下的字节。
rc=0
head -c 2097152 /dev/urandom > "$DIR/t32-src.bin"
wp_sha=$(sha256_of "$DIR/t32-src.bin")
wp_part="$DIR/t32-dst.bin.exvia-part-${wp_sha:0:16}"
head -c 700000 "$DIR/t32-src.bin" > "$wp_part"
cli "$HOME_A" put --resume "$MID" "$DIR/t32-src.bin" "$DIR/t32-dst.bin" >"$DIR/t32-put.log" 2>&1 || rc=1
grep -q 'resuming upload at 700000' "$DIR/t32-put.log" || rc=1
[[ $(sha256_of "$DIR/t32-dst.bin") == "$wp_sha" ]] || rc=1
# 成功后分片必须消失，不能留在目标旁边
[[ -e "$wp_part" ]] && rc=1
# 没有分片时 --resume 退化成普通传输，不能报错
cli "$HOME_A" put --resume "$MID" "$DIR/t32-src.bin" "$DIR/t32-again.bin" >"$DIR/t32-again.log" 2>&1 || rc=1
[[ $(sha256_of "$DIR/t32-again.bin") == "$wp_sha" ]] || rc=1
# 超长分片（比源文件还长）必须整段丢弃重传
head -c 3000000 /dev/urandom > "$DIR/t32-long.bin.exvia-part-${wp_sha:0:16}"
cli "$HOME_A" put --resume "$MID" "$DIR/t32-src.bin" "$DIR/t32-long.bin" >"$DIR/t32-long.log" 2>&1 || rc=1
[[ $(sha256_of "$DIR/t32-long.bin") == "$wp_sha" ]] || rc=1
record "put --resume continues from the leftover partial" $rc

# ---------- get --resume: finish an interrupted download ----------
rc=0
head -c 2097152 /dev/urandom > "$DIR/t33-src.bin"
g_sha=$(sha256_of "$DIR/t33-src.bin")
cli "$HOME_A" put "$MID" "$DIR/t33-src.bin" "$DIR/t33-remote.bin" >/dev/null 2>&1 || rc=1
head -c 512000 "$DIR/t33-src.bin" > "$DIR/t33-back.bin.exvia-part"
cli "$HOME_A" get --resume "$MID" "$DIR/t33-remote.bin" "$DIR/t33-back.bin" >"$DIR/t33-get.log" 2>&1 || rc=1
grep -q 'resuming download at 512000' "$DIR/t33-get.log" || rc=1
[[ $(sha256_of "$DIR/t33-back.bin") == "$g_sha" ]] || rc=1
[[ -e "$DIR/t33-back.bin.exvia-part" ]] && rc=1
record "get --resume continues from the local partial" $rc

# ---------- a bad partial is never spliced into the result ----------
# 本地分片与远端对不上（内容不同/长度超界）时，续传要自己回退到从头传，
# 而不是把两份内容拼在一起；结果必须与远端逐字节一致。
rc=0
head -c 512000 /dev/urandom > "$DIR/t34-back.bin.exvia-part"
cli "$HOME_A" get --resume "$MID" "$DIR/t33-remote.bin" "$DIR/t34-back.bin" >"$DIR/t34.log" 2>&1 || rc=1
[[ $(sha256_of "$DIR/t34-back.bin") == "$g_sha" ]] || rc=1
[[ -e "$DIR/t34-back.bin.exvia-part" ]] && rc=1
# 声称的续传点超过远端文件长度：同样退回从头传
head -c 3000000 /dev/urandom > "$DIR/t34b-back.bin.exvia-part"
cli "$HOME_A" get --resume "$MID" "$DIR/t33-remote.bin" "$DIR/t34b-back.bin" >"$DIR/t34b.log" 2>&1 || rc=1
[[ $(sha256_of "$DIR/t34b-back.bin") == "$g_sha" ]] || rc=1
record "a stale or oversized partial is discarded, not spliced" $rc

# ---------- a hard-killed transfer resumes from where it died ----------
# 这才是 --resume 的真实场景：进程被 kill -9，分片尾巴可能停在半帧上。
# 注意必须直接起二进制：`cli` 是 shell 函数，后台跑时 $! 是子 shell，杀它不会杀到 exvia。
rc=0
head -c 201326592 /dev/urandom > "$DIR/t35-src.bin"   # 192 MiB
k_sha=$(sha256_of "$DIR/t35-src.bin")
k_part="$DIR/t35-dst.bin.exvia-part-${k_sha:0:16}"
HOME="$HOME_A" "$BIN/exvia" put "$MID" "$DIR/t35-src.bin" "$DIR/t35-dst.bin" >"$DIR/t35-put.log" 2>&1 &
KPID=$!
PIDS+=($KPID)
for _ in $(seq 1 400); do
    sz=0
    [[ -e "$k_part" ]] && sz=$(wc -c <"$k_part" 2>/dev/null || echo 0)
    (( sz > 8388608 )) && break
    sleep 0.02
done
kill -9 "$KPID" 2>/dev/null
wait "$KPID" 2>/dev/null
[[ -s "$k_part" ]] || rc=1
# agent 察觉会话断开有毫秒级延迟；用户 Ctrl-C 后重跑也是这个节奏，重试几次
ok=0
for _ in $(seq 1 20); do
    if cli "$HOME_A" put --resume "$MID" "$DIR/t35-src.bin" "$DIR/t35-dst.bin" \
        >"$DIR/t35-resume.log" 2>&1; then ok=1; break; fi
    sleep 0.25
done
[[ $ok == 1 ]] || rc=1
grep -q 'resuming upload at' "$DIR/t35-resume.log" || rc=1
[[ $(sha256_of "$DIR/t35-dst.bin") == "$k_sha" ]] || rc=1
record "a hard-killed upload resumes with --resume" $rc "from=$(grep -o 'resuming upload at [0-9]*' "$DIR/t35-resume.log" | head -1)"

# ---------- same for a download: torn tail is trimmed, not spliced ----------
rc=0
HOME="$HOME_A" "$BIN/exvia" get "$MID" "$DIR/t35-dst.bin" "$DIR/t36-back.bin" >"$DIR/t36-get.log" 2>&1 &
GPID=$!
PIDS+=($GPID)
g_part="$DIR/t36-back.bin.exvia-part"
for _ in $(seq 1 400); do
    sz=0
    [[ -e "$g_part" ]] && sz=$(wc -c <"$g_part" 2>/dev/null || echo 0)
    (( sz > 8388608 )) && break
    sleep 0.02
done
kill -9 "$GPID" 2>/dev/null
wait "$GPID" 2>/dev/null
[[ -s "$g_part" ]] || rc=1
ok=0
for _ in $(seq 1 20); do
    if cli "$HOME_A" get --resume "$MID" "$DIR/t35-dst.bin" "$DIR/t36-back.bin" \
        >"$DIR/t36-resume.log" 2>&1; then ok=1; break; fi
    sleep 0.25
done
[[ $ok == 1 ]] || rc=1
grep -q 'resuming download at' "$DIR/t36-resume.log" || rc=1
[[ $(sha256_of "$DIR/t36-back.bin") == "$k_sha" ]] || rc=1
[[ -e "$g_part" ]] && rc=1
record "a hard-killed download resumes with --resume" $rc "from=$(grep -o 'resuming download at [0-9]*' "$DIR/t36-resume.log" | head -1)"

# ---------- put/get -r: whole tree, mode/mtime, empty dirs ----------
rc=0
mkdir -p "$DIR/t30-src/sub/deep" "$DIR/t30-src/empty"
printf 'alpha' > "$DIR/t30-src/a.txt"
printf 'beta'  > "$DIR/t30-src/sub/b.bin"
head -c 300000 /dev/urandom > "$DIR/t30-src/sub/deep/c.dat"
chmod 750 "$DIR/t30-src/sub"
chmod 640 "$DIR/t30-src/a.txt"
touch -t 202001020304.05 "$DIR/t30-src/a.txt"
cli "$HOME_A" put -r "$MID" "$DIR/t30-src" "$DIR/t30-dst" >"$DIR/t30-put.log" 2>&1 || rc=1
cli "$HOME_A" get -r "$MID" "$DIR/t30-dst" "$DIR/t30-back" >"$DIR/t30-get.log" 2>&1 || rc=1
diff -r "$DIR/t30-src" "$DIR/t30-back" >"$DIR/t30-diff.log" 2>&1 || rc=1
# 空目录必须被还原，否则"传完发现少了个目录"
[[ -d "$DIR/t30-dst/empty" ]] || rc=1
[[ -d "$DIR/t30-back/empty" ]] || rc=1
m_a=$(mode_of "$DIR/t30-dst/a.txt")
m_sub=$(mode_of "$DIR/t30-dst/sub")
[[ $m_a == 640 ]] || rc=1
[[ $m_sub == 750 ]] || rc=1
mt_src=$(mtime_of "$DIR/t30-src/a.txt")
mt_dst=$(mtime_of "$DIR/t30-dst/a.txt")
[[ $mt_src == "$mt_dst" ]] || rc=1
record "put/get -r preserves tree, mode, mtime" $rc \
    "mode=$m_a/$m_sub mtime=$mt_dst"

# ---------- put -r must not write through a symlinked directory ----------
# 目标侧预置 dst/sub -> 外部目录；若不校验，evil.txt 会被写穿到目录树之外
rc=0
mkdir -p "$DIR/t31-src/sub" "$DIR/t31-out" "$DIR/t31-dst"
ln -sfn "$DIR/t31-out" "$DIR/t31-dst/sub"
printf 'should-not-escape' > "$DIR/t31-src/sub/evil.txt"
if cli "$HOME_A" put -r "$MID" "$DIR/t31-src" "$DIR/t31-dst" >"$DIR/t31-put.log" 2>&1; then
    rc=1
fi
grep -qi 'symlink' "$DIR/t31-put.log" || rc=1
[[ ! -e "$DIR/t31-out/evil.txt" ]] || rc=1
record "put -r refuses to write through a symlinked dir" $rc

# ---------- forward half-close and dead-port reason ----------
# local echo service on 18223
python3 - <<'PYEOF' &
import socketserver
class H(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            d = self.request.recv(4096)
            if not d:
                break
            self.request.sendall(d)
socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(("127.0.0.1", 18223), H).serve_forever()
PYEOF
PIDS+=($!)
rc=0
wait_port 18223 || rc=1
HOME="$HOME_A" "$BIN/exvia" forward "$MID" -L 18222:127.0.0.1:18223 \
    >"$DIR/t7-fwd.log" 2>&1 &
PIDS+=($!)
wait_log "$DIR/t7-fwd.log" "forward" 10 || rc=1
# nc half-closes after sending; the echo must still come back
printf 'fwd-x\n' | nc -w 3 127.0.0.1 18222 >"$DIR/t7-nc.out" 2>/dev/null
grep -q 'fwd-x' "$DIR/t7-nc.out" || rc=1
# Dead port: listen on 18299, target 18298 (nothing listening). The target must not
# equal the listen port, or the agent would dial the CLI's own listener.
HOME="$HOME_A" "$BIN/exvia" forward "$MID" -L 18299:127.0.0.1:18298 \
    >"$DIR/t7-fwd2.log" 2>&1 &
PIDS+=($!)
wait_log "$DIR/t7-fwd2.log" "forward" 10 || rc=1
printf 'x\n' | nc -w 3 127.0.0.1 18299 >/dev/null 2>&1
# 关闭原因从 agent 经中继回到 CLI 日志有传输延迟，轮询等待而不是立刻 grep
wait_log "$DIR/t7-fwd2.log" 'forward connection closed' 10 || rc=1
record "forward half-close, dead-port reason" $rc

# ---------- ls --tag filter ----------
rc=0
"$BIN/exvia-relay" machine tag "$MID" "lab,web" --data-dir "$DATA" >/dev/null 2>&1 || rc=1
tagged=$(cli "$HOME_A" ls --tag lab 2>/dev/null)
untagged=$(cli "$HOME_A" ls --tag nope 2>/dev/null)
[[ $tagged == *"$MID"* ]] || rc=1
[[ $untagged != *"$MID"* ]] || rc=1
record "ls --tag filter" $rc

# ---------- user authorization: bob allowed, eve denied ----------
rc=0
"$BIN/exvia-relay" user add --username bob --password bob-pass-123 --data-dir "$DATA" >/dev/null 2>&1 || rc=1
"$BIN/exvia-relay" user add --username eve --password eve-pass-123 --data-dir "$DATA" >/dev/null 2>&1 || rc=1
"$BIN/exvia-relay" auth grant --username bob --machine-id "$MID" --data-dir "$DATA" >/dev/null 2>&1 || rc=1
# bob is granted access
cli "$HOME_B" login --server "$SERVER" --fingerprint "$FP" \
    --user bob --password bob-pass-123 --ws-prefix "$WS_PREFIX" >"$DIR/t9-bob-login.log" 2>&1 || rc=1
bob_ls=$(cli "$HOME_B" ls 2>&1 | tee "$DIR/t9-bob-ls.log") || rc=1
[[ $bob_ls == *"$MID"* ]] || rc=1
cli "$HOME_B" ping "$MID" >"$DIR/t9-bob-ping.log" 2>&1 || rc=1
# eve has no grant: ls shows nothing, ping is rejected
cli "$HOME_E" login --server "$SERVER" --fingerprint "$FP" \
    --user eve --password eve-pass-123 --ws-prefix "$WS_PREFIX" >"$DIR/t9-eve-login.log" 2>&1 || rc=1
eve_ls=$(cli "$HOME_E" ls 2>&1 | tee "$DIR/t9-eve-ls.log") || rc=1
[[ $eve_ls != *"$MID"* ]] || rc=1
cli "$HOME_E" ping "$MID" >"$DIR/t9-eve-ping.log" 2>&1 || true
grep -q 'permission denied' "$DIR/t9-eve-ping.log" || rc=1
# a bad token login produces a denied/login audit row
cli "$HOME_X" login --server "$SERVER" --fingerprint "$FP" --token wrong-token \
    --ws-prefix "$WS_PREFIX" >/dev/null 2>&1
record "user authorization: bob allowed, eve denied" $rc

# ---------- audit rows ----------
audit=$("$BIN/exvia-relay" audit --limit 200 --data-dir "$DATA")
rc=0
printf '%s\n' "$audit" | grep -Eq 'Exec|Pty|File|Echo' || rc=1
printf '%s\n' "$audit" | grep -q 'denied/login' || rc=1
record "audit has session and denied/login rows" $rc

# ---------- a rejected login says why, instead of stalling until the client gives up ----------
# 中继发完 LoginErr 若立刻断连，队列里的文本帧不会被写出，CLI 只能等到
# CONTROL_TIMEOUT(10s) 报“超时”，把令牌错误误诊成网络问题。
rc=0
t0=$(date +%s)
cli "$HOME_X" login --server "$SERVER" --fingerprint "$FP" --token wrong-token-2 \
    --ws-prefix "$WS_PREFIX" >"$DIR/t10b-badtoken.log" 2>&1 && rc=1
t1=$(date +%s)
elapsed=$((t1 - t0))
grep -qi "invalid credentials" "$DIR/t10b-badtoken.log" || rc=1
(( elapsed < 9 )) || rc=1
record "rejected login reports the reason, no 10s stall" $rc "elapsed=${elapsed}s"

# ---------- rotate-admin ----------
NEW_TOKEN=$("$BIN/exvia-relay" token rotate-admin --data-dir "$DATA" | head -1)
rc=0
cli "$HOME_X" login --server "$SERVER" --fingerprint "$FP" --token "$ADMIN_TOKEN" \
    --ws-prefix "$WS_PREFIX" >/dev/null 2>&1 && rc=1   # the old token must fail
cli "$HOME_A" login --server "$SERVER" --fingerprint "$FP" --token "$NEW_TOKEN" \
    --ws-prefix "$WS_PREFIX" >"$DIR/t11-new.log" 2>&1 || rc=1   # the new token must work (refreshes the admin HOME credentials)
record "rotate-admin invalidates the old token" $rc

# ---------- private files are 0600 ----------
rc=0
cfgdir="$HOME_A/Library/Application Support/exvia"
# dirs::config_dir() is ~/.config on Linux; probe both layouts
[[ -d "$HOME_A/.config/exvia" ]] && cfgdir="$HOME_A/.config/exvia"
# BSD stat -f on macOS, GNU stat -c with coreutils
m_client=$(mode_of "$cfgdir/client.json");   [[ $m_client == 600 ]] || rc=1
m_known=$(mode_of "$cfgdir/known_agents.json"); [[ $m_known == 600 ]] || rc=1
m_cli_id=$(mode_of "$cfgdir/cli-identity.json"); [[ $m_cli_id == 600 ]] || rc=1
m_ident=$(mode_of "$AGENT_DIR/identity.json");  [[ $m_ident == 600 ]] || rc=1
record "private files are 0600" $rc \
    "modes=$m_client/$m_known/$m_cli_id/$m_ident"

# ---------- offline detection ----------
kill "$AGENT_PID" 2>/dev/null
wait "$AGENT_PID" 2>/dev/null
rc=1
for i in 1 2 3 4 5 6 7 8 9 10; do   # poll every half second for 5s
    ls_now=$(cli "$HOME_A" ls 2>/dev/null)
    if [[ $ls_now == *"○"* ]]; then rc=0; break; fi
    sleep 0.5
done
record "agent goes offline within 5s" $rc

# ---------- relay status ----------
status=$("$BIN/exvia-relay" status --data-dir "$DATA")
rc=0
[[ $status == *"machines"* ]] || rc=1
[[ $status == *"sessions"* ]] || rc=1
record "relay status shows machines and sessions" $rc

# ---------- logout and re-login ----------
# bob logged in earlier; logout revokes the session token, logging in again restores it
rc=0
cli "$HOME_B" logout >"$DIR/t16-logout.log" 2>&1 || rc=1
grep -q 'logged out' "$DIR/t16-logout.log" || rc=1
# the revoked token must make ls fail
cli "$HOME_B" ls >"$DIR/t16-ls-after.log" 2>&1 && rc=1
# a fresh login restores access
cli "$HOME_B" login --server "$SERVER" --fingerprint "$FP" \
    --user bob --password bob-pass-123 --ws-prefix "$WS_PREFIX" >"$DIR/t16-relogin.log" 2>&1 || rc=1
bob_ls=$(cli "$HOME_B" ls 2>/dev/null)
[[ $bob_ls == *"$MID"* ]] || rc=1
record "logout revokes the session, re-login restores it" $rc

# ---------- user passwd ----------
rc=0
"$BIN/exvia-relay" user passwd --username bob --password bob-pass-456 --data-dir "$DATA" \
    >"$DIR/t17-passwd.log" 2>&1 || rc=1
grep -q 'password updated' "$DIR/t17-passwd.log" || rc=1
# changing the password revokes bob's existing session token
cli "$HOME_B" ls >/dev/null 2>&1 && rc=1
# old password is rejected
cli "$HOME_X" login --server "$SERVER" --fingerprint "$FP" \
    --user bob --password bob-pass-123 --ws-prefix "$WS_PREFIX" >/dev/null 2>&1 && rc=1
# new password works and the machine grant is kept
cli "$HOME_B" login --server "$SERVER" --fingerprint "$FP" \
    --user bob --password bob-pass-456 --ws-prefix "$WS_PREFIX" >"$DIR/t17-newlogin.log" 2>&1 || rc=1
bob_ls=$(cli "$HOME_B" ls 2>/dev/null)
[[ $bob_ls == *"$MID"* ]] || rc=1
record "user passwd keeps the machine grant" $rc

# ---------- forward -R (ssh -R semantics) ----------
# the offline check stopped the agent; start it again
rc=0
spawn "$AGENT_LOG" "$BIN/exvia-agent" run --identity "$AGENT_DIR/identity.json"
wait_line "cli $HOME_A ls" "●" 20 || rc=1
# echo service on the operator side, one thread per connection
python3 - <<'PYEOF' &
import socketserver
class H(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            d = self.request.recv(4096)
            if not d:
                break
            self.request.sendall(d)
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("127.0.0.1", 18233), H).serve_forever()
PYEOF
PIDS+=($!)
wait_port 18233 || rc=1
# -R listens on the agent side at 18232 and dials 18233 on the operator side
HOME="$HOME_A" "$BIN/exvia" forward "$MID" -R 18232:127.0.0.1:18233 \
    >"$DIR/t18-fwd.log" 2>&1 &
PIDS+=($!)
wait_log "$DIR/t18-fwd.log" "reverse forward" 10 || rc=1
# basic echo through the tunnel
printf 'rev-x\n' | nc -w 3 127.0.0.1 18232 >"$DIR/t18-nc.out" 2>/dev/null
grep -q 'rev-x' "$DIR/t18-nc.out" || rc=1
# three concurrent connections
cprs=()
for i in 1 2 3; do
    ( printf "rev-c$i\n" | nc -w 5 127.0.0.1 18232 >"$DIR/t18-c$i.out" 2>/dev/null ) &
    cprs+=($!)
done
for p in "${cprs[@]}"; do wait "$p" 2>/dev/null; done
grep -q 'rev-c1' "$DIR/t18-c1.out" || rc=1
grep -q 'rev-c2' "$DIR/t18-c2.out" || rc=1
grep -q 'rev-c3' "$DIR/t18-c3.out" || rc=1
# a dead target must surface the dial failure in the CLI log
HOME="$HOME_A" "$BIN/exvia" forward "$MID" -R 18243:127.0.0.1:18298 \
    >"$DIR/t18-fwd2.log" 2>&1 &
PIDS+=($!)
wait_log "$DIR/t18-fwd2.log" "reverse forward" 10 || rc=1
printf 'x\n' | nc -w 3 127.0.0.1 18243 >/dev/null 2>&1
sleep 0.3
grep -q 'connection to 127.0.0.1:18298 failed' "$DIR/t18-fwd2.log" || rc=1
record "forward -R echo, 3 concurrent, dead target" $rc

# ---------- CLI identity and persisted settings ----------
rc=0
KEY_A2=$(cli "$HOME_A" pubkey 2>"$DIR/t19-key.err") || rc=1
[[ $KEY_A2 == "$KEY_A" ]] || rc=1
[[ ${#KEY_A2} -ge 40 ]] || rc=1
grep -q "$KEY_A" "$AGENT_DIR/identity.json" || rc=1
grep -q "\"$WS_PREFIX\"" "$AGENT_DIR/identity.json" || rc=1
record "CLI pubkey stable, allowlist and ws prefix persisted" $rc

# ---------- status --json ----------
rc=0
sjson=$("$BIN/exvia-relay" status --json --data-dir "$DATA" 2>"$DIR/t20.err") || rc=1
printf '%s\n' "$sjson" | python3 -c '
import json, sys
d = json.load(sys.stdin)
need = ("machines_total", "machines_active", "version_dist", "users", "auth_pairs",
        "tokens_unused", "sessions_today", "audit_total", "audit_retention_days",
        "protocol_version")
assert all(k in d for k in need), sorted(set(need) - set(d))
assert isinstance(d["machines_total"], int) and d["machines_total"] >= 1
assert isinstance(d["audit_total"], int) and d["audit_total"] >= 1
assert isinstance(d["version_dist"], dict)
' >"$DIR/t20.out" 2>&1 || rc=1
record "status --json parses" $rc

# ---------- exec --timeout ----------
rc=0
t0=$(date +%s)
code=0
cli "$HOME_A" exec "$MID" --timeout 1 -- /bin/sh -c 'sleep 30; echo never' \
    >"$DIR/t21.out" 2>"$DIR/t21.err" || code=$?
t1=$(date +%s)
(( code == 124 )) || rc=1
(( t1 - t0 < 12 )) || rc=1
grep -q 'timed out' "$DIR/t21.err" || grep -q 'timed out' "$DIR/t21.out" || rc=1
grep -q 'never' "$DIR/t21.out" && rc=1
cli "$HOME_A" exec "$MID" --timeout 0 -- /bin/echo x >/dev/null 2>&1 && rc=1
record "exec --timeout kills a long task, --timeout 0 rejected" $rc \
    "code=$code elapsed=$((t1-t0))s"

# ---------- a CLI outside the allowlist cannot open a session ----------
rc=0
KEY_X=$(cli "$HOME_X" pubkey 2>>"$DIR/t22-key.err") || rc=1
[[ $KEY_X != "$KEY_A" ]] || rc=1
grep -q "$KEY_X" "$AGENT_DIR/identity.json" && rc=1
# the relay only checks the token, so login succeeds; the agent rejects the ticket
cli "$HOME_X" login --server "$SERVER" --fingerprint "$FP" --token "$NEW_TOKEN" \
    --ws-prefix "$WS_PREFIX" >"$DIR/t22-login.log" 2>&1 || rc=1
cli "$HOME_X" exec "$MID" -- /bin/echo should-not-run \
    >"$DIR/t22-exec.out" 2>"$DIR/t22-exec.err" && rc=1
grep -qi 'ticket' "$DIR/t22-exec.err" || grep -qi 'ticket' "$DIR/t22-exec.out" || rc=1
grep -q 'should-not-run' "$DIR/t22-exec.out" && rc=1
record "CLI outside allowlist cannot open a session" $rc

# ---------- configurable cert CN and default WS path ----------
rc=0
if command -v openssl >/dev/null 2>&1; then
    subj=$(openssl x509 -in "$DATA/relay-cert.pem" -noout -subject 2>"$DIR/t23-openssl.err") || rc=1
    [[ $subj == *"$CERT_NAME"* ]] || rc=1
    [[ $subj != *"exvia-relay"* ]] || rc=1
else
    echo "openssl unavailable, skipping cert CN check" >>"$DIR/t23-openssl.err"
fi
python3 - "$PORT" "$WS_PREFIX" >"$DIR/t23-probe.out" 2>&1 <<'PY' || rc=1
import base64, os, socket, ssl, sys
port = int(sys.argv[1]); prefix = sys.argv[2].rstrip('/')
ctx = ssl._create_unverified_context()
def probe(path):
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    s = ctx.wrap_socket(s, server_hostname="localhost")
    key = base64.b64encode(os.urandom(16)).decode()
    req = (f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
           "Upgrade: websocket\r\nConnection: Upgrade\r\n"
           f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
    s.sendall(req.encode())
    data = b""
    try:
        while len(data) < 8192:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
    except socket.timeout:
        pass
    s.close()
    return data.split(b"\r\n", 1)[0].decode(errors="replace"), data
custom, _ = probe(prefix + "/cli")
default, ddata = probe("/_exvia/cli")
assert custom.startswith("HTTP/1.1 101"), custom
assert not default.startswith("HTTP/1.1 101"), default
assert b"Welcome" in ddata or b"200" in default, (default, ddata[:120])
print("custom:", custom, "| default:", default)
PY
grep -q 'using default WS path prefix' "$RELAY_LOG" && rc=1
record "cert CN configurable, default WS path closed" $rc

# ---------- local machine aliases ----------
rc=0
cli "$HOME_A" alias add lab-1 "$MID" >"$DIR/t24-add.out" 2>&1 || rc=1
cli "$HOME_A" alias list >"$DIR/t24-list.out" 2>&1 || rc=1
grep -q "$MID" "$DIR/t24-list.out" || rc=1
alias_exec=$(cli "$HOME_A" exec lab-1 -- /bin/sh -c 'echo alias-works' 2>"$DIR/t24-exec.err") || rc=1
[[ $alias_exec == *"alias-works"* ]] || rc=1
grep -q "lab-1 -> $MID" "$DIR/t24-exec.err" && rc=1   # resolution is silent, no echo line
ls_alias=$(cli "$HOME_A" ls 2>"$DIR/t24-ls.err") || rc=1
[[ $ls_alias == *"ALIAS"* && $ls_alias == *"lab-1"* ]] || rc=1
m_alias=$(mode_of "$cfgdir/aliases.json"); [[ $m_alias == 600 ]] || rc=1
pfx=${MID:0:6}
pfx_out=$(cli "$HOME_A" exec "$pfx" -- /bin/sh -c 'echo prefix-works' 2>"$DIR/t24-pfx.err") || rc=1
[[ $pfx_out == *"prefix-works"* ]] || rc=1
record "aliases add/list/ls/exec and 0600" $rc "mode=$m_alias"

# ---------- alias resolution fails closed ----------
rc=0
cli "$HOME_A" exec prod-db -- /bin/echo should-not-run >"$DIR/t25-unknown.out" 2>&1 && rc=1
grep -q "unknown machine" "$DIR/t25-unknown.out" || rc=1
cli "$HOME_A" alias add amb1 ab11111111111111111111111111111111 >/dev/null 2>&1 || rc=1
cli "$HOME_A" alias add amb2 ab22222222222222222222222222222222 >/dev/null 2>&1 || rc=1
cli "$HOME_A" exec ab -- /bin/echo should-not-run >"$DIR/t25-amb.out" 2>&1 && rc=1
grep -q "matches 2 machines" "$DIR/t25-amb.out" || rc=1
cli "$HOME_A" alias rm amb1 >/dev/null 2>&1 || rc=1
cli "$HOME_A" alias rm amb2 >/dev/null 2>&1 || rc=1
cli "$HOME_A" alias rm lab-1 >/dev/null 2>&1 || rc=1
[[ $(cli "$HOME_A" alias list 2>&1) == *"no aliases configured"* ]] || rc=1
cli "$HOME_A" alias add 'bad:name' "$MID" >"$DIR/t25-bad.out" 2>&1 && rc=1
grep -q "only" "$DIR/t25-bad.out" || rc=1
record "alias resolution fails closed" $rc

# ---------- version reporting ----------
rc=0
v_cli=$("$BIN/exvia" --version 2>&1) || rc=1
v_relay=$("$BIN/exvia-relay" --version 2>&1) || rc=1
v_agent=$("$BIN/exvia-agent" --version 2>&1) || rc=1
# 期望值取自 workspace 版本，发版改号时这里不用动
want=$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)
[[ -n $want ]] || rc=1
[[ $v_cli == "exvia $want" ]] || rc=1
[[ $v_relay == "exvia-relay $want" ]] || rc=1
[[ $v_agent == "exvia-agent $want" ]] || rc=1
record "--version on all three binaries" $rc "want=$want"

# ---------- active session listing and forced termination ----------
rc=0
cli "$HOME_A" exec "$MID" -- /bin/sh -c 'sleep 30; echo never' >"$DIR/t26-exec.out" 2>&1 &
EXEC_PID=$!
PIDS+=($EXEC_PID)
# wait for the session to register on the relay
sess_out=""
for _ in $(seq 1 40); do
    sess_out=$(cli "$HOME_A" sessions 2>/dev/null)
    [[ $sess_out == *"Exec"* ]] && break
    sleep 0.25
done
[[ $sess_out == *"SID"* && $sess_out == *"Exec"* ]] || rc=1
SID=$(printf '%s\n' "$sess_out" | awk 'NR>=2 && NF>0 {print $1}' | head -1)
[[ -n ${SID:-} && $SID != "no" ]] || rc=1
# close it: the remote command must be torn down instead of running to completion
cli "$HOME_A" close "$SID" >"$DIR/t26-close.out" 2>&1 || rc=1
grep -q "session $SID closed" "$DIR/t26-close.out" || rc=1
wait "$EXEC_PID" 2>/dev/null
# the bridge is cancelled asynchronously; give the relay a moment to unregister it.
# 断言收紧到本 sid：-R 转发（t18）现在也会登记为活跃会话，列表里允许还有别的行，
# 但被 close 的这条必须从列表消失。
after=""
for _ in $(seq 1 20); do
    after=$(cli "$HOME_A" sessions 2>&1)
    [[ $after != *"$SID"* ]] && break
    sleep 0.25
done
[[ $after != *"$SID"* ]] || rc=1
record "sessions lists active work, close terminates it" $rc "sid=$SID"

# ---------- a user cannot list or close someone else's session ----------
rc=0
cli "$HOME_A" exec "$MID" -- /bin/sh -c 'sleep 20' >/dev/null 2>&1 &
EXEC_PID=$!
PIDS+=($EXEC_PID)
# wait until the admin can see it, then confirm bob cannot
admin_sess=""
for _ in $(seq 1 40); do
    admin_sess=$(cli "$HOME_A" sessions 2>&1)
    [[ $admin_sess == *"Exec"* ]] && break
    sleep 0.25
done
[[ $admin_sess == *"Exec"* ]] || rc=1
bob_sess=$(cli "$HOME_B" sessions 2>&1)
[[ $bob_sess == *"no active sessions"* ]] || rc=1
SID2=$(printf '%s\n' "$admin_sess" | awk 'NR>=2 && NF>0 {print $1}' | head -1)
cli "$HOME_A" close "$SID2" >/dev/null 2>&1 || rc=1
wait "$EXEC_PID" 2>/dev/null
record "session visibility is scoped per user" $rc

# ---------- metrics endpoint ----------
rc=0
metrics=$(curl -s --max-time 5 "http://127.0.0.1:$METRICS_PORT/metrics") || rc=1
[[ $metrics == *"exvia_machines_online 1"* ]] || rc=1
[[ $metrics == *"exvia_sessions_active"* ]] || rc=1
[[ $metrics == *"exvia_build_info"* ]] || rc=1
health=$(curl -s --max-time 5 "http://127.0.0.1:$METRICS_PORT/healthz") || rc=1
[[ $health == "ok" ]] || rc=1
# a non-loopback metrics listener must be refused (loopback-only rule; remote
# scraping goes over an SSH tunnel, --metrics-token is optional hardening on top)
if timeout 5 "$BIN/exvia-relay" serve --listen "127.0.0.1:$((PORT+2))" \
    --data-dir "$DIR/relay-guard" --metrics-listen "0.0.0.0:$((METRICS_PORT+1))" \
    >"$DIR/t27-guard.log" 2>&1; then
    rc=1
fi
grep -qi "must bind a loopback address" "$DIR/t27-guard.log" || rc=1
record "metrics endpoint serves gauges, refuses open bind" $rc

# ---------- trust session: add a key, use it, then revoke ----------
rc=0
KEY_T=$(cli "$HOME_T" pubkey) || rc=1
cli "$HOME_T" login --server "$SERVER" --fingerprint "$FP" --token "$NEW_TOKEN" \
    --ws-prefix "$WS_PREFIX" >"$DIR/t28-login.log" 2>&1 || rc=1
# before the grant, this CLI is outside the allowlist and must be rejected
cli "$HOME_T" exec "$MID" -- /bin/echo should-not-run >"$DIR/t28-before.out" 2>&1 && rc=1
# must fail for the allowlist reason, not because the login/config went missing
grep -qi 'ticket' "$DIR/t28-before.out" || rc=1
cli "$HOME_A" trust add "$MID" "$KEY_T" >"$DIR/t28-add.out" 2>&1 || rc=1
grep -q "added; 4 keys now trusted" "$DIR/t28-add.out" || rc=1
# now it works, and without restarting the agent
cli "$HOME_T" exec "$MID" -- /bin/echo trust-ok >"$DIR/t28-exec.out" 2>&1 || rc=1
grep -q "trust-ok" "$DIR/t28-exec.out" || rc=1
# the list reflects the change and the file is private
cli "$HOME_A" trust list "$MID" >"$DIR/t28-list.out" 2>&1 || rc=1
grep -q "$KEY_T" "$DIR/t28-list.out" || rc=1
mode=$(stat -c '%a' "$AGENT_DIR/trusted-cli.json" 2>/dev/null || stat -f '%Lp' "$AGENT_DIR/trusted-cli.json" 2>/dev/null)
[[ $mode == "600" ]] || rc=1
record "trust add lets a new CLI in without restarting the agent" $rc "mode=$mode"

rc=0
cli "$HOME_A" trust rm "$MID" "$KEY_T" >"$DIR/t29-rm.out" 2>&1 || rc=1
cli "$HOME_T" exec "$MID" -- /bin/echo should-not-run >"$DIR/t29-after.out" 2>&1 && rc=1
grep -qi 'ticket' "$DIR/t29-after.out" || rc=1
# removing the last remaining key must be refused (nobody could log in afterwards)
KEY_B=$(cli "$HOME_B" pubkey)
KEY_E=$(cli "$HOME_E" pubkey)
cli "$HOME_A" trust rm "$MID" "$KEY_B" >/dev/null 2>&1 || rc=1
cli "$HOME_A" trust rm "$MID" "$KEY_E" >/dev/null 2>&1 || rc=1
cli "$HOME_A" trust rm "$MID" "$KEY_A" >"$DIR/t29-last.out" 2>&1 && rc=1
grep -q "last trusted key" "$DIR/t29-last.out" || rc=1
# the surviving key still works
cli "$HOME_A" exec "$MID" -- /bin/echo still-alive >"$DIR/t29-ok.out" 2>&1 || rc=1
grep -q "still-alive" "$DIR/t29-ok.out" || rc=1
record "trust rm revokes access, last key is protected" $rc

# ---------- audit export ----------
rc=0
"$BIN/exvia-relay" export --data-dir "$DATA" --format csv --out "$DIR/audit.csv" >/dev/null 2>&1 || rc=1
head -1 "$DIR/audit.csv" | grep -q "^ts,iso,user,machine,kind,bytes_up,bytes_down,duration_ms$" || rc=1
rows=$(( $(wc -l <"$DIR/audit.csv") - 1 ))
(( rows > 0 )) || rc=1
"$BIN/exvia-relay" export --data-dir "$DATA" --format jsonl >"$DIR/audit.jsonl" 2>/dev/null || rc=1
head -1 "$DIR/audit.jsonl" | grep -q '"bytes_up"' || rc=1
# a closed session must be recorded, and time filters must accept YYYY-MM-DD
"$BIN/exvia-relay" export --data-dir "$DATA" --format csv --since 2020-01-01 --until 2099-01-01 \
    --out "$DIR/audit-window.csv" >/dev/null 2>&1 || rc=1
rows_win=$(( $(wc -l <"$DIR/audit-window.csv") - 1 ))
(( rows_win == rows )) || rc=1
record "audit export writes csv and jsonl" $rc "rows=$rows"

# ---------- -R CloseSession regression: close must tear down the tunnel ----------
# 起一条新 -R 隧道，验证通路后用 `exvia close`（sid 从 sessions 取）关闭。
# 修复前 close 杀不掉 agent 侧监听：关闭后新连接仍被接受。断言三件事：关闭前列表
# 出现本会话、关闭后列表摘除本 sid、关闭后监听端口新连接被拒/无回声。
rc=0
sess_before=$(cli "$HOME_A" sessions 2>/dev/null | awk 'NR>1 && $1 ~ /^[0-9]+$/ {print $1}' | sort)
HOME="$HOME_A" "$BIN/exvia" forward "$MID" -R 18234:127.0.0.1:18233 \
    >"$DIR/t37-fwd.log" 2>&1 &
FWD37_PID=$!
PIDS+=($FWD37_PID)
wait_log "$DIR/t37-fwd.log" "reverse forward" 10 || rc=1
# 隧道先要能通
printf 'rev-pre-close\n' | nc -w 3 127.0.0.1 18234 >"$DIR/t37-nc1.out" 2>/dev/null
grep -q 'rev-pre-close' "$DIR/t37-nc1.out" || rc=1
# sid 从 sessions 取：与启动前做差，多出来的那行就是本会话
SID37=""
for _ in $(seq 1 20); do
    sess_now=$(cli "$HOME_A" sessions 2>/dev/null | awk 'NR>1 && $1 ~ /^[0-9]+$/ {print $1}' | sort)
    SID37=$(comm -13 <(printf '%s\n' "$sess_before") <(printf '%s\n' "$sess_now") | head -1)
    [[ -n ${SID37:-} ]] && break
    sleep 0.25
done
[[ -n ${SID37:-} ]] || rc=1
cli "$HOME_A" close "$SID37" >"$DIR/t37-close.out" 2>&1 || rc=1
grep -q "session $SID37 closed" "$DIR/t37-close.out" || rc=1
# 列表摘除（桥接取消是异步的，轮询等）
after37=""
for _ in $(seq 1 20); do
    after37=$(cli "$HOME_A" sessions 2>&1)
    [[ $after37 != *"$SID37"* ]] && break
    sleep 0.25
done
[[ $after37 != *"$SID37"* ]] || rc=1
# 端口必须拒新连接/无回声：修复前监听还在，echo 服务会把内容原样弹回来
sleep 0.5
printf 'rev-post-close\n' | nc -w 2 127.0.0.1 18234 >"$DIR/t37-nc2.out" 2>/dev/null
grep -q 'rev-post-close' "$DIR/t37-nc2.out" && rc=1
# 控制流随 close 断开，forward 进程应自行退出
alive37=0
for _ in $(seq 1 20); do
    kill -0 "$FWD37_PID" 2>/dev/null || { alive37=1; break; }
    sleep 0.25
done
[[ $alive37 == 1 ]] || rc=1
record "close on -R tears down the tunnel and unlists the session" $rc "sid=$SID37"

# ---------- PTY stdin EOF propagation: session closes when the pipe closes ----------
# stdin 喂一行、不给退出指令：EOF 必须经 Shutdown → 放下 PTY writer（换行 + VEOF）
# 传进 PTY，远端进程读到 EOF 自然退出、会话收尾（修复前 CLI 挂住，只能靠外部
# 超时强杀）。EOF 之后是否退出是子进程自身行为——登录 shell 受机器配置影响
# （个别配置忽略 EOF），所以用 exec -t 跑 cat 这个对 EOF 确定性退出的进程，
# 钉住的是 exvia 的传播链路本身。走一次别名解析，测完删掉。
rc=0
cli "$HOME_A" alias add eofmach "$MID" >"$DIR/t38-alias.out" 2>&1 || rc=1
t0=$(date +%s)
code=0
printf 'marker-eof\n' | timeout 20 env HOME="$HOME_A" "$BIN/exvia" exec -t eofmach cat \
    >"$DIR/t38.log" 2>&1 || code=$?
t1=$(date +%s)
(( code == 0 )) || rc=1
(( t1 - t0 < 19 )) || rc=1
grep -q 'marker-eof' "$DIR/t38.log" || rc=1
cli "$HOME_A" alias rm eofmach >/dev/null 2>&1 || rc=1
record "pty session closes when stdin hits EOF (PTY EOF propagation)" $rc "elapsed=$((t1-t0))s code=$code"

# ---------- put 多源 + 引号通配符；单文件进度行进 stderr ----------
# 多源（含引号通配符，shell 不展开、由 CLI 侧展开）合并成一棵清单树；
# 大于 1MiB 的单文件走非递归快速路径，\r 进度行必须出现在 stderr。
rc=0
mkdir -p "$DIR/t39-src"
printf 'keep' > "$DIR/t39-src/keep.txt"
printf 'alpha' > "$DIR/t39-src/a.log"
printf 'beta' > "$DIR/t39-src/b.log"
printf 'skipme' > "$DIR/t39-src/c.txt"
printf 'hidden' > "$DIR/t39-src/.dot.log"
head -c 1572864 /dev/urandom > "$DIR/t39-big.bin"   # 1.5 MiB，越过进度显示门槛
cli "$HOME_A" put "$MID" "$DIR/t39-src/keep.txt" "$DIR/t39-src/*.log" "$DIR/t39-dest" \
    >"$DIR/t39-put.out" 2>"$DIR/t39-put.err" || rc=1
for f in keep.txt a.log b.log; do
    cmp -s "$DIR/t39-src/$f" "$DIR/t39-dest/$f" || rc=1
done
[[ -e "$DIR/t39-dest/c.txt" ]] && rc=1          # 未被通配符选中的文件不得出现
[[ -e "$DIR/t39-dest/.dot.log" ]] && rc=1       # `*` 不匹配隐藏文件（与 shell 一致）
# 1.5MiB 单文件：进度行在 stderr，stdout 只有 uploaded: 汇总
cli "$HOME_A" put "$MID" "$DIR/t39-big.bin" "$DIR/t39-dest/big.bin" \
    >"$DIR/t39-big.out" 2>"$DIR/t39-big.err" || rc=1
cmp -s "$DIR/t39-big.bin" "$DIR/t39-dest/big.bin" || rc=1
grep -q 'MiB (' "$DIR/t39-big.err" || rc=1
record "put multi-source with quoted glob, single-file progress on stderr" $rc

# ---------- 批量 exec：第二台 agent 入场，双机并发与每机 rc 汇总 ----------
rc=0
AGENT_DIR2="$DIR/agent2"
mkdir -p "$AGENT_DIR2"
TOK2=$("$BIN/exvia-relay" token create --data-dir "$DATA" | head -1)
"$BIN/exvia-agent" enroll --server "$SERVER" --token "$TOK2" --fingerprint "$FP" \
    --identity "$AGENT_DIR2/identity.json" --ws-prefix "$WS_PREFIX" \
    "${TRUSTED_ARGS[@]}" >"$DIR/t40-enroll.log" 2>&1 || rc=1
AGENT2_LOG="$DIR/agent2.log"
spawn "$AGENT2_LOG" "$BIN/exvia-agent" run --identity "$AGENT_DIR2/identity.json"
AGENT2_PID=${PIDS[${#PIDS[@]}-1]}
wait_line "cli $HOME_A ls" "●" 20 || rc=1
MID2=""
for _ in $(seq 1 40); do
    MID2=$(cli "$HOME_A" ls 2>/dev/null | awk -v m="$MID" 'NR>1 && $1 ~ /^[0-9a-f]{32}$/ && $1 != m {print $1}' | head -1)
    [[ -n ${MID2:-} ]] && break
    sleep 0.25
done
[[ -n ${MID2:-} ]] || rc=1
cli "$HOME_A" alias add m-one "$MID" >/dev/null 2>&1 || rc=1
cli "$HOME_A" alias add m-two "$MID2" >/dev/null 2>&1 || rc=1
# 双机并发：输出行带 [别名] 前缀，末尾逐机汇总 rc，全 0 整体退出码 0
code=0
cli "$HOME_A" exec m-one,m-two -- /bin/sh -c 'echo batch-marker' \
    >"$DIR/t40.out" 2>"$DIR/t40.err" || code=$?
(( code == 0 )) || rc=1
grep -qF '[m-one] batch-marker' "$DIR/t40.out" || rc=1
grep -qF '[m-two] batch-marker' "$DIR/t40.out" || rc=1
grep -qF 'm-one: rc=0' "$DIR/t40.out" || rc=1
grep -qF 'm-two: rc=0' "$DIR/t40.out" || rc=1
# 非零退出码：任一非零则整体 1，逐机 rc 仍如实汇总。
# 前一条 exec 的连接刚断，中继收尾有毫秒级延迟，重试几次。
ok=0
for _ in $(seq 1 5); do
    code=0
    cli "$HOME_A" exec m-one,m-two -- /bin/sh -c 'exit 3' \
        >"$DIR/t40-rc.out" 2>"$DIR/t40-rc.err" || code=$?
    if (( code == 1 )) \
        && grep -qF 'm-one: rc=3' "$DIR/t40-rc.out" \
        && grep -qF 'm-two: rc=3' "$DIR/t40-rc.out"; then
        ok=1
        break
    fi
    sleep 0.5
done
(( ok == 1 )) || rc=1
# 一台不可达不拖垮另一台：该目标记 rc=255 风格的错误行
kill "$AGENT2_PID" 2>/dev/null
wait "$AGENT2_PID" 2>/dev/null
for _ in $(seq 1 16); do
    cli "$HOME_A" ls 2>/dev/null | grep "$MID2" | grep -q '○' && break
    sleep 0.5
done
code=0
cli "$HOME_A" exec m-one,m-two -- /bin/echo still-ok \
    >"$DIR/t40-dead.out" 2>"$DIR/t40-dead.err" || code=$?
(( code == 1 )) || rc=1
grep -qF '[m-one] still-ok' "$DIR/t40-dead.out" || rc=1
grep -qF 'm-one: rc=0' "$DIR/t40-dead.out" || rc=1
grep -qF 'm-two: rc=255' "$DIR/t40-dead.out" || rc=1
record "batch exec over two machines, per-machine rc summary" $rc "mid2=$MID2"

# ---------- forward 双 -L 同时转发；绑定冲突报明失败的那条 ----------
rc=0
HOME="$HOME_A" "$BIN/exvia" forward "$MID" -L 18225:127.0.0.1:18223 -L 18226:127.0.0.1:18223 \
    >"$DIR/t41-fwd.log" 2>&1 &
FWD41_PID=$!
PIDS+=($FWD41_PID)
wait_log "$DIR/t41-fwd.log" "18225" 10 || rc=1
wait_log "$DIR/t41-fwd.log" "18226" 10 || rc=1
printf 'dual-1\n' | nc -w 3 127.0.0.1 18225 >"$DIR/t41-nc1.out" 2>/dev/null
printf 'dual-2\n' | nc -w 3 127.0.0.1 18226 >"$DIR/t41-nc2.out" 2>/dev/null
grep -q 'dual-1' "$DIR/t41-nc1.out" || rc=1
grep -q 'dual-2' "$DIR/t41-nc2.out" || rc=1
# 第二条 -L 与正在运行的隧道冲突：整组拒绝、报明是哪条，且先绑成的 18227 不留悬挂
HOME="$HOME_A" "$BIN/exvia" forward "$MID" -L 18227:127.0.0.1:18223 -L 18225:127.0.0.1:18223 \
    >"$DIR/t41-conflict.log" 2>&1 && rc=1
grep -q '18225' "$DIR/t41-conflict.log" || rc=1
printf 'no-listen\n' | nc -w 1 127.0.0.1 18227 >/dev/null 2>&1 && rc=1
record "forward dual -L, bind conflict names the failing spec" $rc

# ---------- known list/rm：TOFU 记录管理与重置 ----------
rc=0
cfgdir="$HOME_A/Library/Application Support/exvia"
[[ -d "$HOME_A/.config/exvia" ]] && cfgdir="$HOME_A/.config/exvia"
known_list=$(cli "$HOME_A" known list 2>"$DIR/t42-list.err") || rc=1
[[ $known_list == *"$MID"* ]] || rc=1            # 之前的会话已按 TOFU 记录本机
# 记录被篡改（模拟 agent 换钥）：下一次会话必须被拒
python3 - "$cfgdir/known_agents.json" "$MID" >"$DIR/t42-corrupt.out" 2>&1 <<'PY' || rc=1
import json, sys
path, mid = sys.argv[1], sys.argv[2]
with open(path) as f:
    d = json.load(f)
d[mid] = {"pubkey_b64": "bogus-not-a-real-key", "first_seen": 0}
with open(path, "w") as f:
    json.dump(d, f)
print("corrupted", mid)
PY
cli "$HOME_A" exec "$MID" -- /bin/echo should-not-run >"$DIR/t42-reject.out" 2>&1 && rc=1
grep -qi 'differs from the recorded' "$DIR/t42-reject.out" || rc=1
# rm 清掉记录（别名或 id 皆可），list 不再出现；重复 rm 报不存在
cli "$HOME_A" known rm "$MID" >"$DIR/t42-rm.out" 2>&1 || rc=1
grep -q 'removed' "$DIR/t42-rm.out" || rc=1
known_list2=$(cli "$HOME_A" known list 2>/dev/null) || rc=1
[[ $known_list2 != *"$MID"* ]] || rc=1
cli "$HOME_A" known rm "$MID" >"$DIR/t42-rm2.out" 2>&1 && rc=1
grep -qi 'no known agent' "$DIR/t42-rm2.out" || rc=1
# TOFU 重置：再次会话重新记录新钥并放行，文件仍 0600
cli "$HOME_A" exec "$MID" -- /bin/echo tofu-again >"$DIR/t42-tofu.out" 2>&1 || rc=1
grep -q 'tofu-again' "$DIR/t42-tofu.out" || rc=1
m_known=$(mode_of "$cfgdir/known_agents.json"); [[ $m_known == 600 ]] || rc=1
record "known list/rm resets the TOFU record" $rc "mode=$m_known"

# ---------- completion smoke ----------
rc=0
for sh in bash zsh fish; do
    cli "$HOME_A" completion "$sh" >"$DIR/t43-$sh.out" 2>&1 || rc=1
    [[ -s "$DIR/t43-$sh.out" ]] || rc=1
    grep -q 'exec' "$DIR/t43-$sh.out" || rc=1
    grep -q 'forward' "$DIR/t43-$sh.out" || rc=1
done
cli "$HOME_A" completion --help 2>&1 | grep -qi 'source' || rc=1
record "completion scripts for bash/zsh/fish" $rc

# ---------- exec -t：强制 PTY（ssh -t 语义） ----------
# 命令在远端 PTY 里跑（CRLF/TERM/resize 与 shell 一致），跑的是指定命令而非 shell，
# 退出码透传；--timeout 语义不变：agent 到点杀掉命令并回 124。
rc=0
code=0
cli "$HOME_A" exec -t "$MID" -- echo pty-ok >"$DIR/t44.out" 2>"$DIR/t44.err" || code=$?
(( code == 0 )) || rc=1
grep -q 'pty-ok' "$DIR/t44.out" || rc=1
# 多目标与 -t 组合：明确拒绝（PTY 语义只对单机有意义）
cli "$HOME_A" exec -t m-one,m-two -- echo nope >"$DIR/t44-multi.out" 2>&1 && rc=1
grep -qi 'single machine' "$DIR/t44-multi.out" || rc=1
# 超时语义不变
t0=$(date +%s)
code=0
cli "$HOME_A" exec -t "$MID" --timeout 1 -- sleep 30 >"$DIR/t44-to.out" 2>"$DIR/t44-to.err" || code=$?
t1=$(date +%s)
(( code == 124 )) || rc=1
(( t1 - t0 < 12 )) || rc=1
grep -q 'timed out' "$DIR/t44-to.out" || grep -q 'timed out' "$DIR/t44-to.err" || rc=1
record "exec -t runs the command in a remote PTY, --timeout unchanged" $rc "code=$code elapsed=$((t1-t0))s"

# ---------- get 远端通配符：agent 匹配 + 树协议下载 ----------
# 引号防 shell 展开；远端路径含 * / ? 时由 agent 在父目录内按尾分量匹配
# （与 put 侧同一套语义：不匹配隐藏文件、只支持尾分量），结果走 get -r 的树路径。
rc=0
mkdir -p "$DIR/t45-remote"
printf 'one' > "$DIR/t45-remote/a.log"
printf 'two' > "$DIR/t45-remote/b.log"
printf 'three' > "$DIR/t45-remote/c.log"
printf 'skip' > "$DIR/t45-remote/d.txt"
printf 'hidden' > "$DIR/t45-remote/.e.log"
rm -rf "$DIR/t45-local"
cli "$HOME_A" get "$MID" "$DIR/t45-remote/*.log" "$DIR/t45-local" >"$DIR/t45.out" 2>"$DIR/t45.err" || rc=1
n=$(ls "$DIR/t45-local" 2>/dev/null | wc -l | tr -d ' ')
[[ $n == 3 ]] || rc=1
for f in a b c; do
    cmp -s "$DIR/t45-remote/$f.log" "$DIR/t45-local/$f.log" || rc=1
done
[[ -e "$DIR/t45-local/d.txt" ]] && rc=1        # 未选中的文件不得出现
[[ -e "$DIR/t45-local/.e.log" ]] && rc=1       # `*` 不匹配隐藏文件（与 shell 一致）
# 无匹配 → 明确报错、非零退出
cli "$HOME_A" get "$MID" "$DIR/t45-remote/*.zip" "$DIR/t45-none" >"$DIR/t45-none.out" 2>&1 && rc=1
grep -q 'no files match' "$DIR/t45-none.out" || rc=1
# 字面路径（无通配符）行为不变：仍走单文件快速路径
cli "$HOME_A" get "$MID" "$DIR/t45-remote/d.txt" "$DIR/t45-lit.txt" >"$DIR/t45-lit.out" 2>&1 || rc=1
cmp -s "$DIR/t45-remote/d.txt" "$DIR/t45-lit.txt" || rc=1
record "get remote tail-glob downloads only matching files" $rc "files=$n"

# ---------- put 多机：同一组源并发分发到每台机器 ----------
# 复用 t40 造的第二台 agent（t40 末尾把它下线了，这里先拉回来）。
# 用多源（put_tree）而不是单文件快速路径：agent 侧临时文件名带 pid，
# 两台 agent 同盘并发时不会共用同一个分片文件互相追加。
rc=0
spawn "$AGENT2_LOG" "$BIN/exvia-agent" run --identity "$AGENT_DIR2/identity.json"
AGENT2_PID=${PIDS[${#PIDS[@]}-1]}
for _ in $(seq 1 40); do
    nonline=$(cli "$HOME_A" ls 2>/dev/null | grep -c '●')
    (( nonline >= 2 )) && break
    sleep 0.25
done
mkdir -p "$DIR/t46-src"
printf 'shared-a' > "$DIR/t46-src/a.txt"
printf 'shared-b' > "$DIR/t46-src/b.log"
code=0
cli "$HOME_A" put m-one,m-two "$DIR/t46-src/a.txt" "$DIR/t46-src/b.log" "$DIR/t46-dest" \
    >"$DIR/t46.out" 2>"$DIR/t46.err" || code=$?
(( code == 0 )) || rc=1
grep -qF '[m-one] uploaded:' "$DIR/t46.out" || rc=1
grep -qF '[m-two] uploaded:' "$DIR/t46.out" || rc=1
grep -qF 'm-one: ok' "$DIR/t46.out" || rc=1
grep -qF 'm-two: ok' "$DIR/t46.out" || rc=1
cmp -s "$DIR/t46-src/a.txt" "$DIR/t46-dest/a.txt" || rc=1
cmp -s "$DIR/t46-src/b.log" "$DIR/t46-dest/b.log" || rc=1
# 任一失败整体退出码 1：把第二台下线再发一次，m-one 照常 ok、m-two 如实 failed
kill "$AGENT2_PID" 2>/dev/null
wait "$AGENT2_PID" 2>/dev/null
for _ in $(seq 1 16); do
    cli "$HOME_A" ls 2>/dev/null | grep "$MID2" | grep -q '○' && break
    sleep 0.5
done
code=0
cli "$HOME_A" put m-one,m-two "$DIR/t46-src/a.txt" "$DIR/t46-src/b.log" "$DIR/t46-dest" \
    >"$DIR/t46-fail.out" 2>"$DIR/t46-fail.err" || code=$?
(( code == 1 )) || rc=1
grep -qF 'm-one: ok' "$DIR/t46-fail.out" || rc=1
grep -qF 'm-two: failed:' "$DIR/t46-fail.out" || rc=1
record "put to two machines concurrently, per-machine summary" $rc "mid2=$MID2"

# ---------- 批量目标去重：m1,m1 直接报错，未发起任何会话 ----------
# 同机两会话会让 CLI 侧按对端公钥暂存的流配对产生歧义（stray_streams 按公钥
# 键控），CLI 必须在建会话前拒绝；exec 与 put 都要拦截，报错即非零退出。
rc=0
code=0
cli "$HOME_A" exec m-one,m-one -- /bin/echo nope \
    >"$DIR/t47.out" 2>"$DIR/t47.err" || code=$?
(( code == 1 )) || rc=1
grep -qF 'duplicate target: m-one' "$DIR/t47.err" || rc=1
grep -qF 'nope' "$DIR/t47.out" && rc=1
code=0
cli "$HOME_A" put m-one,m-one "$DIR/t46-src/a.txt" "$DIR/t47-dest" \
    >"$DIR/t47-put.out" 2>"$DIR/t47-put.err" || code=$?
(( code == 1 )) || rc=1
grep -qF 'duplicate target: m-one' "$DIR/t47-put.err" || rc=1
grep -qF 'uploaded' "$DIR/t47-put.out" && rc=1
record "duplicate batch targets rejected before any session" $rc "m-one,m-one"

# ---------- TOFU 预置锚：enroll 输出即预置命令，首连核对预置值 ----------
# 从 t40 的 enroll 输出抓出 anchor 行执行：known add 后首连成功，且 known_agents.json
# 不再走"首连即记录"路径——first_seen 保持预置时刻的值，会话不改写记录。
rc=0
spawn "$AGENT2_LOG" "$BIN/exvia-agent" run --identity "$AGENT_DIR2/identity.json"
AGENT2_PID=${PIDS[${#PIDS[@]}-1]}
for _ in $(seq 1 40); do
    cli "$HOME_A" ls 2>/dev/null | grep "$MID2" | grep -q '●' && break
    sleep 0.5
done
ANCHOR_LINE=$(grep 'anchor on the CLI side:' "$DIR/t40-enroll.log" | head -1)
ANCHOR_ARGS=${ANCHOR_LINE#anchor on the CLI side: exvia known add }
MID2_ANCH=${ANCHOR_ARGS%% *}
KEY2_ANCH=${ANCHOR_ARGS#* }
[[ $MID2_ANCH == "$MID2" && ${#KEY2_ANCH} -ge 40 ]] || rc=1
cfgdir="$HOME_A/Library/Application Support/exvia"
[[ -d "$HOME_A/.config/exvia" ]] && cfgdir="$HOME_A/.config/exvia"
first_seen_of() {
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]].get("first_seen"))' \
        "$cfgdir/known_agents.json" "$1" 2>/dev/null
}
cli "$HOME_A" known rm "$MID2" >/dev/null 2>&1 || true   # 清掉 t40/t46 留下的 TOFU 记录
cli "$HOME_A" known add "$MID2_ANCH" "$KEY2_ANCH" >"$DIR/t48-add.out" 2>&1 || rc=1
grep -q "anchored known agent $MID2" "$DIR/t48-add.out" || rc=1
FS1=$(first_seen_of "$MID2")
[[ -n ${FS1:-} ]] || rc=1
# 幂等：同钥重复预置 → already anchored，退出码 0
cli "$HOME_A" known add "$MID2_ANCH" "$KEY2_ANCH" >"$DIR/t48-add2.out" 2>&1 || rc=1
grep -q 'already anchored' "$DIR/t48-add2.out" || rc=1
# 预置后首连成功
cli "$HOME_A" exec m-two -- /bin/echo anchored-ok >"$DIR/t48-exec.out" 2>&1 || rc=1
grep -q 'anchored-ok' "$DIR/t48-exec.out" || rc=1
# 首连没有改写记录：first_seen 仍是预置时刻的值（TOFU 路径会以会话时刻重写）
FS2=$(first_seen_of "$MID2")
[[ $FS2 == "$FS1" ]] || rc=1
record "enroll echo presets a trust anchor, first session verifies it" $rc "mid2=$MID2"

# ---------- 预置错钥必须拒绝，known rm 恢复 ----------
# 给 t40 造的第二台 agent 预置一把合法 b64 但随机的错误公钥：首连必须被拒
# （报错含对端公钥与记录不符语义）；known rm 清掉错误锚后 TOFU 重新记录、会话恢复。
rc=0
BADKEY=$(python3 -c 'import os,base64; print(base64.b64encode(os.urandom(32)).decode())')
cli "$HOME_A" known rm "$MID2" >/dev/null 2>&1 || true
cli "$HOME_A" known add "$MID2" "$BADKEY" >"$DIR/t49-add.out" 2>&1 || rc=1
cli "$HOME_A" exec m-two -- /bin/echo should-not-run >"$DIR/t49-exec.out" 2>&1 && rc=1
grep -qi 'differs from the recorded' "$DIR/t49-exec.out" || rc=1
grep -q 'should-not-run' "$DIR/t49-exec.out" && rc=1
# 恢复路径：known rm 后首连重新按 TOFU 记录真实公钥并放行
cli "$HOME_A" known rm "$MID2" >"$DIR/t49-rm.out" 2>&1 || rc=1
ok=0
for _ in $(seq 1 5); do
    if cli "$HOME_A" exec m-two -- /bin/echo recovered >"$DIR/t49-ok.out" 2>&1; then ok=1; break; fi
    sleep 0.5
done
(( ok == 1 )) || rc=1
grep -q 'recovered' "$DIR/t49-ok.out" || rc=1
record "a wrong preset key is rejected on first contact, known rm recovers" $rc

# ---------- results ----------
echo
echo "==== results (port ${PORT}) ===="
printf '%s\n' "${RES[@]}"
echo "--------------------------------"
echo "total: PASS=$pass FAIL=$fail"
(( fail == 0 )) || exit 1
exit 0
