# Independent Codex Low-Level Review Supervisor v2

这是 `independent-codex-pr-review` 低层工具的任务级实现。它不满足 named single、
double、triple review，也不是 canonical PR-readiness 的隐式门禁。它默认在当前 POSIX
账户的 `~/.codex/review-runtime/independent-codex-pr-review/` 下创建 supervisor
状态和独立 checkout，不修改目标仓库源码、文档、refs、当前 checkout 或 helper
状态。只有现有 access token 无法覆盖有界 review deadline 时，`run` 才允许经过同一
受限 Codex snapshot 执行 no-model managed-auth refresh；该步骤可能由 Codex 原子更新
正常账户的 `~/.codex/auth.json`。

`preflight` 不启动 Codex。`run` 是唯一会启动实际 reviewer 的公共命令。
supervisor 只把验证过的 external ChatGPT auth generation 通过内存协议交给 reviewer。
该 generation 在 launch 与 login serialization 两个边界都会重新验证文件身份和完整
bounded-review 剩余时效；时钟异常、generation 漂移或剩余时效不足都会失败关闭。
reviewer 使用隔离的 owner-only `CODEX_HOME`，不会加载正常账户配置、Rules、MCP
servers、Plugins、Skills、Hooks、项目指令或 workspace 环境。

## Requirements

- 必须使用 Python 3.13；其他 Python 版本在入口处失败关闭。
- `--repo`、`--helper-state`、retention root 和 checkout parent 必须是绝对路径。
- `--base` 与 `--head` 必须是目标仓库对象格式对应的完整 commit OID。
- helper attempt 必须已完成，使用 `--reviewer codex --keep-workspace`，并保留匹配的
  `preflight.json`、`control-artifact-state.json`、`cleanup.lock` 和
  `.codex-review/review.diff`。
- retention root 与 checkout parent 必须是当前用户控制的精确 `0700` 目录。工具从
  filesystem root 开始逐级执行 no-follow descriptor walk；每个祖先必须由 root 或当前
  用户拥有，且不可被 group/other 写入，root/current-user owned sticky directory 是唯一
  例外。macOS 只把 root-owned `/etc`、`/tmp`、`/var` 的固定系统 alias 映射到对应
  `/private/*` 路径。
- macOS 的每一级目录都经过稳定的 descriptor-based ACL/xattr 双重采样。私有目录和
  文件拒绝所有 ACL、quarantine 和未知 xattr，只允许系统自动添加的
  `com.apple.provenance`；可信系统祖先还允许 `com.apple.rootless`。retention lease
  在整个 outer lifecycle 持有已认证 root descriptor，attempt 通过 `mkdirat` 创建，
  并把 root 与 attempt identity 写入 durable state 供重启后的操作重新绑定。

## Exact Handoff And Run

以下变量示例使用已安装的 self-contained tool directory。`stateful start` 只在 stdout
输出新建的 state directory，因此可直接捕获为 `HELPER_STATE`。

```bash
TOOL_DIR=/absolute/path/to/review-orchestration-playbook/scripts/independent_codex_pr_review
SUPERVISOR="$TOOL_DIR/independent-codex-pr-review"
HELPER="$TOOL_DIR/../isolated_review"
REPO=/absolute/path/to/repo
BASE_SHA=<full-base-commit-oid>
HEAD_SHA=<full-head-commit-oid>
PR_URL=https://github.com/OWNER/REPO/pull/NUMBER
RETENTION="$TOOL_DIR/runtime/retention"
CHECKOUTS="$TOOL_DIR/runtime/checkouts"

HELPER_STATE="$($HELPER stateful start \
  --repo "$REPO" \
  --reviewer codex \
  --base-ref "$BASE_SHA" \
  --head-ref "$HEAD_SHA" \
  --keep-workspace)"

$HELPER stateful status --state-dir "$HELPER_STATE"
$HELPER stateful wait --state-dir "$HELPER_STATE" --timeout-seconds 60
$HELPER stateful final --state-dir "$HELPER_STATE"
```

本节的 self-contained 示例必须显式使用上面的独立 runtime roots；
account-local defaults 只用于标准 installed overlay catalog，那里可以持续绑定当前
release、helper 与 sibling release 目录。缺少该 catalog 的 self-contained helper
若使用默认 root，会因无法证明 legacy migration fence 而按设计失败关闭。

For each public command, the CLI resolves one default state-root snapshot from
the current POSIX account database, not from `$HOME`, and derives both retention
and checkout defaults from it. Installed release trees therefore remain
immutable, retained evidence survives release replacement, and an account-home
change cannot split one command's defaults across two roots. Non-default
explicit `--retention-root` and `--checkout-parent` values remain available for
task-scoped isolated runs. Every explicitly supplied retention root is compared
with the account-local default through the secure descriptor walk before the
tool can select custom-root behavior. Existing prefixes are compared by object
identity and missing suffixes use a conservative case-insensitive policy. The
comparison retains the existing-prefix descriptors and reopens both paths
before returning, so object or access-policy replacement and missing-suffix
creation observed between the initial snapshots and final revalidation fail
closed. A proven distinct retention root skips the default migration gate; an
equivalent alias uses it, and an unavailable proof fails through the CLI's
single-line JSON failure contract. An explicit checkout parent avoids a second
default-path helper call.

从使用 release-local `runtime/retention` 的旧版本升级时，新版本始终先扫描当前
helper 根下的旧 retention root，因此 self-contained 或非标准安装布局不会绕过迁移
门禁；若当前 helper 位于标准 installed overlay，还会扫描 sibling releases。只要任一
旧 root 仍有 attempt，所有使用 account-local default 的公共命令都会失败关闭并报告
精确旧 root。扫描逐级持有 no-follow descriptors，复用 ACL/xattr access-policy
检查，并对旧 `retention.lock` 获取非阻塞 migration fence；活动旧 writer 会失败
关闭，该 fence 保持到本次默认-root 命令完成。使用报告的旧路径显式运行 `status`、
`final`、`recover`、`release` 和 `cleanup`，直到旧 root drained；在此之前不得删除
旧 release。扫描不会搬动活动 attempt，也不会把旧 attempt 并入新的 account-local
root。
CLI 会把显式或默认 retention root 与 account-local default 的等价性快照保持到公共
命令结束，并让该命令对所选 root 的每次精确打开都验证同一 binding。binding 保护
对象身份、访问策略和两条路径的等价关系；missing leaf 的预期创建和目录 child-entry
churn 可以继续，现有前缀、所选 root、default root 或等价关系的替换会在写入
`retention.lock` 或后续状态前失败关闭。命令结束后还会再次验证该 binding。
采用 account-local retention 的 release 必须携带经过内容、身份与访问策略校验的
`ACCOUNT_LOCAL_RETENTION_V1` 标记。扫描先精确读取标记，再完成 held descriptor、
reopened path、ACL/xattr 和对象身份复验，随后从原 descriptor 第二次完整读取；两次
bytes 必须完全一致。时间戳变化不构成内容变化。当前正在执行的 installed release
也必须通过同一 marker、目录身份和 catalog 稳定性检查，但复用已经持有的 current-root
fence，不重复加锁。若仍包含 helper 的未标记 release 没有可获取的 legacy retention
lock，新命令会在执行公共命令前失败关闭；需要先停用或移除该 release，不能用一次
“路径暂时不存在”的探测推断它之后不会启动。
对于当前或 sibling release 中尚无 legacy root 的 helper，扫描会把初始逐组件 policy
和最深层 existing descriptor 保持到公共命令结束；终态 fresh probe 必须与初始
custody 完全一致。替换嵌套 helper 目录会失败关闭，而只改变目录 child entries 不会被
误判为对象或访问策略替换。
公共命令失败后仍执行完整 fence finalization 和 descriptor cleanup；若它们也失败，
原命令异常的类型与结构化诊断保持主错误，后续故障只作为次级 exception evidence
附加，并通过可选的 `secondary_errors` 数组输出；该数组最多 4 条、每条最多 512
字符。命令成功时的 finalization 或 cleanup 故障仍会失败关闭。
每个 legacy root 的初始 attempt 状态也属于 fence 证据：起初为空且已加锁的 root
若在公共命令期间出现 `attempt-*`，finalization 会失败关闭，不能把最终枚举到的新
attempt 当作无关 child-entry churn。

仅在 helper 已 terminal 后运行独立 preflight。它验证 exact repo/base/head、helper
runner completion、primary-diff 双重 attestation、control directory 完整性、source
metadata、最终 primary-evidence byte limit、账本、host floor、raw Git manifests、prompt
bytes、Codex path 的 stable regular/executable 形态和 exec argv budget；不会创建 attempt、
prompt 或 worktree，也不会启动 Codex。Codex 的签名、版本、schema、snapshot 和 external
auth generation 仍由 `run` 在任何 model request 之前完成验证。

```bash
python3.13 -B "$SUPERVISOR" preflight \
  --helper-state "$HELPER_STATE" \
  --repo "$REPO" \
  --base "$BASE_SHA" \
  --head "$HEAD_SHA" \
  --pr-url "$PR_URL" \
  --retention-root "$RETENTION" \
  --checkout-parent "$CHECKOUTS"
```

只有 preflight 返回一行 `{"status":"ready",...}` 后才运行 reviewer：

```bash
python3.13 -B "$SUPERVISOR" run \
  --helper-state "$HELPER_STATE" \
  --repo "$REPO" \
  --base "$BASE_SHA" \
  --head "$HEAD_SHA" \
  --pr-url "$PR_URL" \
  --retention-root "$RETENTION" \
  --checkout-parent "$CHECKOUTS"
```

### Standard Installed Overlay Defaults

标准 installed overlay 必须省略显式 runtime roots，让 CLI 使用 account-local defaults
并执行 sibling-release migration fence。对应的 preflight/run 形式如下；后续
`status`、`final`、`recover`、`release` 和 `cleanup` 同样省略
`--retention-root`：

```bash
python3.13 -B "$SUPERVISOR" preflight \
  --helper-state "$HELPER_STATE" \
  --repo "$REPO" \
  --base "$BASE_SHA" \
  --head "$HEAD_SHA" \
  --pr-url "$PR_URL"

python3.13 -B "$SUPERVISOR" run \
  --helper-state "$HELPER_STATE" \
  --repo "$REPO" \
  --base "$BASE_SHA" \
  --head "$HEAD_SHA" \
  --pr-url "$PR_URL"
```

`run` 返回单行 JSON。保存其中的 `attempt_dir`，然后读取状态并重新验证唯一 sealed
final artifact；不要把 stdout/stderr JSONL、tail 或 keepalive 当成 findings。

```bash
ATTEMPT_DIR=<attempt_dir-from-run-json>

python3.13 -B "$SUPERVISOR" status \
  --retention-root "$RETENTION" \
  --attempt-dir "$ATTEMPT_DIR"

python3.13 -B "$SUPERVISOR" final \
  --retention-root "$RETENTION" \
  --attempt-dir "$ATTEMPT_DIR"
```

`final` 只在两个 settlement 均为 `exact`、attempt supervisor 已被 outer 以零退出码
reap、outer final authorization 与直接 predecessor 完整绑定、final
device/inode/length/SHA-256 重新读回一致且文本分类匹配时返回 `final_message`。内部
terminal authorization 本身不构成 completed 状态。

## Helper Cleanup

独立 destination seal/readback 完成后，状态 JSON 会显示
`source_custody_released=true`。只有此时，且不再需要 clean-context fallback，才清理
helper workspace：

```bash
$HELPER stateful cleanup --state-dir "$HELPER_STATE"
```

不要提前执行该命令。运行期间 supervisor 通过同一个 `cleanup.lock` 的 shared BSD
`flock` 与 already-open no-follow source FD 保持 custody；helper cleanup 使用 exclusive
侧，不能越过该 lease。

## Recovery

先读取 durable state：

```bash
python3.13 -B "$SUPERVISOR" status \
  --retention-root "$RETENTION" \
  --attempt-dir "$ATTEMPT_DIR"
```

同一 boot 中，只有原始 outer/supervisor 及其未 reap 的 child handles 能证明 closure。
后继 `recover` 会返回 `same-boot-owner-required`，不会修改状态；不要循环重试或手工杀掉
owner。记录的 boot ID 与当前 boot ID 不同时，运行：

```bash
python3.13 -B "$SUPERVISOR" recover \
  --retention-root "$RETENTION" \
  --attempt-dir "$ATTEMPT_DIR"
```

boot-change recovery 会先验证 phase 对应的 durable closure evidence，再严格枚举
no-follow process artifacts。exact process ledger 在任何删除前先保守计入完整 process
envelope；随后 interrupted prompt/state temporaries 与 retained `review-runtime/` 通过有界
custody manifest 清理，最后重新精确结算。prelaunch phase 保持
`review_status=not-run`；`spawn-intent`、`launched` 及缺少有效 outer authorization 的
post-review phase 都降级为 `review_status=inconclusive`。post-review recovery 不从
`final.txt` 恢复分类，也不会生成或修复 final authorization。process settlement 与
checkout settlement 相互独立。

若 helper handoff 留下 checkout-only、registration-only 或其他可认证的 mixed state，
recovery 会先持久化外部有界 manifest 和删除进度，再通过持续托管的描述符执行
descriptor-relative、no-follow 的 targeted removal。注册别名、身份漂移或 manifest
不一致仍会失败关闭；不会运行 `git worktree prune`、递归路径删除、隔离 rename 或
猜测性 unlink。

## Release And Cleanup

terminal status 或年龄本身不会释放 evidence。parent 确认已经消费 findings 后记录
`resolved`；receiver 已确认接管且本地副本可回收时记录 `handoff-complete`：

```bash
python3.13 -B "$SUPERVISOR" release \
  --retention-root "$RETENTION" \
  --attempt-dir "$ATTEMPT_DIR" \
  --reason resolved
```

```bash
python3.13 -B "$SUPERVISOR" release \
  --retention-root "$RETENTION" \
  --attempt-dir "$ATTEMPT_DIR" \
  --reason handoff-complete
```

只有 process 与 checkout 都 `exact`、没有 manual worktree recovery、且 evidence 已显式
released 时，才可回收整个 attempt：

```bash
python3.13 -B "$SUPERVISOR" cleanup \
  --retention-root "$RETENTION" \
  --attempt-dir "$ATTEMPT_DIR"
```

该命令先持久化 `retention_state=reclaimed`，再以 no-follow descriptor-relative 方式删除
ordinary artifacts，最后删除 `state.json`、attempt directory，并 fsync retention root。
每次 `preflight` 都会先回收已显式 release 且超过 7 天的 attempt；若新 attempt 因
retention 或 checkout 容量受阻，还会按 `released_at` 从旧到新逐个回收未过期的已释放
attempt，然后重新执行完整 admission。中断的 `reclaiming` 状态可安全恢复，且在物理
删除和最终 tombstone 清除前不会提前退还账本 charge。

## Reviewer Invocation

运行时不经过 shell 或 `eval`。Codex source 先经过 path/FD identity、codesign、version
和 SHA-256 验证，再复制到 owner-only snapshot；只有 snapshot 可以执行。每个
auth-refresh 和 reviewer stage 都由该 snapshot 在 lease-owned `0700` work root 中生成并
验证 aggregate schema，不依赖 checkout 或安装目录中的 sidecar。实际 reviewer argv
固定为 app-server stdio，并附带完整的 no-execution strict-config overrides：

```bash
/OWNER-ONLY/SNAPSHOT/codex app-server \
  --session-source exec \
  --strict-config \
  -c '<PINNED-NO-EXECUTION-OVERRIDE>' ... \
  --stdio
```

sessionFlags 显式禁用 tools、web search、MCP、Apps、Plugins、Skills、Hooks、subagents、
shell、remote control、memory、history persistence 和环境/项目指令注入。有效 config 和
sessionFlags/user/system 三层 inventory 必须逐项匹配，否则在 model request 前失败关闭。
完整 diff 与允许的 nearby context 在 launch 前组装为 bounded evidence bundle；reviewer
没有 checkout path 或 filesystem capability。`gpt-5.6-sol` 与 `xhigh` 在每次 thread/turn
request 中显式绑定，禁止静默 provider/model fallback。

snapshot 的 Seatbelt profile 默认拒绝所有写入，只允许 isolated `CODEX_HOME` 与 `TMPDIR`
两个通过 held read-only directory FD 认证的 writable roots，并把 `RLIMIT_NPROC` 固定为
hard zero。每个 auth-refresh/reviewer child 都满足 `pid == pgid == session`，其 spawn intent、
leader binding、profile binding、exit 和 closure 按阶段写入 durable ledger。authenticated
no-child profile 保证 leader 是进程组唯一成员；custodian 在 reap 前解除 signal relay，避免
PID/PGID reuse。`SIGHUP`、`SIGTERM` 与 `SIGQUIT` 都会先触发 bounded cleanup；默认
`SIGQUIT` 最终使用无 core 的 termination。只有 leader 已由 owner reap、stdio 已关闭后，
final artifact 才能进入独立 authorization/readback 流程。

## Status And Exit Codes

所有公共命令 stdout 都只有一行 compact JSON。

每个公共 JSON envelope 和持久化 attempt state 都固定包含
`review_contract: supplied-diff-no-git` 与 `named_lane_eligible: false`。缺失、畸形或不为
布尔值 `false` 的持久化标签会在读取时失败关闭。exit `0`、`overall_status: completed`、
`review_status: clean`、请求模型名或 `No findings.` 都不能把这个预供证据、无 reviewer Git
能力的低层 helper 升级为 named review lane。

- `0`: 命令完成；`run` 得到可分类 terminal artifact，或管理操作成功。
- `1`: attempt 已 terminal，但存在 inconclusive/manual cleanup 阻塞。
- `2`: preflight、handoff、recovery、state authentication 或 CLI 操作失败关闭。

关键独立字段包括 `admission_status`、`phase`、`handoff`、`launch_status`、
`review_status`、`cleanup_status`、`worktree_status`、`reservation_status`、
`process_settlement`、`checkout_settlement`、`retention_state`、`failure_stage`、
`source_custody_released`、requested/observed runtime metadata 和 final seal。

## Explicit Unsupported Clauses

这些项目会出现在每次 preflight/attempt JSON 的 `unsupported_clauses` 中，不会被静默
降级：

- `cross-crash-stable-handle-cleanup-backend`: 未配置可证明 deletion-versus-move 的平台
  durable handles。
- `quota-backed-zero-physical-overshoot`: lightweight profile 只做保守 admission accounting，
  不提供 quota-backed strict guarantee。

## Self-Tests

This candidate gate and its receipts are implementation/self-test evidence only; formal named-review lanes remain controlled by an independently trusted prior bundle.

以下命令需在已安装的 self-contained tool directory 中运行，只使用本目录中的
fixtures/runtime，创建 disposable local Git repositories；不启动 Codex、不访问网络、
不读取认证配置：

```bash
TRUSTED_PYTHON=/absolute/path/to/parent-validated/python3.13
TRUSTED_GIT_DEVELOPER_DIR=/absolute/path/to/parent-validated/Developer
TRUSTED_GIT=/absolute/path/to/parent-validated/git
TRUSTED_GIT_SHA256=<parent-validated-sha256>
TRUSTED_GIT_EXEC_PATH=/absolute/path/to/parent-validated/git-core
TRUSTED_GIT_CONTROL_PARENT=/absolute/path/to/owner-private-control-parent
TRUSTED_GIT_TMPDIR=/absolute/path/to/owner-private-runtime
if ! PYTHONDONTWRITEBYTECODE=1 "$TRUSTED_PYTHON" -B \
  -m tests.run_required_deterministic_supervisor; then
  exit 1
fi
TOOL_ROOT="$PWD"
HEAD_SHA=<full-head-sha>
GATE_SOURCE="$TOOL_ROOT/tests/trusted_mac_gate.py"
GATE_SOURCE_SHA256=<manifest-bound-sha256>
SOURCE_MANIFEST="$TOOL_ROOT/trusted_mac_gate_sources.index"
SOURCE_MANIFEST_SHA256=<manifest-bound-sha256>
set -o pipefail
stream_manifest_gate() {
  /usr/bin/env -i LANG=C LC_ALL=C PATH=/usr/bin:/bin \
    "$TRUSTED_PYTHON" -I -B -S -c '
import hashlib
import os
import stat
import sys

limit = 131072
path, expected_digest = sys.argv[1:]
if len(expected_digest) != 64 or any(
    character not in "0123456789abcdef" for character in expected_digest
):
    raise SystemExit("invalid manifest-bound gate digest")
flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
descriptor = os.open(path, flags)
try:
    opened = os.fstat(descriptor)
    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
        raise SystemExit("trusted gate is not a singly linked regular file")
    if opened.st_size < 1 or opened.st_size > limit:
        raise SystemExit("trusted gate size is outside the closed bound")
    chunks = []
    total = 0
    while total <= limit:
        chunk = os.read(descriptor, min(65536, limit + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    data = b"".join(chunks)
    closed = os.fstat(descriptor)
finally:
    os.close(descriptor)
identity = lambda value: (
    value.st_dev,
    value.st_ino,
    stat.S_IFMT(value.st_mode),
    value.st_uid,
    value.st_gid,
    stat.S_IMODE(value.st_mode),
    value.st_nlink,
    value.st_size,
)
if identity(opened) != identity(closed):
    raise SystemExit("trusted gate identity or access policy changed")
if len(data) != opened.st_size or not 1 <= len(data) <= limit:
    raise SystemExit("trusted gate content exceeded or disagreed with its bound")
if hashlib.sha256(data).hexdigest() != expected_digest:
    raise SystemExit("trusted gate digest disagrees with the installed manifest")
view = memoryview(data)
while view:
    written = os.write(1, view)
    if written <= 0:
        raise SystemExit("trusted gate stream made no progress")
    view = view[written:]
' "$GATE_SOURCE" "$GATE_SOURCE_SHA256"
}
measure_trusted_git_directory_custody() {
  local directory="$1"
  stream_manifest_gate \
    | /usr/bin/env -i HOME=/var/empty LANG=C LC_ALL=C PATH=/usr/bin:/bin \
        TMPDIR="$TRUSTED_GIT_TMPDIR" "$TRUSTED_PYTHON" -I -B -S - \
          --trusted-git-tmpdir-receipt "$directory"
}
if ! TRUSTED_GIT_CONTROL_PARENT_CUSTODY_RECEIPT="$(
  measure_trusted_git_directory_custody "$TRUSTED_GIT_CONTROL_PARENT"
)"; then
  exit 1
fi
if ! TRUSTED_GIT_TMPDIR_CUSTODY_RECEIPT="$(
  measure_trusted_git_directory_custody "$TRUSTED_GIT_TMPDIR"
)"; then
  exit 1
fi
for custody_receipt in \
  "$TRUSTED_GIT_CONTROL_PARENT_CUSTODY_RECEIPT" \
  "$TRUSTED_GIT_TMPDIR_CUSTODY_RECEIPT"; do
  if [[ "$custody_receipt" == *$'\n'* ]] \
    || [[ "$custody_receipt" != \
      *'"schema":"trusted-git-tmpdir-custody-v1"'* ]]; then
    exit 1
  fi
done
verify_trusted_git_directory_custody() {
  local current_control_parent_receipt=""
  local current_tmpdir_receipt=""
  current_control_parent_receipt="$(
    measure_trusted_git_directory_custody "$TRUSTED_GIT_CONTROL_PARENT"
  )" || return 1
  current_tmpdir_receipt="$(
    measure_trusted_git_directory_custody "$TRUSTED_GIT_TMPDIR"
  )" || return 1
  [[ "$current_control_parent_receipt" == \
    "$TRUSTED_GIT_CONTROL_PARENT_CUSTODY_RECEIPT" ]] \
    && [[ "$current_tmpdir_receipt" == \
      "$TRUSTED_GIT_TMPDIR_CUSTODY_RECEIPT" ]]
}
if ! TRUSTED_GIT_TOOLCHAIN_RECEIPT="$(
  stream_manifest_gate \
    | /usr/bin/env -i HOME=/var/empty LANG=C LC_ALL=C PATH=/usr/bin:/bin \
        TMPDIR="$TRUSTED_GIT_TMPDIR" "$TRUSTED_PYTHON" -I -B -S - \
          --hosted-git-receipt "$TRUSTED_GIT_DEVELOPER_DIR" \
          "$TRUSTED_GIT" "$TRUSTED_GIT_SHA256" \
          "$TRUSTED_GIT_EXEC_PATH"
)"; then
  exit 1
fi
if ! verify_trusted_git_directory_custody; then
  exit 1
fi
if ! stream_manifest_gate \
  | /usr/bin/env -i LANG=C LC_ALL=C PATH=/usr/bin:/bin \
  "$TRUSTED_PYTHON" -I -B -S - "$TOOL_ROOT" \
  "$SOURCE_MANIFEST" "$SOURCE_MANIFEST_SHA256" live; then
  exit 1
fi
if ! stream_manifest_gate \
  | /usr/bin/env -i LANG=C LC_ALL=C PATH=/usr/bin:/bin \
  "$TRUSTED_PYTHON" -I -B -S - "$TOOL_ROOT" \
  "$SOURCE_MANIFEST" "$SOURCE_MANIFEST_SHA256" readonly "$HEAD_SHA" \
  "$TRUSTED_GIT_TMPDIR" "$TRUSTED_GIT_DEVELOPER_DIR" "$TRUSTED_GIT" \
  "$TRUSTED_GIT_SHA256" "$TRUSTED_GIT_EXEC_PATH" \
  "$TRUSTED_GIT_TOOLCHAIN_RECEIPT" \
  "$TRUSTED_GIT_TMPDIR_CUSTODY_RECEIPT"; then
  exit 1
fi
if ! verify_trusted_git_directory_custody; then
  exit 1
fi
if ! PYTHONDONTWRITEBYTECODE=1 "$TRUSTED_PYTHON" -B \
  independent-codex-pr-review --help; then
  exit 1
fi
```

第一条命令是确定性零跳过测试。Hosted CI 的 required read-only job 另以 root-owned
isolated source、随机命名且 receipt-bound 的 ephemeral non-admin child account、受监管
Python runtime 和完整 deterministic suite 验证安装树。Workflow 为该 account 选择未占用的
专用 UID/GID，绑定 user/group GUID，拒绝 admin membership 或该 UID 已存在的进程，并在启动前、
supervised run 后和删除前重验同一身份与 exact-UID process census；身份不明、replacement、
census 失败或残留进程都会 fail closed，并保留 account records 到 ephemeral runner disposal。
它保留 `source_head_bound == false` 与 `no_child_runtime_profile == null`，因为 exact Git binding
和 production no-child proof 不属于这个 isolated copy 的证明边界。

后续 receipt、live 与 readonly gate commands 只允许在匹配 production pin、且没有外层
Seatbelt 的受信任 Mac 上连续运行。
它们不通过 ambient `PYTHONPATH` 或 `-m` 解析 candidate source。source-only bootstrap
要求 `-I -B -S`，且只从已绑定 exact HEAD blob 或 installed-release manifest 的最多
131072-byte stdin 执行。Installed-release 模式由 parent-validated Python 以 no-follow
descriptor 只读取一次，验证同一内存 byte sequence 的 manifest digest 后再流入 gate；
路径替换、增长、链接、FIFO 或 access-policy 变化均失败关闭。直接执行 candidate gate path
会失败。外部发布证据还必须分别绑定 `trusted_mac_gate_sources.index` 的 SHA-256；
安装树内的自声明摘要不能作为信任根。`TRUSTED_GIT_CONTROL_PARENT` 与
`TRUSTED_GIT_TMPDIR` 必须是 physical、current-UID、0700、zero-flags 的
owner-private directories。各自的 canonical receipt 持久化完整 root-to-target chain
的 type/device/inode/uid/gid/mode/flags；祖先 owner 只能是 root 或 current UID，普通
group/world-writable ancestor 失败关闭，root-owned sticky ancestor 允许。每级 ACL 必须
为空；target xattr 仅允许 provenance，ancestor 另允许系统 rootless marker，允许项的
出现/消失不序列化为漂移。Readonly v3 entry 先校验独立 closed TMPDIR custody
receipt，再以非执行方式重新读取 physical Git bytes 与完整 exec-path inventory，并
exact-compare canonical v2 toolchain receipt，随后再次校验 TMPDIR。Canonical receipt
本身只保护 exact Git path/SHA 与 exec-path closure；TMPDIR path/full-chain custody 是
并列的外部 receipt，由 readonly v3 composite profile 与 `DEVELOPER_DIR`、`GIT_EXEC_PATH`、
`TMPDIR` 环境绑定合并。发行或 operator 若另记 Git version/capability，只能作为 provenance
evidence，不能折入该 security identity；receipt issuance 与 child validation 均不执行 Git。
随后恢复完整的 `CODEX_REVIEW_BOUND_GIT_*` 绑定，并将同一
receipt-bound TMPDIR 设置为显式 `CODEX_REVIEW_TEST_RUNTIME_PARENT`，避免任何 ambient
repository candidate 或未绑定 Git dispatcher 探测。该 explicit parent 保持 private
target policy，同时只对 root-owned sticky writable ancestor 使用安全例外。清空环境后，gate 先将
`review_supervisor/` 与 `tests/` 的完整 regular-file inventory 和 checked manifest 中的
相对路径、Git mode、长度及 SHA-256 逐项比较，再从 descriptor-bound、双重读取且有
entry/path/source-byte 上限的捕获 bytes 映射加载模块；missing/extra entry、symlink、
`__pycache__`、`.pyc`/`.pyo`、native substitute 和重复 module mapping 均失败关闭。
十三项 live 测试必须全部执行并通过，随后 exact-head read-only install runner 必须返回完整
成功的 structured summary。该 Trusted Mac summary 只有在
`primary_status == "complete"`、`primary_failure == null`、
`child_process_closure == "proven"`、`cleanup_status == "complete"`、
`cleanup_failures == []`、`release_tree_immutable == true`、
`source_head_bound == true`、`source_head_sha == <full-head-sha>`、
`source_head_subtree_manifest_sha256` 是完整小写 SHA-256、
`source_manifest_sha256` 是完整小写 SHA-256、
`no_child_runtime_profile == "production-current"`、`returncode == 0`、
`retained_paths == []`、`runtime_residue == []`、`secondary_failures == []`、
`signal_number == null`、`timed_out == false`、`creation_origin_proven == false`、
`creation_origin_guarantee == "best-effort-128-bit-leaf-immediate-nofollow-open-same-uid-host-tcb"`
且
`cleanup_guarantee == "custodied-manifest-quarantine-descriptor-revalidation-same-uid-final-rename-unlink-host-tcb"`
时才算成功。后三项固定字段声明平台边界，不是失败：macOS 没有创建目录并原子返回
descriptor 的 API，也没有按 descriptor 删除目录的 API。因此 receipt 建立前的
`mkdirat`→首次 no-follow open 和最终 identity check→`unlinkat`/`rmdir` 窗口依赖
128-bit 不可预测 leaf 与 cooperative same-UID host TCB。receipt 建立后，工具绑定
identity/access policy，使用 custodied manifest、quarantine 和 descriptor revalidation；
一旦观察到 identity-unproven 或 mismatch，就保留对象且绝不删除当前 replacement。
CONTROL_PARENT 与 TMPDIR 的独立 receipts 都绑定完整 physical chain；每个 ordered
record 保护 type/device/inode 对象身份与 uid/gid/mode/flags access policy，每次
issuance/revalidation 另强制上述 owner、writable ancestor、ACL 与 property-scoped xattr
policy。不比较会因正常 child-entry churn 变化的 `nlink`、size、mtime 或 ctime。路径生成
到最终复验之间仍依赖文中既有的 cooperative same-UID host TCB，离散 receipt snapshot
不声称排除同 UID 的瞬时替换后恢复。
Exact-head source proof 不信任普通 `git status`。它拒绝 repository-visible include、
executable filter/diff、`core.fileMode=false`、fsmonitor、assume-unchanged 和
skip-worktree 状态，并通过隔离 Git object-control 视图读取 HEAD 的 raw tree/blob/mode。
Descriptor-based 双重 source snapshot 必须在路径集合、目录集合、完整文件字节和 executable
bit 上与该 raw subtree 精确一致；`source_head_subtree_manifest_sha256` 绑定这份 HEAD 证明，
而 `source_manifest_sha256` 继续绑定实际 source 的 path/type、content、mode/flags 和
access policy；descriptor snapshot 在 capture/revalidation 边界单独保护 object identity。
所有 source/installed snapshot 与 exact-receipt copy 共用累计 file/access-policy/path byte
和 entry-observation 预算；entry observation 统计 listing、open/capture 与 revalidation
观察，并非 unique path 数。每个双 pass snapshot 另有一个两遍共享的 monotonic deadline，
child 前后 snapshot 各自取得新 deadline。Copy 只遍历 initial exact snapshot 中已绑定的
expected path set；并发新增的 untracked/ignored/fanout path 不会先被复制或读取，随后仍由
同一累计预算下的 exact-head rebind 显式拒绝。Raw HEAD path 的隐式目录展开同样消费
depth/path/entry/deadline 预算。Hosted root-owned source 没有 Git metadata，因此不声明
`source_head_bound`；它仍先建立同一有界 descriptor receipt，再按 receipt 复制并复验，
不再使用无界 `copytree`。
GitHub Hosted `macos-26` 的独立 production-profile probe仍必须以已审阅 blocker signature
失败关闭；hosted read-only job 的 root/ephemeral-account 隔离成功不能替代 Trusted Mac
no-child proof。

这个 Trusted Mac gate 是合并前由交付操作者执行的 exact-head procedure，不是 GitHub
check、branch-protection status 或 cryptographic attestation。最终 commit 产生后，PR
delivery evidence 必须记录对应 `head_sha`、Python absolute path/digest、13 tests、0 skips、
live terminal result 和紧随其后的 read-only structured summary；该 read-only child还必须
给出固定的 no-child test count/identity completion record。任何后续 push 都会使证据失效。
缺少任一项时，涉及 Darwin isolation boundary 的变更不能报告 merge-ready。
