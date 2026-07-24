# Independent Codex Low-Level Review Supervisor v2

这是 `independent-codex-pr-review` 低层工具的任务级实现。它不满足 named single、
double、triple review，也不是 canonical PR-readiness 的隐式门禁。它只在本目录的默认
`runtime/` 下创建 supervisor 状态、独立 checkout 和测试临时文件，不修改目标仓库
源码、文档、refs、当前 checkout 或 helper 状态。只有现有 access token 无法覆盖有界
review deadline 时，`run` 才允许经过同一受限 Codex snapshot 执行 no-model managed-auth
refresh；该步骤可能由 Codex 原子更新正常账户的 `~/.codex/auth.json`。

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

以下命令需在已安装的 self-contained tool directory 中运行，只使用本目录中的
fixtures/runtime，创建 disposable local Git repositories；不启动 Codex、不访问网络、
不读取认证配置：

```bash
TRUSTED_PYTHON=/absolute/path/to/parent-validated/python3.13
PYTHONDONTWRITEBYTECODE=1 "$TRUSTED_PYTHON" -B -m tests.run_required_deterministic_supervisor
CODEX_REVIEW_REQUIRE_LIVE_NO_CHILD_PROFILE=1 PYTHONDONTWRITEBYTECODE=1 "$TRUSTED_PYTHON" -B -m tests.run_required_no_child_profile
PYTHONDONTWRITEBYTECODE=1 "$TRUSTED_PYTHON" -B independent-codex-pr-review --help
```

第一条命令是跨 Hosted Runner 的确定性零跳过测试；第二条命令只允许在匹配生产 pin、
且没有外层 Seatbelt 的受信任 Mac 上运行，九项测试必须全部执行并通过。GitHub Hosted
`macos-26` 自身位于外层 Seatbelt 中，不能产生生产等价的 live isolation evidence；CI
因此只验证该环境以已审阅的 blocker signature 失败关闭，并把真实九项 live suite 保留为
涉及隔离边界变更时的本机交付门。若 Hosted 环境不再呈现该 signature，CI 会失败并要求
重新审阅架构，不能把环境指纹相同解释为生产能力证明。

这个 live gate 是合并前由交付操作者执行的 exact-head procedure，不是 GitHub check、
branch-protection status 或 cryptographic attestation。最终 commit 产生后，PR delivery
evidence 必须记录对应 `head_sha`、9 tests、0 skips 和 terminal result；任何后续 push 都会
使证据失效。缺少该证据时，涉及 Darwin isolation boundary 的变更不能报告 merge-ready。
