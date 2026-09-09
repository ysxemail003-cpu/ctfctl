# ctf-agent 优化实施方案

> 文档用途：供后续 AI 开发者和人工维护者执行本项目的工程化优化。
>
> 本文是实施计划，不是本轮代码改动说明。开发者应按阶段领取任务、直接修改代码和测试，并在完成后提交变更清单、测试结果和未解决风险。

## 1. 项目定位与当前基线

`ctf-agent` 是一个面向**已授权 CTF、靶场和 cyber range** 的本地运行时，不是单纯的题目求解器。它负责把自然语言请求转化为可审计的挑战工作流：

```text
自然语言请求
  → intake / current / context
  → scope 与授权检查
  → tool / run / tty 执行
  → logs / artifacts / events
  → state / evidence
  → specialist handoff / merge
  → flag replay verification
  → final report
```

### 现有核心目录

```text
src/ctf_agent/
├── cli.py              # CLI 解析与分发
├── challenge.py        # 挑战初始化、选择和恢复
├── intake.py           # 自然语言意图解析
├── runner.py           # 命令执行、缓存、日志
├── scope.py            # 授权目标和网络范围
├── state.py            # 挑战状态机
├── evidence.py         # 证据账本
├── context.py          # 压缩上下文
├── flag.py             # flag 生命周期、复现和提交
├── report.py           # 报告、handoff、result merge
└── adapters/           # HTTP、Nmap、ELF、Ghidra、文件导入等适配器
```

### 当前事实

- 现有测试基线：`26 passed`。
- 当前仓库处于初始开发工作树，尚无可用于回滚的 Git 历史提交。
- 当前适合单 Agent 或低并发运行。
- `state.yaml` 是规范状态，`STATE.md` 和 `EVIDENCE.md` 是生成文件。
- `original/` 应保持不可变；`work/` 用于修改、解包和运行。
- 当前 scope 已有若干 limits 字段，但部分 limits 还没有在运行时真正执行。

## 2. 优化目标

本次优化的目标是将项目从“单 Agent 可用的可审计工具集”提升为：

1. **并发安全**：多个低并发 Agent 不会互相覆盖状态、日志和证据。
2. **证据可信**：所有重要声明都能解析到真实日志、证据或 artifact。
3. **流程正确**：状态转换和 flag 生命周期符合定义，不允许伪造成功状态。
4. **执行安全**：原始输入、路径、进程、超时和敏感信息受到明确约束。
5. **协作可恢复**：specialist result 可重复合并，不因重试产生重复事实。
6. **Web 可复现**：HTTP 请求支持 session、Cookie 和完整请求/响应证据。
7. **可维护可扩展**：核心逻辑有明确接口、测试和质量门禁。

## 3. 非目标

本轮不要做以下工作：

- 不重写为大型 Web UI。
- 不立即用数据库替换 `state.yaml`、`events.jsonl` 和 `evidence.jsonl`。
- 不为所有 Kali 工具增加 adapter；只有结构化解析能显著提高准确率时才增加。
- 不默认开启自动 flag 提交。
- 不扩大 `.scope.yaml` 中的目标、端口或授权能力。
- 不把参数级 scope 检查宣传为完整网络隔离。
- 不直接修改现有挑战目录中的历史 evidence 以“修正”结果；历史记录应保持可追溯。

## 4. 开发总原则

### 4.1 兼容优先

优先保持现有 CLI 和目录布局兼容。破坏性 schema 变更必须提供迁移工具或兼容读取逻辑，并在 changelog 中说明。

### 4.2 单一写入入口

任何会修改规范状态、追加事件、追加证据或分配 ID 的操作，都必须经过统一的 runtime mutation/transaction 层。adapter 不应自行分配全局日志 ID。

### 4.3 原子性优先

对以下操作必须具备“要么完整成功，要么不产生半成品”的语义：

- 日志 ID 分配和 metadata 写入；
- state read-modify-write；
- evidence 追加；
- specialist result merge；
- projection 文件生成。

### 4.4 证据先于结论

新增 FACT、INFERENCE、HYPOTHESIS、技术结果和状态跃迁时，必须校验其证据引用。开发测试不得通过伪造 `LOG-*` 或 `E-*` 来绕过校验；测试应先创建真实 fixture 日志或证据。

### 4.5 最小权限

默认禁止：

- 访问 scope 外的网络目标；
- 修改 `original/`；
- 从挑战目录逃逸的路径操作；
- flag 自动提交；
- 将挑战数据上传到外部服务。

## 5. 分阶段实施计划

## Phase 0：建立基线和质量门禁

### 目标

让后续变更可回滚、可比较、可自动检查。

### 任务

1. 建立 Git 基线提交：

   ```text
   baseline: ctf-agent v0.2.0, 26 tests passing
   ```

2. 从 `pyproject.toml` 统一读取版本号，去除 CLI 中的重复硬编码。
3. 增加 lint、类型检查和覆盖率工具，建议：
   - Ruff；
   - mypy 或 pyright；
   - pytest-cov；
   - pre-commit。
4. 增加统一质量命令：

   ```text
   make test
   make lint
   make typecheck
   make coverage
   make check
   ```

5. 增加 CI：测试、lint、类型检查和 package build。

### 验收标准

- 现有测试全部通过；
- `make check` 可以一次执行所有质量检查；
- 版本号只维护一处；
- CI 可从干净环境构建并运行测试。

## Phase 1：Runtime Core Hardening（最高优先级）

### 目标

解决多 Agent 场景下最危险的一致性问题。

### 任务 A：锁和并发 ID

新增 challenge-level runtime lock，例如：

```text
<challenge>/.runtime.lock
```

使用 Linux `fcntl.flock`，并保证同进程嵌套调用不会死锁。以下操作必须在锁内完成：

- `LOG-*`、`EVT-*`、`E-*`、`F-*`、`H-*` ID 分配；
- state 更新；
- evidence/event append；
- flag 状态更新；
- specialist merge。

要求：

- 兼容现有 `LOG-000001` 和日志文件名格式；
- 不依赖文件名数量猜测唯一 ID；
- 并发失败时返回清晰错误，不静默覆盖；
- 新增多进程并发测试。

### 任务 B：state revision 和状态转换

在后续 schema 中增加 revision，例如：

```yaml
revision: 17
```

保存前检查磁盘 revision，避免旧 context 覆盖新状态。实现合法转换表，禁止任意状态跳转。建议转换关系：

```text
INIT        → AUTHORIZED / BLOCKED / ABANDONED
AUTHORIZED  → RECON / BLOCKED / ABANDONED
RECON       → HYPOTHESIS / TESTING / BLOCKED / ABANDONED
HYPOTHESIS  → TESTING / RECON / BLOCKED / ABANDONED
TESTING     → EXPLOITATION / VERIFICATION / HYPOTHESIS / BLOCKED
EXPLOITATION→ VERIFICATION / TESTING / BLOCKED
VERIFICATION→ SOLVED / EXPLOITATION / BLOCKED
SOLVED      → SOLVED
BLOCKED     → RECON / HYPOTHESIS / ABANDONED
ABANDONED   → 无
```

如确需跳过流程，必须使用显式 force 操作，并强制要求 reason 和 evidence。

### 任务 C：严格 evidence 引用

统一实现证据解析器：

- `LOG-*` 必须对应真实 metadata，且 metadata 中的 ID 必须一致；
- metadata 引用的 stdout/stderr 必须存在；
- `E-*` 必须存在于 `evidence.jsonl`；
- artifact 必须存在于 challenge 目录内，且不能通过 symlink 逃逸；
- 外部 operator input 必须通过导入记录，并保留 hash。

默认拒绝 unresolved evidence。调试例外必须显式标记并写入 event。

### Phase 1 验收标准

- 20 个并发写入测试无重复 ID、无损坏 JSONL、无丢失 state 更新；
- 非法状态转换被拒绝；
- 不存在的 LOG/E/artifact 引用被拒绝；
- 现有测试和历史挑战只读加载仍兼容；
- `STATE.md`、`EVIDENCE.md` 可从规范数据重新生成。

## Phase 2：执行安全与 scope enforcement

### 目标

把“文档中的安全要求”转化为“代码中的默认约束”。

### 任务 A：路径策略

统一处理并拒绝：

- `original/` 写入；
- `..` 逃逸；
- symlink 逃逸；
- challenge 外部 cwd；
- 未经导入的未知 binary 执行；
- 未授权外部文件作为输入。

建议新增 execution policy 模块，并使用 `Path.resolve()` 后的 `is_relative_to()` 做判断。

### 任务 B：进程组和 timeout

`run_command()`、`run_tty()` 应：

1. 使用独立 process group/session；
2. timeout 后先终止进程组；
3. 等待宽限期后再强制杀死；
4. 在日志中记录 timeout、信号和终止结果；
5. 测试子进程不会在父命令超时后残留。

### 任务 C：敏感信息脱敏

统一脱敏 command、环境变量、HTTP headers、Cookie 和 submission token。日志保留必要的 hash、长度和 `[REDACTED]`，禁止把 secret 明文写入 metadata、context 或报告。

### 任务 D：scope limits

真正执行 `.scope.yaml` 中的：

```yaml
request_rate_per_second
max_requests
max_scan_ports
max_runtime_minutes
max_concurrent_commands
max_output_bytes
```

建议记录 usage：

```yaml
usage:
  requests: 0
  scan_ports: 0
  runtime_seconds: 0
  last_request_at: null
```

网络操作流程：

```text
授权检查
 → host/port 检查
 → budget reservation
 → 执行
 → usage commit
 → 记录 evidence/event
```

### Phase 2 验收标准

- 原始目录写入和 symlink 逃逸测试全部拒绝；
- timeout 后没有残留测试进程；
- secret 不出现在日志明文中；
- 超过请求、端口、运行时预算时操作被拒绝；
- redirect 仍逐跳执行 scope 检查。

## Phase 3：Agent 协作和结果合并

### 目标

使 specialist 可以安全重试、并行工作和恢复。

### 任务 A：result schema

结果至少应包含：

```json
{
  "schema_version": 2,
  "result_id": "RES-...",
  "agent": "ctf-agent-web",
  "status": "PARTIAL",
  "facts": [],
  "hypotheses": [],
  "failed_techniques": [],
  "recommended_next_action": "...",
  "source_hash": "..."
}
```

旧结果没有 `result_id/source_hash` 时，应从文件内容 hash 派生，保持兼容。

### 任务 B：merge 幂等

新增 merge history，例如：

```text
reports/merged-results.jsonl
```

重复 merge 同一 result 时返回：

```json
{
  "merged": false,
  "reason": "already_merged",
  "result_id": "..."
}
```

不得重复添加 fact、hypothesis 或 technique。相同 statement + evidence 的记录也应去重。

### 任务 C：任务租约

如需要多个 Agent 并行处理，可增加 task lease：

```yaml
active_tasks:
- id: TASK-0001
  agent: ctf-agent-web
  objective: Map HTTP routes
  status: RUNNING
  lease_until: ...
```

任务租约超时、接管和释放必须写入 event。

### Phase 3 验收标准

- 同一 result 重复 merge 不会重复写入；
- 非法 schema 被拒绝；
- evidence 引用无效时 merge 失败且不产生部分 state 修改；
- 并行 Agent 不会覆盖彼此状态；
- 旧版 result 至少能以兼容模式导入。

## Phase 4：HTTP Session 和可复现请求

### 目标

提升 Web CTF 中登录态、Cookie、CSRF 和多请求流程的可复现性。

### 任务

1. 增加 session ID 和 Cookie jar；
2. 保存 session 的请求序列；
3. 支持登录后继续请求；
4. 保存完整 request/response 证据；
5. 记录 redirect chain、body hash、headers 脱敏版本和 timing；
6. 支持基于 session 的重放；
7. 不在日志中暴露 Authorization、Cookie、token。

建议 artifact：

```text
artifacts/http/sessions/<session-id>/
├── session.json
├── cookies.json
└── requests.jsonl
```

### Phase 4 验收标准

- 登录接口设置的 Cookie 可用于后续请求；
- session 请求序列可以重放；
- 请求和响应均具备文件、hash、大小和脱敏 headers；
- 重定向跨 scope 时被拒绝；
- 现有无 session HTTP 用法不受影响。

## Phase 5：性能、索引和代码组织

### 目标

在日志量和 Agent 数量增加后保持可维护性。

### 任务

1. `logs/index.json` 或 SQLite 作为查询/缓存索引，不立即替换规范文件；
2. 将 `cli.py` 拆为命令模块；
3. 为 CommandMetadata、Evidence、AgentResult 等增加 TypedDict/dataclass；
4. 减少重复 projection 渲染；
5. 增加日志归档和清理策略；
6. 增加基准测试，关注大日志目录、并发 merge 和 context 构建。

### Phase 5 验收标准

- 10,000 条日志下 cache 查询仍在可接受时间内；
- context 构建不读取不必要的完整原始输出；
- CLI 拆分后现有命令行为不变；
- index 损坏时可以从规范日志重建。

## 6. 推荐任务拆分

为了交给多个 AI 开发者并行推进，建议使用以下互不重叠的写入范围：

### Developer A：Runtime / Runner

负责：

```text
src/ctf_agent/runtime_lock.py
src/ctf_agent/runner.py
src/ctf_agent/util.py
tests/test_runner.py
```

重点：锁、ID、进程组 timeout、输出限制。不要修改 state/evidence/report。

### Developer B：State / Evidence

负责：

```text
src/ctf_agent/state.py
src/ctf_agent/evidence.py
tests/test_state.py
```

重点：状态转换、revision、证据引用校验、projection 一致性。不要修改 runner/report。

### Developer C：Agent Merge

负责：

```text
src/ctf_agent/report.py
tests/test_reports.py
```

重点：result schema、source hash、merge 幂等和重复记录去重。不要修改 state API；如需扩展，先提出接口变更。

### Developer D：执行策略与安全测试

负责：

```text
src/ctf_agent/policy.py
src/ctf_agent/redaction.py
tests/test_security.py
```

重点：路径安全、原始目录保护、脱敏和预算策略。只提供策略接口，由主集成者接入 runner。

### Developer E：HTTP Session（第二阶段）

负责：

```text
src/ctf_agent/adapters/http.py
tests/test_http_adapter.py
```

重点：Cookie/session、完整请求响应证据。不得改变第一阶段状态写入协议。

### 主集成者

主集成者负责：

- 接收各开发者变更；
- 解决接口冲突；
- 更新 CLI、文档和迁移代码；
- 运行完整测试；
- 做安全回归；
- 只在所有验收项满足后合并。

## 7. 每个 AI 开发者的交付格式

开发者完成任务时必须返回：

```text
完成内容：
- ...

修改文件：
- ...

兼容性影响：
- ...

新增测试：
- ...

测试结果：
- 命令：...
- 结果：...

未解决问题：
- ...

风险与回滚方式：
- ...
```

要求：

- 不直接修改其他开发者的写入范围；
- 不修改生成文件 `STATE.md`、`EVIDENCE.md` 作为测试手段；
- 不用不存在的 LOG/E ID 伪造测试证据；
- 不扩大目标 scope；
- 不提交 flag；
- 不删除历史日志或原始输入。

## 8. 测试矩阵

### 单元测试

- 状态转换；
- evidence 引用；
- URL/host/port 解析；
- 路径包含关系；
- symlink 逃逸；
- redaction；
- budget reservation；
- flag 生命周期；
- result schema。

### 并发测试

- 多进程分配 LOG/E/H/F ID；
- 并发 state 更新；
- 并发 evidence append；
- 并发重复 merge；
- 并发 flag replay metadata 写入。

### 安全回归

```text
../../etc/passwd
challenge/../outside
symlink -> original/
absolute external binary
shell redirect 到 original/
timeout 后残留子进程
未声明 network tool
redirect 到未授权 host
IPv4 / IPv6 / 非默认端口
```

### 集成回归

```text
init
→ import-files
→ file/ELF recon
→ state fact/evidence
→ specialist handoff
→ merge-result
→ flag candidate
→ flag verify
→ final report
```

推荐质量门槛：

```text
核心模块覆盖率 ≥ 90%
整体覆盖率 ≥ 80%
P0/P1 安全用例全部通过
ruff 无错误
类型检查无错误
package build 成功
```

## 9. 迁移、兼容与发布策略

### Schema

- 当前 schema v1 必须可读；
- 新增字段优先使用默认值兼容读取；
- 只有确实需要时才升级 schema；
- 升级必须提供 `migrate` 或自动只读迁移预览；
- 迁移前备份 `state.yaml`；
- 不自动猜测修复历史事实。

### 发布节奏

```text
v0.2.0  当前基线
v0.2.1  Phase 0 + 并发/证据/状态修复
v0.3.0  执行安全、Agent merge、HTTP Session
v0.4.0  索引、CLI 拆分和更强 sandbox
```

每个版本都必须包含：

- 变更日志；
- 测试结果；
- 兼容性说明；
- 安全风险说明；
- 回滚方法。

## 10. 第一批必须完成的任务

如果只能先做一批，严格按以下顺序：

1. 建立 Git baseline；
2. challenge-level lock 和原子 ID 分配；
3. state revision 与合法状态转换；
4. evidence 引用严格校验；
5. original/work 路径保护；
6. process-group timeout；
7. specialist merge 幂等；
8. 并发、安全和回归测试；
9. 再开始 HTTP Session 和更多工具能力。

完成前 8 项之前，不建议扩大 Agent 并发规模或引入大量新的自动化功能。

## 11. 完成定义（Definition of Done）

本优化阶段只有在以下条件全部满足时才算完成：

- 所有 P0 任务已实现并有测试；
- 所有现有测试通过；
- 新增并发和安全测试通过；
- 规范状态没有被 projection 文件反向修改；
- 证据引用均可解析；
- `original/` 在失败和成功路径下都保持不变；
- timeout 不遗留子进程；
- 重复 merge 不产生重复 state；
- 未授权目标和超额预算无法执行；
- 生成最终报告，列出实际完成项、未完成项和残余风险。

> 本文完成的是方案落位，不代表上述代码任务已经实施。后续开发者应以本文为执行合同，并在每个阶段结束后更新实施状态或追加变更记录。

## 12. 实施状态记录（第一批，2026-09-09）

> 本文档同时是实施合同与变更记录。以下为本轮（Phase 0 + 第一批任务 1-8）的实际执行状态。

### 已完成

- **Phase 0 质量门禁**：Git 基线提交；版本号单一来源（`pyproject.toml` → `ctf_agent/_version.py` → CLI/`__version__`）；`make test/lint/typecheck/coverage/check/build`；ruff/mypy/pytest-cov；`.github/workflows/ci.yml`；CHANGELOG。
- **第一批 #1 Git baseline**：`a30bf84 baseline: ctf-agent v0.2.0, 26 tests passing`。
- **第一批 #2 锁与原子 ID（Developer A 范围）**：`src/ctf_agent/runtime_lock.py`（fcntl.flock + 进程内可重入，challenge 级 `.runtime.lock`）；`util.next_log_id` 改为读取真实 metadata ID；`run_command/run_tty` 全程持锁；并发 LOG ID 无重复。
- **第一批 #3/#4 状态 revision/合法转换 + 严格 evidence 引用（Developer B 范围）**：`state.yaml` 新增 `revision`，`save()` 带 CAS；合法转换表 + `force`（强制 reason+evidence）；`evidence.py` 解析 `LOG-*`/`E-*`/artifact（含 symlink 逃逸拒绝）。
- **第一批 #5 original/work 路径保护（Developer D 范围）**：`policy.py` 路径包含、`original/` 保护、预算投影接口；runner 拒绝外部 input file。
- **第一批 #6 process-group timeout（Developer A 范围）**：子进程独立进程组，timeout 后 SIGTERM → 宽限 → SIGKILL，日志记录终止信号；无残留子进程测试通过。
- **第一批 #7 specialist merge 幂等（Developer C 范围）**：result schema v2、`source_hash`（文件内容派生/校验）、`reports/merged-results.jsonl` 历史、重复 merge 返回 `already_merged`、先校验后写入（无部分修改）。
- **第一批 #8 并发/安全/回归测试**：`tests/test_runtime_lock.py`、`tests/test_concurrency.py`、`tests/test_security.py` 等新增 27 个测试，全套 53 通过。
- **脱敏接入**：`redaction.py`（env/headers/内联 secret → 确定性 `[REDACTED:hash]`），runner 记录 command 前先脱敏。

### 提交点（可回滚）

```text
a30bf84 baseline: ctf-agent v0.2.0, 26 tests passing
00f9ad4 runtime: challenge lock, atomic log IDs, process-group timeout, output cap
9925e89 state/evidence: revisions, legal transitions, strict evidence refs, locked mutations
77bca20 merge: schema v2, source-hash idempotency, atomic validate-before-merge
96b0c64 policy/security: path containment, original/ protection, budget interfaces, secret redaction in runner
```

### 未完成 / 残余风险（下一批）

- **scope limits 运行时强制**（request_rate_per_second / max_requests / max_scan_ports / max_runtime_minutes 全链路 usage commit）只完成了接口（`policy.ensure_within_limits`）与 runner 的 `max_output_bytes` 执行；HTTP/nmap/flag 适配器的逐请求/端口/运行时预算记账留待 Phase 2。
- **Developer E（HTTP Session，Phase 4）未开始**：Cookie jar、会话重放、响应 header 脱敏入库等仍为既有单请求行为。
- **HTTP 响应 Set-Cookie/Authorization 脱敏入库** 在 HTTP adapter 层尚未接入（先由 E/Phase 4 统一做）。
- 覆盖率从 66% 提升有限（总体仍低于 DoD 80%，`cli.py`/ghidra adapter 是主要缺口）；`fail_under` 暂为 60，需在后续批次随测试补强上调。
- 质量门槛中的“超额预算无法执行”DoD 项依赖上述 scope limits 记账落地。

## 13. 实施状态记录（第二批，2026-09-09）

> 第二批完成 Phase 2 的 scope limits 运行时强制 + Developer E（HTTP Session，Phase 4 核心）。

### 已完成

- **scope limits 运行时强制（Phase 2 Task D）**：
  - `.scope.yaml` 新增 `usage:` 账本（requests/scan_ports/runtime_seconds/concurrent_commands/last_request_at），由 `ScopeStore.commit_usage()` 在 challenge 锁内原子提交；
  - 执行点：HTTP adapter 每次请求 `requests+1`（含速率窗口检查）、nmap adapter 提交 `scan_ports`、flag 提交计 1 请求、`run_command/run_tty` 预检运行时预算并在结束后提交墙钟秒数；
  - `max_output_bytes` 由 runner 截断执行（第一批已接入）。
- **HTTP 响应头脱敏入库**：`Authorization`/`Cookie`/`Set-Cookie`/`X-Api-Key` 等写入 logs 前替换为 `[REDACTED:hash]`；URL 中的 `token=`/`password=` 等内联值同样脱敏。
- **Developer E / HTTP Session（Phase 4 核心）**：`tool http --session ID` 持久化 Cookie jar；`artifacts/http/sessions/<id>/` 下保存 `session.json`/`cookies.json`/`requests.jsonl` 与每请求 body/headers 文件（脱敏 headers、body hash/size、redirect chain、timing、请求体供重放）；`tool http-session show|replay ID` 检视与重放；重定向逐跳 scope 检查保留。
- **版本**：bump 至 0.3.0；覆盖率门禁上调至 70%（当前总体 70%）。

### 提交点

```text
<第二批提交 hash 见 git log，追加于本段之后>
```

### 未完成 / 残余风险（下一批）

- **Phase 4 增强项**：session 级显式 Authorization 头重放（脱敏后不可复原，登录流程依赖 Cookie 会话；如需要可增加"允许明文 artifact"开关）；跨 scope 重定向已有拒绝，但重放时依赖原始 URL 存于 session artifact。
- **Phase 3 Task C 任务租约**（active_tasks/lease）未实施（方案标注"如需要"）。
- **Phase 5**（logs/index.json 或 SQLite、CLI 拆分、TypedDict 重构、归档与基准）未开始。
- 覆盖率 70% 仍低于 DoD 80%（cli.py 47%、ghidra adapter、recon/elf adapter 为缺口）。
- `concurrent_commands` 限制未独立记账（challenge 锁已将单 challenge 命令串行化，跨 challenge 由各自 scope 独立约束）。

## 14. 实施状态记录（第三批，2026-09-09）

> 第三批完成 Phase 5 主体：logs 查询索引、TypedDict 记录、CLI 拆分为命令模块、覆盖率补强至 DoD 80%。

### 已完成

- **Phase 5 #1 logs/index.json**：`logindex.py` 派生索引（id + command_hash 两级映射），runner cache 查询不再全量扫描；缺失/过期/损坏自动从规范 `logs/*.json` 重建；10,000 条日志下缓存查询正确且快速（回归测试）。
- **Phase 5 #3 TypedDict**：`records.py` 提供 CommandMetadata/EvidenceRecord/AgentResult/LogIndexEntry（functional TypedDict，total=False 兼容旧记录）；`EvidenceLedger.add()` 标注 `EvidenceRecord`。
- **Phase 5 #2 CLI 拆分**：handler 按域拆入 `src/ctf_agent/commands/`（admin/challenge_cmds/scope/run/tool/state/evidence/flag/report + common）；`cli.py` 由 793 → ~300 行，保留解析器与分派；全部 88 测试通过，行为不变。
- **Phase 5 #6 基准回归**：`test_logindex.py::test_ten_thousand_logs_cache_lookup_is_fast`（10k 元数据构建 + 三次查询计时断言）。
- **覆盖率补强**：runner 错误路径、challenge 选择器/指针边界、recon/ghidra adapter、全 CLI 命令组集成测试；总体覆盖率 70% → **83%**，`fail_under` 提升至 80（DoD 达成）。

### 提交点

```text
<见 git log：batch-3 提交为 logindex / cli-split / records+coverage 等>
```

### 未完成 / 残余风险

- **Phase 5 #4 减少重复 projection 渲染**：save() 每次重渲染 STATE.md/EVIDENCE.md；大状态下的增量渲染未优化（日志量主导的场景收益有限）。
- **Phase 5 #5 日志归档/清理策略**：未实现——移动/删除 `logs/*.json` 会破坏 evidence 引用解析与重放；如需要应先引入“归档目录 + 解析器递归/索引映射”再实施。
- 核心模块覆盖率（runner 62%、challenge 66%、elf 74%）仍低于 90% 建议值；ghidra 成功路径依赖本机安装（本机已装，回归较慢 ~18s）。
- Phase 3 Task C 任务租约仍未实施（“如需要”项）。

## 15. 实施状态记录（第四批，2026-09-09）

> 第四批完成 Phase 3 Task C（任务租约）、Phase 5 #4（projection 渲染去重）、Phase 5 #5（evidence-safe 日志归档）与核心覆盖率补强。

### 已完成

- **Phase 3 Task C 任务租约**：`tasks.py` 的 `start_task/heartbeat/take_over/release_task`；`state.yaml#active_tasks`（schema v1 增量字段 `active_tasks: []`）；`lease_until` 到期前禁止 takeover；全部变更写入 events。
- **Phase 5 #4 减少重复 projection 渲染**：`util.write_if_changed()`；`STATE.md`/`EVIDENCE.md` 内容未变时跳过原子写（回归测试用 mtime 断言）。
- **Phase 5 #5 日志归档/清理策略（evidence-safe）**：`logarchive.py` 只归档未被 facts/hypotheses/techniques/flag/evidence 账本/events 引用的 `LOG-*`；移动至 `logs/archive/<YYYY-MM-DD>/` 并重建 `logs/index.json`；CLI `logs summary|archive [--dry-run]`。
- **覆盖率补强**：98 测试通过；总体 83%（`fail_under=80` 保持）；核心模块显著提升：runner 62→83%、challenge→89%、elf→79%、state 88%、flag 85%、tasks 85%、logarchive 81%。

### 提交点

```text
<见 git log：batch-4 提交为 tasks/logarchive/render-skip/0.4.1 等>
```

### 未完成 / 残余风险

- 核心模块 90% 建议值尚未全部达到（evidence 81%、logindex 85%、report 89%、scope 74%、ghidra 60% 依赖本机安装）。
- 归档策略只处理“未被引用”的日志；若未来允许归档被引用日志，需要让 evidence 解析器与 session 重放支持归档目录/索引映射。
- Phase 5 性能目标在超大日志（>10k）下已验证缓存查询；归档/索引增量维护的上限未做压力测试。

## 16. 阶段收尾（2026-09-09）

优化阶段 DoD 定性项全部达成；最终报告见 `docs/OPTIMIZATION_REPORT.md`（分批完成内容、DoD 逐项核对、提交点、未完成项与残余风险）。本阶段自基线起共 16 个可回滚提交，当前版本 `v0.4.1`。
