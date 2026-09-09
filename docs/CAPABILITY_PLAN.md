# ctf-agent 深度优化方案书（第二阶段：解题能力层）

> 文档用途：本文件是第二阶段的**实施合同**，供后续 AI 开发者与人工维护者执行，把
> `ctf-agent` 从“可审计、并发安全的运行时”升级为“**高效高能力的自研 AI 解题专家**，
> 能够熟练运用各种 Kali 工具”。
>
> 上一阶段合同见 `docs/OPTIMIZATION_PLAN.md`（运行时硬化，v0.2.0 → v0.4.1，已完成）；
> 本阶段在其成果之上推进，**不推倒重来、不破坏既有证据/安全/并发契约**。
> 本文是实施计划，不是本轮代码改动说明。开发者应按阶段领取任务、直接修改代码和测试，
> 并在完成后按 §10 的交付格式汇报。第三方定位评价见 `docs/OPENSOURCE_REVIEW.md`。

---

## 1. 背景与定位

### 1.1 时代背景（外部事实，2025–2026）

AI 作为“参赛选手”正从话题变成赛制本身（证据见 `docs/OPENSOURCE_REVIEW.md` §1）：

- **CSAW Agentic Automated CTF 2025**（NYU + CSAW'25）：要求队伍构建**完全自主**的 LLM 智能体
  解 50 道 NYU CTF Bench 题；执行期禁止 human-in-the-loop；每道解出的题必须提交**完整轨迹**
  （thoughts / actions / observations / final flag，机器可读 JSON）；代码开源供评审。
- **第九届西湖论剑（2026）**：首次引入“AI Agent 解题夺旗”赛制——只开放 API、无网页答题入口，
  题量远超人工上限；决赛现场演示 + 专家组代码审查。
- **“长城杯”网络安全大赛（2026）**：明确要求参赛队伍“运用 AI 工具、自研 AI 智能体辅助解题”。
- **腾讯云黑客松·智能渗透挑战赛（2025）**：LLM 智能体全流程自动化渗透，Agent 赛段内自主答题。
- **DARPA AIxCC（2024–2025）**：完全自主的 Cyber Reasoning System，七支决赛系统全部公开。

结论：**队伍的竞争力 = 工程化能力**（智能体架构、工具编排、状态管理、轨迹证据、成本与速率控制）。
这正是本阶段要补的能力层。

### 1.2 项目定位

`ctf-agent` 的长期定位是：

> **一个高效高能力的自研 AI 解题专家运行时**——能熟练调用 Kali 工具链完成
> web / pwn / rev / crypto / forensics / misc 六类题目的侦察、分析、利用与验证，
> 全程留下可评审、可回放、可导出为赛制轨迹的证据；
> 既能作为 Claude Code / Codex 的“技能层”被人类指挥，也能以 `AI_NATIVE` 模式无人值守跑分。

### 1.3 与上一阶段的关系

- 上一阶段（v0.4.1）交付的是**过程层**：锁、CAS 状态、证据校验、scope/预算门禁、HTTP session、
  CLI 拆分、日志索引、任务租约、归档。**这些全部保留并复用。**
- 本阶段交付的是**能力层**：工具熟练度（adapter 扩容）、求解策略（solve loop）、能力度量
  （bench）、平台对接（CTFd + 轨迹导出）、效率（并行竞速）、执行环境（沙箱）、
  学习（记忆与复盘）、发布（Demo/文档/许可）。

---

## 2. 现状能力差距基线

以下差距均来自对仓库代码、测试与文档的复核，供本阶段完成后对照。

| # | 能力项 | 现状（事实） | 差距 |
|---|---|---|---|
| G1 | 结构化 Kali 工具 | 仅 6 类 adapter：`file/strings/elf/checksec`、`http(+session)`、`web-inventory`、`nmap`、`ghidra`、`import-files`（见 `src/ctf_agent/adapters/` 与 `cli.py` tool 组） | 覆盖 ~20%；ffuf/sqlmap/john/hashcat/binwalk/foremost/exiftool/zsteg/tshark/volatility3/ROPgadget 等仍是“文档路由 + 裸 `ctfctl run`” |
| G2 | 求解循环 | 无 plan/act/observe 引擎；“下一步”靠宿主 LLM 临场发挥；无自动换招/收敛语义 | 无策略层、无 round 记录、无“不轻易放弃”的求解器行为 |
| G3 | 能力度量 | 98 个测试全部是运行时纪律测试；无任何端到端解题测试 | 无 solved rate / 单题耗时 / 成本 / 失败模式统计；无法回答“你多强” |
| G4 | 并行与竞速 | `.runtime.lock` 防冲突；`tasks.py` 只有租约库 API；`merge-result` 幂等 | 无执行器/调度/多模型 racing/成本控制 |
| G5 | 平台对接 | `flag submit` 支持 CTFd 兼容提交（受门禁约束）；无拉题 | 无 CTFd `pull`/事件同步/自动领题；无 HTB 等扩展点 |
| G6 | 赛制轨迹交付 | LOG/evidence/events 齐备，但格式是运行时内部格式 | 无 CSAW 要求的 machine-loadable trajectory 导出 |
| G7 | 沙箱 | 目录约定 + 自律；`original/` 不可变由 policy 强制 | 陌生二进制/样本无隔离执行环境（docker/bwrap） |
| G8 | 学习与记忆 | `state technique` 半结构化记录失败；无跨挑战知识 | 无“技法↔题型↔结论”知识库，无复盘沉淀，无检索注入 |
| G9 | 模型后端抽象 | 绑定 Claude Code / Codex 宿主技能 | 无 codex/claude/gemini 统一 runner 抽象（自主跑分需要） |
| G10 | 发布形态 | 文档/门禁齐全；无 Demo、无 LICENSE、无命名区分、无示例数据 | 开源前包装工作（见 `OPENSOURCE_REVIEW.md` §7） |

---

## 3. 优化目标与成功度量

### 3.1 定性目标

1. **工具熟练**：常见六类题目所需的高频 Kali 工具都有结构化 adapter，输出是 JSON 摘要而非裸 stdout。
2. **会解题**：内置求解循环（规划→侦察→假设→利用→验证→复盘），自动换招、可设迭代上限，结果落到现有证据层。
3. **可度量**：`ctfctl bench` 能在自包含合成题集上输出可复现的能力报告（solve rate / 耗时 / 成本 / 失败模式）。
4. **能参赛**：可选 CTFd 事件拉题→求解→受门禁提交；可导出 CSAW 风格轨迹 JSON。
5. **跑得快**：多挑战/多模型并行有编排与预算控制，不破坏证据幂等与 scope 门禁。
6. **敢执行**：陌生二进制可在沙箱中运行（docker/bubblewrap），缺省不改变现有行为。
7. **会成长**：跨挑战知识账本 + 复盘自动沉淀，bench 显示“重复失败下降”。
8. **可发布**：Demo、README 能力页、LICENSE/CONTRIBUTING、示例工作区齐备，可开源。

### 3.2 定量度量（KPI，Phase C 起记录并持续跟踪）

| 指标 | 定义 | 记录位置 |
|---|---|---|
| solve_rate | bench 合成题集（及可选外部集）解决比例 | `bench/results/<date>/summary.json` |
| time_per_solved | 每解一题墙钟时间（p50/p90） | 同上 |
| cost_per_solved | 每解一题模型 token/API 估算成本（有后端时可算） | 同上 |
| attempts_per_challenge | 每挑战迭代轮数（p50） | 同上 |
| failure_modes | 失败按“题型 × 技法”归类计数 | `bench/results/<date>/failure_modes.json` |
| adapter_coverage | 已实现 adapter / TOOL_ROUTING 高频工具清单 | `docs/TOOL_ROUTING.md` 对照表 |
| repeat_failure_rate | 同一题型重复使用同一失败技法的次数（知识库生效后应下降） | `workspace/knowledge.jsonl` 统计 |

> 注：数值目标（如“合成题集 solve_rate ≥ X%”）**不在本文预设**——先建立度量，跑出第一批
> 基线后再在 `bench/RESULTS.md` 中登记目标与差距，避免拍脑袋数字。发布前以“可复现的度量 +
> 持续上升曲线”为卖点，而不是一次性绝对分数。

---

## 4. 外部借鉴与取舍

| 来源 | 类型 | 可借鉴点 | 我们的取舍 |
|---|---|---|---|
| **NYU CTF Bench**（github.com/nyu-llm-ctf/nyu_ctf_bench） | 数据集 + `nyuctf` 包 | 200 test / 55 dev，6 类，docker 化，`challenge.json` 元数据 + flag；CSAW Agentic CTF 官方题源 | dev 集做**可选外部基准**（opt-in、需 docker/网络）；默认 CI 基准用**自包含合成题集**（不进依赖外部镜像） |
| **CSAW Agentic Automated CTF 规则**（csaw.io） | 赛制 | 轨迹交付物、禁止 human-in-the-loop、代码评审、污染禁止 | 轨迹导出做成一等功能（Phase D2）；知识库/题解只存“技法↔题型”，不存 flag/答案原文，防止污染与泄题 |
| **verialabs/ctf-agent**（BSidesSF 2026 冠军） | 求解器 | coordinator + solver swarm；多模型竞速；CTFd poller 自动领题；Docker 沙箱预装工具；跨 solver 消息总线 | 吸收“协调器 + 竞速 + 自动领题”理念；**不吸收**其弱审计（我们保留全量 LOG/evidence/trajectory 作为差异点）；竞速做成可关闭选项 |
| **Koshary**（ahmedreda38/Koshary） | 求解框架 | 平台无关 orchestrator；`NormalizedChallenge` + `submit_flag()` 抽象；category→model 路由；per-challenge 工作区（plan.md/agent_rounds/round_N.{prompt,out,commands,exec}）；并行 worker；first-blood 轮询 | 采用其 round 目录与“orchestrator 不直接碰平台”的分层；round 内容全部走现有 `run_command` 落 LOG，保持证据契约 |
| **Eruditus**（es3n1n） | 平台/团队工具 | CTFd/rCTF/ctfjs/Traboda 抽象接口；syscall/cipher 小工具 | 只借鉴“平台抽象接口”思路；我们不做 Discord bot |
| **D-CIPHER / nyuctf_agents、CTFJudge（NYU）** | 基线 agent + judge | 超参调优、LLM-as-judge、轻量基准 | judge 化思想用于 bench 的“半自动判定”扩展；第一阶段先做确定性 flag 比对 |
| **Cybench** | 评测框架 | 40 道专业题、多赛事、难度分层 | 其“难度分层、可复现跑分”理念用于合成题集设计（easy/medium/hard 各若干） |
| **AIxCC SoK（Usenix Sec'26）** | 论文 | 真正驱动 CRS 表现的是“agentic-first + 围绕候选缺陷的编排”；纯堆工具无效 | 支撑“先做 solve loop/策略，再铺工具”的顺序判断 |
| **HackSynth** | 渗透 agent | plan 模块 + summary 模块；命令生成/反馈解析/迭代 | “计划与总结分离”思想融入 planner 设计；但保持每步证据化 |

---

## 5. 总体架构演进

### 5.1 分层图（新增“能力层”，过程层不动）

```text
┌─ 会话层（不变）─────────────────────────────────────────────┐
│ operator 自然语言 / Claude Code / Codex 技能 / AI_NATIVE     │
└───────────────────────────────┬─────────────────────────────┘
                                │
┌─ 能力层（本阶段新增）────────────────────────────────────────┐
│ ctfctl solve   —— 求解循环/planner（rounds、换招、收敛）      │
│ ctfctl bench   —— 能力基准（合成题集 + 指标报告）            │
│ ctfctl platform—— CTFd 拉题/同步（受 scope/授权门禁）        │
│ ctfctl trajectory —— 导出赛制轨迹 JSON/Markdown             │
│ ctfctl knowledge—— 跨挑战技法知识账本 + 复盘                 │
│ runner --sandbox —— docker/bwrap 隔离执行                    │
│ adapters/*     —— 扩容：crypto/forensics/web/pwn 高频工具    │
└───────────────────────────────┬─────────────────────────────┘
                                │ 只通过现有 ctfctl 原语
┌─ 过程层（v0.4.1，不变/仅增量）──────────────────────────────┐
│ run/tool/tty → runner(锁/超时/脱敏/预算) → LOG/evidence      │
│ state(CAS/合法转换) → scope(授权/usage) → flag(生命周期)     │
│ report(handoff/幂等 merge) → tasks(租约) → logindex/archive  │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 数据与目录增量（全部 additive，schema 不破坏）

```text
workspace/
├── knowledge.jsonl                  # 跨挑战技法知识（无 flag/答案原文）
├── current.yaml                     # （已有）
bench/                               # 仓库内自包含合成题集（CI 可跑）
├── challenges/<category>/<name>/    # 与 workspace 挑战同构（.scope.yaml 指向本机）
└── RESULTS.md                       # 能力基线登记
src/ctf_agent/
├── solver.py                        # solve loop 状态机与调度
├── planner.py                       # 计划生成/round 管理（或并入 solver）
├── backends.py                      # codex/claude/gemini CLI 统一 runner 抽象
├── bench.py                         # bench 运行器与指标
├── platform.py                      # 平台抽象（CTFd 起步）+ challenge 导入
├── trajectory.py                    # LOG/evidence/rounds → 赛制轨迹
├── knowledge.py                     # 知识账本读写/注入
├── sandbox.py                       # docker/bwrap profile
└── adapters/{crypto,forensics,web,pwn}.py   # 新 adapter
```

> 原则：能力层**不得绕过**过程层。solve loop 的每一步行动仍通过
> `run_command`/`tool`/`state`/`evidence` 落盘；竞速 worker 之间通过挑战锁互斥；
> 平台提交复用 `flag.submit` 的现有门禁（`allow_flag_submission`、`no_auto_submit`、dry-run）。

### 5.3 求解循环状态机（Phase B 设计目标）

每个挑战一轮求解的内部控制状态（区别于 `state.yaml` 的挑战生命周期）：

```text
PLAN → RECON → ANALYZE → ATTEMPT → VERIFY → SOLVED
   │       │        │        │         │
   └───────┴────────┴────────┴──── REVISE（换招，带计数与原因）→ 回 ANALYZE/ATTEMPT
                                        │
                                        └ max_iterations / 无新证据 → STUCK（如实记录）
```

规则草案（以验收标准形式落入 Phase B）：
- 每轮 = 一个 `agent_round` 目录：`prompt/plan/commands/exec/observation/conclusion`，
  全部经 `run_command` 落 LOG 并回写 evidence；
- REVISE 必须携带“上一招为何失败”（引用 LOG）与“下一招假设”（引用 H-*）；
- 连续 3 轮无新证据 → 强制 STUCK 或切换专家（呼应 AGENTS.md 停止规则）；
- 任一 ATTEMPT 产出候选 flag → 进入现有 `flag candidate → verify(≥2 replay) → submit` 流程。

---

## 6. 设计原则

承接 `docs/OPTIMIZATION_PLAN.md` §4 全部原则，并新增：

1. **能力必须可度量**：任何“解题能力”改动都要能在 bench 上看到指标变化；无法度量的能力不优先做。
2. **adapter 有收益门槛**：只为“结构化解析能显著提升 agent 准确率”的工具加 adapter；能用
   通用 `run` 的保持通用。每个新 adapter 必须带真实 fixture 测试。
3. **能力层与过程层解耦**：solve loop/bench/racing 只调用既有公开 API，不直接读写
   `state.yaml`/`logs/` 内部结构（通过 ctfctl 原语或对应模块函数）。
4. **轨迹即产品**：一切新增执行路径默认可回放；bench 与 solve 的产物都能导出为
   machine-loadable trajectory。
5. **不引入污染**：知识账本、复盘、合成题集、文档示例**均不含真实赛题 flag/答案**；
   防止“训练污染”与泄题（CSAW 规则的硬约束）。
6. **默认保守、显式放开**：沙箱默认关闭（兼容）；竞速默认关闭（单 solver）；平台提交沿用
   dry-run + `--yes` + scope 授权三级门禁；任何新增网络动作都必须过 scope 检查。
7. **外部依赖可选**：docker/bubblewrap、NYU 外部基准、模型 CLI 都是“检测到才启用”，
   缺失时报清晰错误并跳过，不影响核心测试与 CI。
8. **文件所有权**：开发者只改自己的写入范围（§9），接口变更先提出来由主集成者裁决。

---

## 7. 非目标

本阶段**不要**做以下工作：

- 不重写为大型 Web UI / 服务端；
- 不用数据库替换 `state.yaml` / `events.jsonl` / `evidence.jsonl`；
- 不为 TOOL_ROUTING 中所有工具做 adapter（按 §6.2 门槛挑选）；
- 不把真实赛事题目/flag/答案带入仓库（合成题集除外，且合成题必须原创）；
- 不默认开启自动 flag 提交或自动领题；一切平台动作受 scope/约束门禁；
- 不做 Discord/IM bot；
- 不绕过既有 scope/evidence/锁机制“求快”；
- 不承诺“保证解出某题”——本阶段交付的是能力系统与度量，不是特定题解；
- 不在本阶段处理“更强的 OS 级隔离（seccomp 内核策略）”，只做容器/命名空间级沙箱起步。

---

## 8. 分阶段实施计划

> 阶段可分批执行（见 §13 执行顺序与第一批）。每个 Phase 标注目标 / 任务 / 验收标准 / 文件范围。
> 验收标准即“可测的完成定义”；全部新增行为必须有回归测试。

### Phase A：工具适配器扩容（能力层的地基）

#### 目标
把“高频、结构化解析收益大”的 Kali 工具变成 JSON 摘要 adapter，降低 LLM 使用成本与出错率。

#### 任务

**A1 密码类（`adapters/crypto.py` + `commands/tool_cmd.py` 扩展）**
- `hashid`/hash 识别：输入 hash/文件 → 输出候选算法列表 + 置信度；
- `john`/`hashcat`：仅**本地文件**破解（不接远程）；自动按识别算法装配参数；
  输出破解结果/状态/耗时；默认 `--show` 只读，`--force` 才跑实际破解；
- `openssl`/`gpg`/`zip2john` 等：由通用 run 覆盖，不做 adapter（收益不足）。

**A2 取证类（`adapters/forensics.py`）**
- `exiftool -json`：结构化元数据；
- `binwalk`：entropy 与签名列表（默认不 `-e` 提取，提取到 `work/extracted/` 需显式）；
- `7z l` / `unzip -l`：归档清单；解包到 `work/`（受 policy 约束）；
- `strings`/`xxd`/`base64` 等由 file-recon/通用 run 覆盖；
- `zsteg`/`steghide info`：隐写探测（只读）；（steghide extract 需密码，显式参数才执行）
- `tshark -T json`（PCAP 摘要：会话、DNS、HTTP 对象清单）；对象导出到 `work/`。

**A3 Web 辅助（`adapters/web.py`）**
- `ffuf`：目录/参数模糊测试 adapter——要求先有明确原因与目标词表；默认低速率；
  输出命中表 JSON；**计入 usage ledger 的 requests**；
- `sqlmap`：**只读/审计模式**（`--batch --smart --crawl=0` 且显式 `--level/--risk` 上限、
  禁止 `--os-shell` 等破坏性开关），仅在存在手工证据（引用 H-*）后由专家显式调用；
- 说明：浏览器自动化（Playwright）保持“文档路由 + 技能”，不做 CLI adapter（交互性强，收益不稳）。

**A4 Pwn/Rev 辅助**
- `checksec`（已在 elf adapter 中，保持）；
- `ROPgadget --binary ... --json`：ROP gadget 清单（限制输出行数）；
- `readelf`/`objdump` 结构化节表/导入表摘要（可并入 elf adapter 的扩展输出）；
- `angr`/`z3`：作为 Python 模板进 `templates/solve/`，不做 adapter。

#### Phase A 验收标准
- 每个新 adapter：真实 fixture（非伪造 LOG）下，输出为稳定 JSON schema（含
  `schema_version/tool/command/summary/logs/artifacts`），错误与工具缺失有清晰报错；
- 网络型工具（ffuf/sqlmap）逐次 commit usage 且 scope 校验失败即拒绝；
- 破坏性操作默认关闭，需显式参数 + 文档；
- TOOL_ROUTING.md 增加“adapter 覆盖对照表”并勾选完成项；
- `make check` 全绿，覆盖率不降（新增 fixture 测试补齐）。

### Phase B：求解循环与规划器

#### 目标
给系统装上“解题大脑”：可编程的 plan→act→observe 循环、自动换招、round 记录、停止规则。

#### 任务
- **B1 模型后端抽象（`backends.py`）**：统一 `run_model(prompt, model, effort, timeout)`
  接口；首批支持 `codex` / `claude` / `gemini` CLI（PATH 检测，缺失即报错跳过）；
  所有往返记入 round 目录（prompt 原文、输出原文），为轨迹导出供料。
- **B2 求解循环（`solver.py`）**：按 §5.3 状态机实现单挑战循环；迭代上限、无新证据停止、
  REVISE 原因强制引用；调用现有 `state/evidence/flag` API 落盘；产出 `agent_rounds/`。
- **B3 规划器（`planner.py` 或并入 solver）**：开始前生成 `plan.md`（目标、假设、工具路线、
  预算估计）；每轮后更新“已排除路线”（引 evidence），防止重复。
- **B4 技能注入（context/knowledge 接入点）**：把“题型→推荐工具/模板/常见坑”注入每轮
  system prompt（来自 Phase G 知识库，未建时用内置静态 playbook）；
  静态 playbook 来源 = 现有 `agent-specs/*.md` + `docs/TOOL_ROUTING.md` 的结构化版本。
- **B5 CLI**：`ctfctl solve [--event EVENT] [--challenge NAME] [--backend codex|claude|gemini]
  [--max-iterations N] [--no-submit] [--rounds-dir ...]`；默认 dry-run 不提交。

#### Phase B 验收标准
- 端到端集成测试：对一个合成题，solver 至少完成 PLAN→RECON→…→STUCK 或 SOLVED 全流程，
  且**每一步都能从 LOG/evidence 反查**；
- REVISE 不带 evidence 引用被拒绝；连续无新证据强制停止；
- 不同 backend 缺失时错误清晰且不半途写坏状态；
- 合成题集（Phase C）上能稳定产出 round 目录 + 指标输入。

### Phase C：能力基准（bench）

#### 目标
用可复现的方式度量“专家能力”，为所有后续改动提供对照。

#### 任务
- **C1 自包含合成题集（`bench/challenges/`）**：原创、无外部依赖，覆盖 6 类各 ≥2 题、
  难度 easy/medium 起步；每题与 workspace 挑战同构（可 `init` + 自带 `original/` fixture +
  答案校验脚本），**不进真实题/flag**；CI 可离线跑。
- **C2 harness（`bench.py` + `ctfctl bench`）**：遍历题集 → 逐题跑 solver（Phase B）→
  收集 solve/time/cost/attempts/失败技法；输出
  `bench/results/<date>/summary.json` + `failure_modes.json` + 可读 `REPORT.md`；
  失败时可复跑单题（`ctfctl bench --only crypto/rsa-easy`）。
- **C3 指标与基线登记**：`bench/RESULTS.md` 记录首次基线 + 每次显著变化的对比表；
  新增“adapter_coverage”“repeat_failure_rate”统计入口（对接 knowledge，未建先置空）。
- **C4 可选外部基准接入点（延后，默认关闭）**：定义 `BenchRunner` 抽象；NYU dev 子集
  （`nyuctf` + docker）作为 opt-in provider，文档说明网络/镜像/许可注意事项；不在 CI 跑。

#### Phase C 验收标准
- 全新 clone + `make check` 后 `ctfctl bench`（合成集）可离线、确定性复现；
- 指标文件 schema 稳定（版本化），单题失败可定位到 LOG；
- 两次跑同一合成题，结果一致（确定性；涉及 LLM 的部分允许记录 seed/backend 版本差异）；
- RESULTS.md 有首次基线条目。

### Phase D：平台桥与赛制轨迹

#### 目标
打通“领题—求解—交付”闭环：可选接入 CTFd 事件，导出 CSAW 风格轨迹。

#### 任务
- **D1 平台抽象（`platform.py` + `ctfctl platform`）**：`BasePlatform` + `NormalizedChallenge`
  + `submit_flag()`（Koshary 式分层）；首批 CTFd（cookie 或 token，遵循现有脱敏：凭据不落盘，
  只存 env/`0600` 配置）；命令：
  `ctfctl platform ctfd list|pull|status|scoreboard`、`--sync-only`（只建工作区不求解）、
  `--no-submit`；
  拉题 = 下载附件（经 ingest 导入 original/，记录来源与 hash）+ 写 `.scope.yaml`（目标来自
  平台，**须 operator 确认授权范围**后方可添加）；
- **D2 轨迹导出（`trajectory.py` + `ctfctl trajectory export`）**：把单挑战
  LOG/evidence/rounds/flag 汇总为机器可读 JSON：`{challenge, trajectory:[{round, thought,
  actions:[{command,log,stdout_ref,observation}], evidence_refs}], final_flag, verdict}`；
  同时输出人类可读 Markdown；导出内容不含凭据（复用 redaction）；
- **D3 提交门禁确认**：submit 路径复用 `flag.submit`，新增“平台 pull 的挑战默认
  `no_auto_submit`”，operator 显式移除后才允许自动提交。

#### Phase D 验收标准
- 用本地 mock CTFd（测试 fixture，非真实平台）完成 pull→init→(solve)→submit 全链路集成测试；
- 轨迹 JSON 通过 schema 校验，字段与 CSAW 规则对齐（thoughts/actions/observations/final flag）；
- 凭据不出现在任何 LOG/artifact/轨迹中（redaction 回归测试）；
- 未确认授权的平台目标无法进入 scope（拒绝写 `.scope.yaml` 外部目标）。

### Phase E：并行竞速与编排

#### 目标
多挑战/多模型并行，提升吞吐；不破坏证据幂等、预算与 scope。

#### 任务
- **E1 并发执行器（`solver.py` 扩展）**：`ctfctl solve --parallel N --only unsolved`；
  按挑战分配 worker（多进程），每个 worker 持有自身挑战锁（复用现有锁，**锁顺序固定，
  禁止跨挑战嵌套锁**防死锁）；结果经 `merge-result` 幂等汇总。
- **E2 多模型 racing（可关闭）**：`--race "codex,claude,gemini"`：同一挑战由多个 backend
  各自独立 round 目录求解，首个产出“REPRODUCED 级 flag 证据”者胜出；其余 worker 终止并
  归档其 rounds（也是轨迹素材）；仲裁规则写入文档与测试。
- **E3 成本/预算控制**：worker 共享一份“运行预算”（新字段 additive 到 workspace 级配置）：
  最大并行数、总轮数、单挑战最大轮数、后端超时；超额即优雅停止该 worker 并记录 budget_error；
  usage ledger 继续按挑战记账。
- **E4 提示词/技能注入并行安全**：各 worker 的 knowledge 读取只读共享，写入仅 master/赛后。

#### Phase E 验收标准
- 并发 4 worker × 2 backend 的集成测试：无 ID 冲突、无 state 损坏、merge 无重复
  （复用既有并发回归模式）；
- 预算超额时 worker 停止且错误可解释；
- racing 关闭时行为与 Phase B 完全一致（默认路径零回归）。

### Phase F：沙箱执行

#### 目标
陌生二进制/样本的隔离执行；默认不改变现有行为。

#### 任务
- **F1 sandbox profile（`sandbox.py`）**：`auto|none|docker|bwrap` 探测与 profile；
  docker：只读挂载 `original/`，可写挂载 `work/`，默认无网络（`--network` 需 scope 校验），
  资源上限（内存/cpu/pids）；bwrap：同语义，无 docker 时的备选；
- **F2 runner 集成**：`ctfctl run --sandbox docker -- python3 work/x.py`；
  命令哈希身份加入 sandbox 类型，避免缓存串味；沙箱内 stdout/stderr 仍全量记录；
- **F3 策略**：`original/` 内二进制默认“只读 + 沙箱提示”；`doctor` 报告 docker/bwrap 可用性；
  未知格式（非 ELF/脚本/文档）运行前给 warning 并建议 sandbox。

#### Phase F 验收标准
- 有 docker 时：恶意/崩溃样本在沙箱内运行不污染宿主与 `original/`（集成测试，可跳过标记）；
- 无 docker/bwrap 时：命令给出清晰 MISSING 提示且不静默降级为宿主执行（除非 `--sandbox none` 显式）；
- 缓存身份包含 sandbox 类型（回归测试）。

### Phase G：记忆与复盘

#### 目标
让专家“越用越强”：跨挑战知识账本 + 自动复盘 + 检索注入。

#### 任务
- **G1 知识账本（`knowledge.py` + `workspace/knowledge.jsonl`）**：条目 =
  `{id, category, technique, trigger, conclusion, outcome, evidence_refs, created_at}`；
  **禁止存 flag/答案原文**；写入需 evidence；按挑战 solved/失败自动建议条目，人工/operator
  确认后入库；
- **G2 复盘生成**：solve 结束后 `ctfctl knowledge review --challenge NAME` 产出
  `reports/review-<name>.md`（时间线、关键转折、可复用技法、浪费点）；
- **G3 检索注入**：planner 在 PLAN/REVISE 时检索同 category + trigger 命中的知识条目，
  注入本轮 context（限制条数与 token）；bench 的 repeat_failure_rate 用来验证效果。

#### Phase G 验收标准
- 知识条目 schema 与注入格式有测试；不含 flag 的静态检查（测试断言序列化文本不含
  `flag{` 等模式）；
- 合成题集上重复失败率可统计，并在至少一个 fixture 场景证明“命中知识后不再重复同一失败技法”。

### Phase H：开源发布准备

#### 目标
达到可开源形态：能力可见、上手快速、法律与协作文件齐全、示例干净。

#### 任务
- **H1 Demo**：一个端到端示例（合成题 web 类 + crypto 类）从 `init` 到
  `bench`/`trajectory export` 的脚本化演示（`examples/demo.sh` + asciinema 录制建议）；
- **H2 文档**：README 增加“能力”一节（bench 结果引用、adapter 对照表、轨迹示例、架构图）；
  新增 `docs/SOLVER_ARCHITECTURE.md`（能力层设计，含本方案 §5 图）；更新 CHANGELOG；
- **H3 法律与协作**：LICENSE（作者选定，建议 MIT/Apache-2.0）、CONTRIBUTING.md、
  SECURITY.md（负责任披露）；
- **H4 命名与定位**：评估与 verialabs/ctf-agent 的命名撞车，README 首屏一句话区分定位；
- **H5 卫生**：`gitleaks`/`trufflehog` 扫历史；确认无真实挑战数据/凭据入库；
  `core.*`/`.venv` 等已 ignore 复核。

#### Phase H 验收标准
- 新 clone 按 README “Quick start + Demo”可在 15 分钟内跑通合成题示例；
- LICENSE/CONTRIBUTING/SECURITY 存在；敏感扫描 0 命中；
- README 含能力指标与定位声明。

---

## 9. 推荐任务拆分（互不重叠写入范围）

> 用于并行 AI 开发者。每位只改自己的范围；接口变更先提出，由主集成者裁决。
> 冲突时优先保证过程层（`state/runner/scope/evidence/report`）不被破坏。

| Developer | 写入范围（新增/修改） | 重点 | 禁止触碰 |
|---|---|---|---|
| **A · Adapters** | `adapters/crypto.py`、`adapters/forensics.py`、`tests/test_adapters_crypto.py`、`tests/test_adapters_forensics.py`、TOOL_ROUTING 对照表对应行 | 密码/取证 adapter；只读默认 | 其它 adapter、runner、scope |
| **B · Web Adapters** | `adapters/web.py`、`tests/test_adapters_web.py`、scope usage 扩展（如需要先提接口） | ffuf/sqlmap 只读封装 + 预算 | 其它 adapter |
| **C · Solve Loop** | `solver.py`、`planner.py`、`commands/solve_cmd.py`、`tests/test_solver.py` | 状态机、round、停止规则、CLI | 不直接写 state/logs 内部；经 API |
| **D · Backends + Bench** | `backends.py`、`bench.py`、`bench/challenges/**`（合成题）、`commands/bench_cmd.py`、`tests/test_bench.py`、`bench/RESULTS.md` | 模型 runner 抽象；合成题集与指标 | 不改 solver 内部状态机（只调用其公开入口） |
| **E · Platform + Trajectory** | `platform.py`、`trajectory.py`、`commands/platform_cmd.py`、`commands/trajectory_cmd.py`、`tests/test_platform.py`、`tests/test_trajectory.py` | CTFd mock 全链路；CSAW 轨迹导出 | 不改 flag.submit 门禁语义（可扩展参数） |
| **F · Racing/Sandbox** | `solver.py`（并行部分，先与 C 协调）、`sandbox.py`、runner `--sandbox`（经主集成者接入）、`tests/test_sandbox.py`、`tests/test_racing.py` | 并发执行器、racing、预算、沙箱 | 不与 C 同时改 solver 核心状态机（分批） |
| **G · Knowledge** | `knowledge.py`、`commands/knowledge_cmd.py`、`tests/test_knowledge.py`、复盘生成 | 知识账本/注入/复盘 | 不含 flag；不改 planner 主循环结构（只加注入点） |
| **H · Docs/Demo/Release** | README、`docs/SOLVER_ARCHITECTURE.md`、`examples/`、LICENSE/CONTRIBUTING/SECURITY、CHANGELOG | 发布形态 | 不改 src 行为 |

**主集成者**：裁决接口变更；保证能力层只经公开 API 触达过程层；跑 `make check` +
bench；维护 `docs/CAPABILITY_PLAN.md` 状态记录（§16）；只在验收全过后合并并打提交点。

---

## 10. 每个 AI 开发者的交付格式

沿用 `docs/OPTIMIZATION_PLAN.md` §7：

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

附加要求（本阶段专属）：

- 不修改生成文件 `STATE.md`/`EVIDENCE.md` 作为测试手段；
- 不用不存在的 LOG/E ID 伪造证据；fixture 日志走真实 `run_command` 或受控 fixture 构建；
- 不把真实赛题/flag/答案写入仓库；合成题必须原创；
- 不扩大 scope/授权；不提交 flag（除非走完整门禁且 operator 批准）；
- 网络/外部依赖（docker、模型 CLI、NYU 集）缺失时必须跳过并有清晰报错，不许静默假成功。

---

## 11. 测试矩阵

### 单元测试
- 新 adapter：工具缺失/成功/失败/超时/输出上限/schema 稳定；
- solver：状态转移合法、REVISE 需证据、无新证据停止、迭代上限；
- knowledge：条目 schema、注入排序与数量限制、**不含 flag 断言**；
- trajectory：字段对齐、redaction 后无凭据、schema 版本；
- sandbox profile 探测与参数构造（mock docker/bwrap）。

### 并发测试
- 并行 worker 写不同挑战：无 ID/state 冲突；
- 同挑战多 backend racing：round 目录隔离、仲裁唯一、merge 幂等；
- 预算共享：并行超预算优雅停止；
- 沙箱与缓存：sandbox 类型进入命令哈希身份。

### 安全回归（沿用并扩展）
```text
../../etc/passwd
symlink -> original/
未授权网络工具 / 重定向到未授权 host
ffuf/sqlmap 越界（未 scope 目标、超速率）
沙箱内写 original/（拒绝）
知识库写入真实 flag 模式（拒绝）
平台 pull 未确认授权目标（拒绝写 scope）
```

### 集成回归（既有路径，保持全绿）
```text
init → import-files → file/ELF recon → state fact/evidence
→ handoff → merge-result → flag candidate → flag verify → final report
```

### 新增端到端
```text
ctfctl bench（合成集，离线、确定性）
ctfctl solve（合成题，dry-run）→ 轨迹反查
mock CTFd：pull → init → solve(dry-run) → submit(门禁)
```

质量门槛（在 `make check` 基础上新增 bench 门槛，纳入 Makefile）：

```text
make check            # 既有：tests/lint/typecheck/coverage(≥80)
make bench            # 合成题集全绿（每题可 SOLVED 或如实 STUCK，无崩溃/挂死）
adapter 新增文件覆盖率 ≥ 80%
核心过程层覆盖率不因本阶段下降
```

---

## 12. 迁移、兼容与发布策略

### Schema / 目录
- 过程层 schema 保持 additive；新增：workspace 级 `budget`（若 E3 需要）、
  `workspace/knowledge.jsonl`、`bench/`、`agent_rounds/` 均不破坏旧读取；
- 旧挑战目录无需迁移即可继续使用；新字段缺省兼容。

### 版本与提交节奏（建议）
```text
v0.5.0   Phase A + B 骨架 + C 最小基准（“能度量地解题”）
v0.6.0   Phase D 平台 + 轨迹（“能参赛交付”）
v0.7.0   Phase E + F 并行竞速 + 沙箱（“跑得快、敢执行”）
v1.0.0   Phase G + H 记忆复盘 + 开源发布（“越用越强、可发布”）
```
每个提交 = 可回滚点；每个版本 = changelog + bench 结果 + 兼容性说明 + 风险 + 回滚方法。

---

## 13. 完成定义（Definition of Done）

本阶段全部完成的条件：

- Phase A–H 全部验收标准满足且各有回归测试；
- `make check` 与 `make bench` 全绿；过程层覆盖率不下降；
- `ctfctl bench` 可复现地输出能力报告，`bench/RESULTS.md` 有基线与至少一次对比记录；
- 合成题端到端 demo 可 15 分钟内跑通（新 clone）；
- trajectory 导出通过 schema 校验且无凭据泄漏；
- mock CTFd 全链路测试通过，真实提交仍受 dry-run/`--yes`/scope/`no_auto_submit` 门禁；
- 知识账本无真实 flag/答案，repeat_failure_rate 可统计；
- 发布文件（LICENSE/CONTRIBUTING/SECURITY/README 能力节/示例）齐备，敏感扫描 0 命中；
- 生成最终报告：实际完成项、bench 指标、未完成项、残余风险、回滚点列表。

---

## 14. 风险与未决问题（如实登记，随阶段更新）

| # | 风险/问题 | 影响 | 缓解 |
|---|---|---|---|
| R1 | 解题能力受宿主 LLM 质量限制 | 绝对 solve rate 不可承诺 | 以“可度量 + 持续上升”为口径；能力层（工具/循环/记忆）价值独立于模型 |
| R2 | 模型 API/CLI 成本与抖动 | bench 成本不稳定 | 默认合成题集小规模；成本入指标；racing 可关 |
| R3 | docker/bwrap 在部分环境缺失 | 沙箱不可用 | 检测即跳过 + 清晰报错；CI 用可跳过标记 |
| R4 | NYU 等外部基准：镜像大、网络/许可 | 不作为默认 | opt-in provider，文档说明；合成集为默认 |
| R5 | 并行 racing 引入状态竞争 | 数据损坏 | 复用挑战锁；锁顺序固定；racing 默认关 |
| R6 | sqlmap/ffuf 滥用风险 | 越界请求 | 仅 scope 内 + usage 记账 + 只读模式 + 需手工证据 |
| R7 | 知识库污染（写入 flag/答案） | 泄题/污染 | 写入 schema 白名单 + 静态检测 + 人工确认 |
| R8 | 能力层改动波及过程层 | 回归 | 能力层只经公开 API；每批跑既有全套测试 |
| R9 | 工具版本差异导致 adapter 输出不稳 | 解析脆弱 | fixture 固定版本输出样例；解析容错降级为原始输出 |
| R10 | 命名撞车（verialabs/ctf-agent） | 开源辨识度 | Phase H4 评估改名/定位区分 |

---

## 15. 执行顺序与第一批必须完成的任务

依赖关系：**A/C 先行**（工具 + 循环）→ **B 后端**可与 C 并行 → **C 基准**需要 B/C 的
最小闭环 → D 需要 B；E 需要 B/C + A；F 独立但需 runner 接入；G 需要 C（度量）+ B（注入点）；
H 收尾。

若只能先做一批（推荐 Batch 1，目标 v0.5.0），严格按以下顺序：

1. Phase A1/A2：crypto + forensics adapter（离线、无网络依赖，最易验证）；
2. Phase B 骨架：`backends.py`（先 codex）+ `solver.py` 最小循环（PLAN→…→STUCK/VERIFY，
   先不接 LLM 也能用“脚本模式”跑通状态机测试）；
3. Phase C1/C2：合成题集 ≥6 道（每类 1 道 easy）+ `ctfctl bench` 指标输出；
4. 以“合成题集端到端（dry-run）”作为 Batch 1 的集成验收；
5. 更新 CHANGELOG、`bench/RESULTS.md` 基线、本文件 §16 状态记录，打提交点 `v0.5.0`。

Batch 1 完成前不启动 E（racing）、F（沙箱）、D 的自动领题，避免并行复杂度干扰基线建立。

---

## 16. 实施状态记录（预留）

> 每批完成后在此追加：完成内容 / 提交点（可回滚）/ 未完成与残余风险 / bench 指标变化。
> 本文件是活文档；阶段全部完成后，最终报告另存 `docs/CAPABILITY_REPORT.md`。

### 批次 1a（Phase A1/A2 工具适配器，2026-09-09）

> 完成 Phase A1（密码类）与 A2（取证类）的离线 adapter 扩容；Phase A3/A4、B/C 后续批次。

- 新增 `ctf_agent/adapters/crypto.py`：`tool hashid`（本地形状启发 + hashid 富化，按形状偏好选
  suggested）、`tool crack`（john/hashcat 本地破解，强制 wordlist；argv 哈希字符集校验防注入；
  pot/hash 文件落 `work/hashes/`）。
- 新增 `ctf_agent/adapters/forensics.py`：`tool exif`、`tool binwalk`（`--extract` 仅落
  `work/extracted/`）、`tool archive`（7z `-slt`）、`tool zsteg`（工具崩溃 → `status=error`
  而非硬失败）、`tool pcap`（capinfos + tshark 协议层级）。
- CLI/doctor/TOOL_ROUTING 覆盖表已更新；21 个 adapter 测试新增（hashcat 端到端以
  `CTF_TEST_HASHCAT=1` 显式开启，默认跳过因其 OpenCL 启动约 20s）。
- 提交点：`<见 git log：Phase A1/A2 提交>`。
- 残余风险：hashcat 成功路径默认不在 `make check` 内；binwalk 提取耗时用例约 3–5s；
  zsteg 对病态图片仍可能产生非零退出（已优雅上报）；A3/A4（ffuf/sqlmap/ROPgadget 等）未开始。

### 批次 1b（Phase A3/A4 工具适配器，2026-09-09）

> 完成 Phase A3（web：ffuf/sqlmap）与 A4（pwn/rev：ROPgadget/readelf）适配器。Batch 1a 记录见上。

- 新增 `ctf_agent/adapters/web.py`：`tool ffuf`（scope 校验 + FUZZ 位置必需 + wordlist 强制 +
  **执行前**按词表行数预算 requests，超预算直接拒绝）；`tool sqlmap`（`build_sqlmap_argv` 纯函数
  固化只读不变量：level≤3/risk≤2、无任何破坏性开关；执行需可解析 `--evidence`，除非 operator
  显式 `--force`）。
- 新增 `ctf_agent/adapters/pwn.py`：`tool rop`（ROPgadget 结构化 gadget，`--only/--depth/
  --max-gadgets`）、`tool imports`（`readelf --dyn-syms` UND 符号，含版本解析）。
- 测试：web/pwn 模块 + CLI 集成共 16 个新用例（sqlmap argv 不变量、ffuf 校验/scope 拒绝/本地
  HTTP 端到端、ROP/imports 解析、evidence 门禁）。
- 提交点：`<见 git log：Phase A3/A4 提交>`。
- 残余风险：sqlmap 真实执行路径未纳入默认测试（需注入靶标，成本高；由 argv 不变量 + evidence
  门禁 + stub 摘要测试守护，真实靶场验证留待 Phase B/C 端到端）；ffuf 请求数为执行前估算
  （= 词表行数 × FUZZ 位），与真实发送数可能略有出入，属诚实上界。
- 至此 Phase A 全部完成（A1–A4）。

### 批次 1c（Phase C 基准 v1，2026-09-09）

> 完成 C1（合成题集首版）+ C2（harness + 指标输出）+ C3（基线登记）。C4（外部基准）按计划延后。

- `src/ctf_agent/bench.py` + `ctfctl bench`：发现 `challenge.json` → 每题隔离 AI_NATIVE 工作区
  → 经 ingest 导入 `original/*` → web 题自动起本地靶标服务器 → 超时执行确定性 `solve.py` driver
  （`FLAG=` 行上报）→ 产出 `summary.json` / `failure_modes.json` / `REPORT.md`；缺工具记
  `SKIPPED` 而非 `FAILED`（CI 友好）；`actions` 统计每题真实落盘命令数。
- 合成题集 v1（`bench/challenges/`，全部原创、离线、无真实赛题材料）：6 题 easy 每类一题 —
  crypto/hash-crack（john+hashid）、forensics/hidden-zip（binwalk 提取）、web/http-header
  （本地靶标 + `tool http`）、pwn/argv-gate（strings 找口令 + run 执行）、rev/xor-file、
  misc/rot-multi。
- `make bench` 目标；`bench/RESULTS.md` 基线 1：6/6 SOLVED，墙钟 ≈ 6 s（含 john/binwalk）。
- 提交点：`<见 git log：Phase C v1 提交>`。
- 残余/待办：C1 未达“每类 ≥2 题、含 medium”目标（suite v2 计划，见 RESULTS.md Growth rules）；
  solve.py 驱动目前是“脚本模式”，Phase B 的 LLM solver 接入后 bench 增加 `--driver solver` 选项；
  `actions` 目前只统计命令数，token/成本统计待 Phase B 后端接入。

### 批次 1d（Phase B 求解循环骨架，2026-09-09）

> 完成 B1（后端抽象）、B2（求解循环）、B3 基础（round 记录/停止规则）、B4 静态 playbook 注入。

- `src/ctf_agent/backends.py`：`CliBackend`（codex `exec -o` / claude `-p` / gemini `-p`）+
  可用性探测 + `auto` 优先级；缺失 CLI 报清晰错误，不静默。
- `src/ctf_agent/solver.py` + `ctfctl solve`：round 循环 = 组合 prompt（state digest + 文件清单 +
  分类 playbook + 历史轮次）→ 策略产出 JSON 动作（`analysis/commands/flag_candidate/conclusion`）
  → 引擎校验并执行 `ctfctl run|tool`（每条动作留痕、可解析 LOG id）→ `agent_rounds/round-NN/`
  落盘 + events 记录；flag 在输出中或候选中出现即记入 flag.candidate 并 SOLVED；停止条件：
  conclusion=stuck / 连续两轮无新证据 / max_rounds。`ScriptedPolicy`（测试确定性）+ `BackendPolicy`
  （JSON 严格解析，容忍一次坏回复）。
- 测试：17 个（argv 构造、可用性错误、JSON 提取、输出检测到 flag→SOLVED、candidate→SOLVED、
  idle/conclusion/两次坏回复→STUCK、事件与 flag 记录）。codex/claude CLI 本机已装；未做真实模型
  调用（避免无谓成本），真实跑分待 operator 显式执行。
- 提交点：`<见 git log：Phase B skeleton 提交>`。
- 残余/待办：网络类动作仍走既有 scope 门禁但 v1 动作集仅允许 `run|tool`；求解成功不自动推进
  state 生命周期（SOLVED 由既有 flag verify/submit 流程接管）；PLAN 步骤为“每轮 prompt 内联”
  而非独立 plan.md 文件；bench 的 `--driver solver` 与 suite v2（每类 ≥2、含 medium）未开始。

### 批次 1e（规划中）

- bench 接入 solver driver（`--driver solver`，可跑真实 LLM 对照基线）→ suite v2 扩容 →
  Phase D/E（平台桥+轨迹导出、并行竞速）。







- Phase A3/A4（web/pwn 辅助 adapter）→ Phase B 求解循环骨架 → Phase C 合成题集 + `ctfctl bench`。

