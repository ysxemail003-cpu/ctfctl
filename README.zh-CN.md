[**English**](README.md) | [**简体中文**](README.zh-CN.md)

# ctfctl

**面向 Kali Linux 的“证据优先”智能体 CTF 运行时** —— 用来构建、运行并审计属于你自己的自研 AI 解题专家。

> 仅可用于你被明确授权测试的系统与挑战；赛事规则始终优先于本仓库。

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Python >= 3.11](https://img.shields.io/badge/python-3.11+-3776AB.svg)
![Target: Kali Linux](https://img.shields.io/badge/target-Kali%20Linux-557C94.svg)

---

## 这是什么

`ctfctl` 是一个把自然语言转化为**可审计 CTF 解题工作流**的运行时。它不是一次性“解题 Prompt 合集”，
而是给个人或战队提供一整套体系，用来培养**自己的 AI 解题专家**：结构化的 Kali 工具调用、
自主求解循环、可复现的能力基准、CTF 平台桥接，以及 CSAW 风格的轨迹导出——并且每一步都被记录、
做范围校验、与证据绑定。

它**不是**：

- 授权绕过工具——授权、范围与赛事规则由代码强制；
- 单一写死的“解题器”——它是一个供你构建智能体的运行时；
- 黑盒——每一条结论都能回溯到真实的 `LOG-*` / `E-*` 证据。

## 核心亮点

- **证据是被强制执行的，而非一句建议**：事实、假设与状态转换必须引用真实日志或产物，
  无法解析的引用会被拒绝写入。
- **状态跨上下文存活**：`state.yaml` 是唯一权威；上下文压缩、会话中断、切换模型都不会丢失进度
  （`ctfctl context`、`next_action`）。
- **安全写在代码里，而非提示词里**：目标范围、逐跳重定向校验、凭据脱敏、进程组超时、
  预算账本、flag 默认 dry-run 提交。
- **它真的能解题**：覆盖 crypto / forensics / web / pwn / rev 的结构化工具适配器、
  自主求解循环（`ctfctl solve`）、并行竞速（`ctfctl race`），以及用 12 道离线合成题
  度量进步的基准（`ctfctl bench`）。
- **为参赛而生**：CTFd `pull`、默认 `no_auto_submit`、与 agentic-CTF 提交要求对齐的轨迹导出。

## 能力地图

| 能力 | 状态 | 文档 |
|---|---|---|
| 过程层：锁 / 状态 / 证据 / 范围 / flag / 日志 | 已交付（v0.4.1） | `docs/ARCHITECTURE.md` |
| 结构化 Kali 工具适配器（crypto / forensics / web / pwn-rev） | 已交付 | `docs/TOOL_ROUTING.md` |
| 求解循环 + 模型后端（codex / claude / gemini） | 已交付 | `docs/SOLVER_ARCHITECTURE.md` |
| 基准：12 道原创题（6 easy + 6 medium） | 已交付，脚本基线 12/12 | `bench/RESULTS.md` |
| CTFd 平台桥 + 轨迹导出 | 已交付 | `docs/SOLVER_ARCHITECTURE.md` |
| 并行竞速 + 线程/进程安全的运行时锁 | 已交付 | `docs/SOLVER_ARCHITECTURE.md` |
| 知识账本 + 赛后复盘 | 已交付 | `docs/SOLVER_ARCHITECTURE.md` |
| 更难 suite v3 | 待定/冻结 | `docs/CAPABILITY_PLAN.md` |

## 快速开始

```bash
cd ~/ctfctl
./tools/ctfctl doctor                     # 环境与工具可用性检查

./tools/ctfctl init \
  --event 2026-demo --challenge web-login --category web \
  --mode AI_NATIVE --target challenge.example.ctf --port 80 \
  --confirm-authorization

export CTF_CHALLENGE_DIR="$PWD/workspace/contests/2026-demo/web-login"
./tools/ctfctl state show
./tools/ctfctl tool web-inventory http://challenge.example.ctf/
```

常用命令：

```bash
./tools/ctfctl tool hashid <hash>                    # 识别哈希类型
./tools/ctfctl tool crack <hash> --wordlist words.txt --tool john
./tools/ctfctl tool exif|binwalk|archive|zsteg|pcap <file>
./tools/ctfctl tool ffuf http://host/FUZZ --wordlist words.txt
./tools/ctfctl tool rop binary --only 'pop|ret'      # pwn/rev 侦察
./tools/ctfctl solve --backend auto                  # 自主求解循环
./tools/ctfctl race --backends codex,claude          # 多后端竞速，先 SOLVED 者胜
./tools/ctfctl bench                                 # 离线能力基准
./tools/ctfctl platform ctfd pull --url https://ctf.example --event EVENT
./tools/ctfctl trajectory export                     # CSAW 风格轨迹 JSON + MD
./tools/ctfctl knowledge add -C <challenge> --category rev \
    --technique "..." --trigger "..." --conclusion "..." \
    --outcome successful --evidence LOG-000001
```

`make demo` 会跑一遍完整的、不需要模型的演示：doctor → init → hashid/john →
evidence → trajectory export → 基准子集。

## 工作原理

```text
操作者 / 编排器
  → intake / context                  （自然语言进，状态出）
  → scope + 授权检查                   （无范围，无动作）
  → run / tool / tty                  （每条命令都留痕、记账）
  → logs / evidence / state           （审计轨迹）
  → 求解循环 / 专项智能体              （假设驱动的多轮推进）
  → flag candidate → verify → submit  （受门禁，默认 dry-run）
  → report / trajectory               （人读 + 机读双产物）
```

两层结构、一条铁律：**能力层只调用公开运行时原语，绝不直接改权威状态。** 求解循环的每个动作
都经由 `ctfctl` 执行，因此即使多个智能体并行竞速，证据层也始终完整。

仓库结构：

```text
src/ctf_agent/          过程层 + 能力层（import 名为 ctf_agent）
bench/challenges/       原创离线合成题（不含任何真实赛题材料）
agent-specs/            orchestrator / web / pwn / rev / verification 规格
examples/demo.sh        端到端演示
docs/                   架构、计划、工具路由、求解器架构
```

## 开发

```bash
make dev             # 创建 .venv 并安装开发依赖
make check           # 测试 + ruff + mypy + 覆盖率（门槛 >= 80%）
make bench           # 能力基准（脚本驱动）
make demo            # 端到端演示
make scan-secrets    # 扫描 git 历史中的高信号密钥模式
```

贡献流程见 [`CONTRIBUTING.md`](CONTRIBUTING.md)，安全披露见 [`SECURITY.md`](SECURITY.md)。
本项目以 [MIT License](LICENSE) 授权。

## 文档

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) —— 过程层（v0.4.1 契约）
- [`docs/SOLVER_ARCHITECTURE.md`](docs/SOLVER_ARCHITECTURE.md) —— 能力层
- [`docs/TOOL_ROUTING.md`](docs/TOOL_ROUTING.md) —— Kali 工具路由 + 适配器覆盖表
- [`docs/CAPABILITY_PLAN.md`](docs/CAPABILITY_PLAN.md) —— 工程路线图与状态
- [`docs/OPENSOURCE_REVIEW.md`](docs/OPENSOURCE_REVIEW.md) —— 第三方定位评审
- [`CHANGELOG.md`](CHANGELOG.md)
