# dsh-proof

**证据驱动的完成证明与回归归因引擎** — DeepSeek Harness 插件

> 把「我做完了」从一句自我陈述，变成一条可复算的证据链。
> 把「改一处坏三处」从事后发现，变成事中归因。

```
$ proof_claim "修复了登录重定向 bug，并补了回归测试"
✓ PROVEN — 修复了登录重定向 bug，并补了回归测试
evidence root: 9f2c1ab47d0e
PROVEN (p≈0.97) — "修复了登录重定向 bug，并补了回归测试" is backed by evidence root 9f2c1ab47d0e: 3 check(s) passing, 0 regression(s), 1 pre-existing failure(s) left untouched.
```

**一行安装**

```sh
dsh plugin --profile web add dsh-proof
# 或从本地目录 / tarball / git
dsh plugin --profile web add ./dsh-proof
```

v0.15 起，核心不再只是一个插件：它是一个开放标准、一台独立服务器，加上宿主适配器——**所有 agent 的公共基础设施**。**Agent Proof Protocol（APP/1.4）**（见 **[PROTOCOL.md](./PROTOCOL.md)**）把词表、内容寻址、签名链与可携带的 bundle 交换格式固化为任何实现都能说的规范；包内随附 **Proof MCP Server**——任何 harness 上的任何 agent（Claude Desktop、Cursor、一切会说 MCP 的宿主）都能对着一个从未装过 DSH 的工作区调 `proof_verify`；v0.15 起另有 **Claude Code 与 OpenCode 宿主适配器**，在工具调用的缝隙上执行一台服务器永远做不到的强制。v0.18 起另有 **Proof Transparency Log**：已发布的检查点历史从此可被公开核验——任何人都能证明某次交付的检查点确实在日志里，且日志从未回写自身。v0.19 起另有**跨代理责任 DAG**：委派出去的任务携带证明义务，父任务的 `proven` 以全部子任务 `proven` 为前提，DAG 的每条边都是任何人都能从字节重验的 proof bundle——多智能体系统第一次有了可追责的信任拓扑。v0.20 起**训练数据飞轮**装上排气阀：证据日志里机器验证的判定蒸馏为可导出、内容寻址、链上锚定的带标签数据集——诚实工作本身在积累部署方的数据资产。v0.21 起**信任有了单位成本**：定价运行的账本落链（花了多少算、验了多少断言、买到了多少置信、得到多少信息——各按美元计），`proven` 等级可精算为保险式 SLA 报价——除外条款把系统自己的诚实边界写进了保单。v0.22 起整个代码库经 **27 个 agent 逐行对抗审计**（34 条高危全部关闭）：每一个悄悄重新发明「自报即真」的产品面——委派提交、豁免、PTL 发布、bundle 验证——如今都要求一个它可核验的签名或信任根，学习先验不再为被篡改的脚本体作证，观察层的工具名与 shell 盲区有了守卫。

---

## 一、为什么是这个插件：市面空白分析

DSH 生态已超过 5000 个插件、14 个分类。但把分类摊开看，缺的恰好是**横切关注点**：

| 生态分类 | 数量 | 它解决什么 | 它不解决什么 |
|---|---|---|---|
| 工具与能力 / UI 增强 / 开发与运行时 | 2477 | 能力与体验 | — |
| 记忆 / 会话 / 技能包 | 918 | 记住什么 | 记住的东西**是否为真** |
| 用量与计费 | 156 | 花了多少 | 钱**花得对不对** |
| 工作流 / 通知 / 模型 / 视觉 / 市场 / 娱乐 | 1590 | 编排与接入 | — |

**14 个分类里没有「验证 / 审计 / 可信」。** 而这恰好是所有 DSH 用户最先撞上的墙：

1. **「Agent 说完成了，问题却还在」** —— 模型自我陈述无法证伪。
2. **「改了一个地方，另一个地方坏了」** —— 没有基线，就分不清「本来就坏」和「被你改坏」。
3. **「用户手动改了文件，Agent 不知道」** —— 世界模型与仓库事实漂移，模型继续基于旧代码推理。

三件事同一个根因：**Agent 的「认知」与仓库「事实」之间没有强制对齐机制。**

### 已有方案为什么不够

| 现有方案 | 机制 | 差在哪 |
|---|---|---|
| `dsh-completion-guard` | 让模型自己保存任务清单、逐项核对 | 仍是**自我陈述**，没有机器测量的证据 |
| `dsh-rollback` | 记录改前映像，事后回滚 | **止血**，不是预防，也不是证明 |
| `@suagr_xl/dsh-safety` | 删除进回收站、插件组合事务化 | 面向**破坏性操作**，不验证结果 |
| Aegis 技能包 | 提示词层的方法论 | 提示词层，**不强制、无证据** |

**`dsh-proof` 是运行时强制的「事实层」**：把断言变成证据，把「我猜文件是这样」变成「我刚校验过」，把「跑过了」变成「基线对比证明没有回归」。

---

## 二、能力：三个支柱，一个论点

### P1 · 基线（Baseline）

开工前自动发现仓库的**客观事实检查**并跑一遍，记录证据快照：

- **多语言发现器**：`package.json` scripts、`pyproject.toml`（pytest / mypy / ruff）、`go.mod`、`Cargo.toml`、`Makefile`、`composer.json`
- **发现的是「仓库自己声明的可执行命令」**，不是模型说的话
- **内容寻址证据**：`sha256(canonical(outcome))`，同一条证据跨会话、跨机器可比对

### P2 · 变更影响与增量验证（Impact-Aware Incremental Verification）

不跑全量。根据本次会话**实际改动的文件**选出受影响的检查：

- **反向依赖闭包**：TS/JS/Python 的 import 图，改动 `src/c.ts` → 传染 `b → a → test/a.test.ts`
- **路径耦合 + 全局失效器**：`package.json` / lockfile / `tsconfig` / CI workflow 变更 → 全部检查过期
- **保守原则**：图被截断、文件类型未知、路径过滤缺失 → **放大选择而不是缩小**。多跑一次的代价远小于漏掉一个断点

### P3 · 断言 → 证据（Claim → Evidence）

`proof_claim` 是模型声明完成的**唯一合规出口**：

```
基线 ∘ 变更 = 证明
```

| 基线状态 | 当前状态 | 判定 | 谁负责 |
|---|---|---|---|
| pass | pass | `still-passing` | — |
| pass | fail | **`regression`** | **本次会话**，并给出嫌疑文件 |
| fail | fail | `still-failing` | 本来就是红的，**不记在你头上** |
| fail | pass | `fixed` | 本次会话修好了 |
| 无记录 | pass | `new-check` | 首次纳入视域；**真跑过且决定性通过**才计入 passing |
| 无记录 | fail | `new-failure` | 无法区分，如实标注 |
| 有记录 | 本次未跑 | `not-run` | 证据过期 |
| 任一侧 skipped / timeout / aborted / error | — | `indeterminate` | **既不记功也不记账**——知识格的诚实中间态 |

判定知识格是三值的：**记功**（`still-passing`、`fixed`、决定性通过的 `new-check`）、**记账**（`regression`、`still-failing`、`new-failure`）、**两者都不是**（`indeterminate`、`not-run`、从未运行的 `new-check`）。记账要求基线是决定性 pass，记功要求基线是决定性 fail——任何一侧拿不到决定性结果，判定就是 `indeterminate`，summary 相应有独立的 `indeterminate` 计数。**未知永远不能向任何一方借确定性**（v0.7 之前，`skipped` 曾被当作"通过"参与对比）。

**这是本插件的头号差异点**：在一个本来就红的仓库里工作时，你不需要先修完所有历史遗留才能证明自己没做坏。这正是「大多数用户」的真实处境。

### 附加：工作区漂移检测

工具流之外的文件改动（IDE 编辑、构建产物、后台进程）会被指纹比对抓到，注入纠正性上下文（注入文案为英文，以下逐字引自 `observe.ts` 的 `driftNarrative`）：

```
⚠️ Files you already read have changed outside your tool calls. Your in-context copies are stale:
  · src/auth/redirect.ts
Re-read these before relying on them, then re-run proof_verify.
```

---

## 三、五档评级

| 评级 | 含义 |
|---|---|
| `proven` | 有基线、受影响检查全部拿到决定性结果、零回归 |
| `regressed` | 本次工作**弄坏了**什么（回归或首次出现的失败） |
| `stale` | 有受影响的检查拿不到决定性结果（未跑 / 跳过 / 超时 / 中断） |
| `unproven` | 工作区没有客观检查，或改动集不被任何检查覆盖 |
| `no-baseline` | 没有基线，无从对比 |

**诚实优先**：拿不到证据就不背书。`proven` 是唯一能让模型说「做完了」的评级。

**分级信任（v0.9）**：默认的 `bayesian` 调度器下，`proven` / `stale` 的分界不再是「受影响检查是否全部拿到决定性结果」，而是**后验概率阈值**——claim 后验 ≥ `certifyTarget`（默认 0.97）即 `proven`，叙事展示为 `PROVEN (p≈0.97)`；未达标即 `stale`（如 `STALE (p≈0.61, target 0.97)`）。`no-baseline` / `regressed` / `unproven` 的优先序不变；`scheduler: 'set'` 时回到旧的二值覆盖规则（即上表语义）。详见 §五·十二。

**覆盖维度（v0.13）**：「跑过、绿」之上，`proven` 还要求检查**真的执行过改动**（change-executed）——检查子进程经 `NODE_V8_COVERAGE` 留下的 V8 覆盖率若显示某个变更源文件从未被任何决定性通过的检查执行，`proven` 降为 `unproven`（点名未执行文件）；`regressed` / `stale` 不受此门影响。三档模式（`coverage`: `observe` / `require` / `off`）详见 §五·十六。

---

## 四、面向模型的九个工具

| 工具 | 作用 |
|---|---|
| `proof_status` | 当前证明状态：基线、发现的检查、最新证据、证据链是否完好 |
| `proof_baseline` | 建立/刷新基线：跑全部客观检查并记录证据 |
| `proof_verify` | 增量验证：只跑变更集所影响的检查，对照基线给出评级与归因 |
| `proof_claim` | **声明 + 证明**：`proven: true` 才算数，否则 `blockers` 就是待办清单；v0.10 起可携带合约参数（`kind` 与 `budgetMs` / `review` / `entryPoints`）把断言绑定到对应的证据义务（§五·十三） |
| `proof_jury` | **B 类证据·第一步**：为断言申请一次 LLM 陪审审议——冻结审议 prompt（量规全文 + 断言 + 上下文）返还模型，并把请求（含逐字 prompt）落链（§五·十四） |
| `proof_jury_submit` | **B 类证据·第二步**：把陪审裁决（verdict / probability / reasoning 逐字）连同冻结 prompt、声明模型身份、独立性档位全包落链为永久 Class B 证据；claimId 必须匹配最新请求；gen 自动 +1 = 申诉 |
| `proof_endorse` | **C 类证据**：具名人类背书/驳回断言——调用本身触发宿主审批（ask），人类批准才落链（approver / scope / approvedAt）；endorse = 风险接受（解锁等级、不抬数字），reject = 崩塌置信 |
| `proof_conjure` | **合成证据·第一步**：为没有现成检查的断言申请构造验证——插件冻结请求（断言全文 + 待覆盖路径）、把确定性脚手架模板落盘 `.proof-synthetic/`、`synthetic/requested` marker 上链，并返还四步操作指引（§五·十五） |
| `proof_conjure_run` | **合成证据·第二步**：插件校验链上请求存在 → 读取沙箱脚本并逐字 sha256 → 能力筛检（拒收即 `skipped`，不执行、不落链）→ 经插件自己的执行端口运行；`scriptDigest` 连同沙箱档位/筛检结论/作者归因参与 `evidenceId` 内容寻址，`synthetic/run` marker 上链 |

所有工具都遵守 DSH 的硬契约：`execute` 只返回**规范 JSON 值**，人类可读文案在 `output.render`，UI 卡片通过 `presentCall` / `presentResult` / `presentationMeta` **纯投影**生成 —— session-log 回放时逐字节复现同一张卡片。

---

## 五、运行时强制（不只是提示词）

| 扩展点 | 机制 |
|---|---|
| `tools/pre-execute`（waterfall） | `requireBaseline: ask` 时，**没有基线就不许改工作区**，走用户审批 |
| `tools/pre-execute`（waterfall） | `evidenceStore: workspace` 时，**写入证据库的变更类工具一律转用户审批**——被审计者不能改审计记录 |
| `tools/pre-execute`（waterfall） | `proof_endorse` 恒转 `ask` 审批——Class C 证据是**人类的有意识决定**，模型说了不算（§五·十四） |
| `tools/result`（emit） | 观察每次工具结果，维护脏区与文件指纹 |
| `agent/turn-stopping` | 本轮改了东西但没做 `proof_claim` → 注入纠正性上下文；没有基线且 `requireBaseline: warn` → 注入基线提醒；检测到漂移 → 注入 stale 警告 |
| `ctx.systemPrompt.section()` | 发布 `proof:policy` 段落，让模型知道规则存在，不必靠失败去摸索 |

## 五·五、信任模型（v0.2）：对抗被审计者

证据日志的对手不是黑客，是**它要审计的智能体本身**——模型有文件写工具，可以把 `.proof/` 整个重写，并用本包导出的哈希函数重算所有自洽地址。v0.1 的 `audit()` 只能抓这种「天真篡改」。v0.2 用四层机制把「证明者」和「验证者」分开：

1. **哈希链**：每行携带 `prev = sha256(上一行)`，改动或删除任意一行都会断链。
2. **签名检查点**：检查点承诺 `{记录数, 链头}`，由**宿主持有、模型不可见**的 Ed25519 密钥签名（密钥在 `$DSH_HOME/proof/keys/`，永远不在工作区内）。智能体可以伪造整条链，但**造不出签名**。
3. **带外锚点**：历史最高检查点同时镜像到密钥旁边的锚点文件（工作区之外）。把日志截断或回滚到旧检查点之前 → `rewind` 检测。
4. **基线摘要入链**：`baseline.json` 是普通 JSON 文件，整体替换原本不可察觉——现在保存时其 sha256 作为 marker 落链并紧跟检查点，任何事后替换都会被 `audit()` 标记 `baselineTampered`。

配套的存储隔离：默认 `evidenceStore: host` 把日志放到 `$DSH_HOME/proof/workspaces/<工作区指纹>/`，移出工作区——这是一个**由宿主属性背书、由插件守卫而非由插件凭空创造**的事实：v0.22 起，信任根已知时共享适配层门（Claude Code、OpenCode、以及一切基于 `src/adapters/shared` 构建的适配器）会拒绝以绝对路径写入宿主侧证据库的调用、以及提及证据库（或信任工件）的 shell 命令；未配置信任根的部署，日志仍在工作区之外，但对绝对路径写入**如实不设防**。选择 `workspace` 模式（放回项目内）时，写入 `.proof/` 的变更类工具会被转用户审批。

`proof_status` 暴露全部信任遥测：`chainMode`（signed/unsigned/legacy）、`checkpoints`、`chainIntact`、`rewindDetected`、`baselineTampered`，以及 v0.7 加入的三态裁定字段（`unverifiableCheckpoints`、`anchorForged`）与检查点窗口余量（`tailRecords`）。`proven` 评级的可信度从此有了对抗性保证：**日志要么没被动过，要么动了就会被点名。**

## 五·六、变更集溯源（v0.3）：内容锚定 + 来源归因

「改了什么」与「谁改的」从此分开。v0.1–0.2 的变更集就是 `git status` 的脏文件清单——基线之前就存在的旧脏区、用户在 IDE 里的手改、智能体的工具编辑，三者混在一起全部记在会话头上。v0.3 用三层机制重构：

1. **内容锚定基线**：建基线时对每个脏文件记录内容摘要（`dirtyDigests`）。基线检查是对着*当时的工作树*（带脏文件）跑的，所以真正的对照原点是那些字节，不是某个 commit。变更集 = 「与基线快照的内容差异」：
   - 基线时脏、至今未动 → **排除**（陈旧脏区豁免，不再是每次 verify 的冤大头）
   - 基线时脏、之后被改 → 计入
   - 基线时脏、被还原成 HEAD 内容 → **计入**（对基线快照而言这就是变更，`git diff HEAD` 看不见）
   - 基线时干净 → `git diff <baselineHead>` + 未跟踪文件，计入
2. **来源分类（provenance）**：结合会话级工具触达集（`WorkspaceWatch.sessionTouchedPaths()`，跨轮次累计），每个变更文件标注 `agent` / `external` / `explicit` / `unknown`。
3. **归因区分**：`attributedTo` 只装智能体（或显式声明）的变更；外部变更进入 `externalSuspects` 单独呈报。**用户在 IDE 里改坏的文件，回归照实报告（诚实优先），但不再记在智能体头上**——理由栏写明 "changed outside the agent's tool stream"。

解析方法在结果里显式标注（`attributionMethod`：`baseline-content` / `git-head` / `dirty-fallback` / `explicit`），降级可见：无 git 时退化为脏区并集，旧格式基线（无摘要）退化为保守包含。`proof_verify` 的输出新增 `externalChanged` 清单，渲染为 "EXTERNAL edits (outside your tool stream, not charged to you)"。

## 五·七、LSP 影响融合（v0.4）：双源置信的影响图

影响分析从「正则近似」升级为**双源置信融合**。核心技巧：把 `goToDefinition` 放在**导入语句的模块说明符上**（TS/Python 语言服务器都支持"点导入字符串跳到目标文件"），于是：

1. **验证**：正则图的每条近似边都可被语言服务器确认，变成 `lsp-verified` 边；
2. **发现盲区**：`tsconfig paths` 别名、包内路径等**工作区内部导入**是正则永远看不见的——monorepo 里「改了别名指向的文件、检查却没被选中」的漏判由此堵上；
3. **并集语义（soundness 永不变窄）**：验证过的边与近似边取并集；语言服务器缺席、查询失败或预算耗尽时，该边退回近似——**精度降级，覆盖不降级**。

工程控制：`DefinitionResolverPort` 端口（核心层零框架依赖不变）+ 宿主 `ctx.lsp` 适配（`dsh/lsp-impact.ts`）；结果按（文件, 内容版本, 位置）缓存，单次建图有 `lspQueryBudget`（默认 400）硬预算。精度在 `proof_verify` 输出中显式可见（`impactPrecision`：`lsp-verified` / `approximate` / `forced`）。

## 五·八、智能摘录（v0.5）：预算花在失败信息所在的地方

`headChars` 曾经是个死配置（值传进了引擎却到不了领域层）——v0.5 把它接通为真正的**摘录预算**，并升级了花钱的方式。朴素的前 N 字符截断有一个结构性缺陷：测试输出的头部通常是横幅（「✓ 50 passed」），**断言、diff、栈回溯在中部或尾部**——截断截掉的恰恰是模型修 bug 需要的部分。

新策略 `balanced`（默认）三段式分配预算：

1. **显著行优先**：第一条匹配失败模式的行（`AssertionError`、`expected/received`、`Traceback`、栈帧 `at ...`、`✖`、`not ok`、`timed out`……）只要不超过预算一半就**强制保留**——检查为什么红，优先级高于横幅和尾声；
2. **对齐整行的尾窗**：从剩余预算里向前取整行（绝不从词中间切开）——栈回溯完整可见；
3. **诚实的省略记账**：`[... N chars omitted ...]` 标记精确记下被丢弃的字符数，证据记录携带 `outputTruncated` / `outputOmittedChars` 字段；硬夹逼保证摘录永不超预算，且夹逼只削尾部、**从不削显著中段**。

一切是 `(文本, 配置)` 的纯函数——确定性保持，内容寻址不受影响。配套升级：回归叙事与 `proof_verify` 的失败详情改为**优先引用显著行**（`firstInformativeLine`）而非首行——模型第一眼看到的就是「expected 1 to be 2」，不再是「✓ 1 passing」。保守起见 `excerptStrategy: head` 保留了旧行为。

## 五·九、位置无关的证据寻址（v0.6）：同一次失败，任何机器同一个地址

编译错误与栈回溯几乎必然携带绝对路径——digest 因此混入本机路径，同一测试在两台机器、两个检出目录产出**不同的 `evidenceId`**：跨会话比对、证据去重、第三方复算（透明日志的地基）全部无从谈起；而且用户名（`/home/alice/…`、`C:\Users\28646\…`）被写进可能导出审计的证据记录，是一处实打实的**隐私泄漏**。

v0.6 在 `normalizeOutput` 落地双层归一：**root → `$WORKSPACE`（先具体）**，**home → `$HOME`（后一般）**——工作区恰在主目录下时整段先坍缩为 `$WORKSPACE`，兄弟路径归 `$HOME`；Windows 路径的正反斜杠双形态都能匹配。`makeEvidence` 经由 Runner 注入 `{root, home}`（`normalizeHome` 可配置，默认开），于是：

- **同一次失败在任何机器、任何检出目录、任何用户名下，`outputDigest` 与 `evidenceId` 完全相同**——证据天然跨机器去重，这是「证明透明日志」能够比较、合并、第三方复算的前提原语；
- **用户名不再进入任何证据字段**；
- 不传归一根时行为逐字节保持旧状（存量 digest 稳定），且 `audit()` 的自寻址验证对存量字段重算，天然不受影响。

## 五·十、诚实性加固（v0.7.0）：不确定，就绝不冒充通过

深读一轮之后修的全是「错误的方向性」：不是缺功能，而是存在一整类会把**未知四舍五入成好消息**的路径。v0.7 把它们逐个关掉。

**判定知识格（三值）**。旧判定里 `skipped` / `timeout` 与"通过"同权——一个从未真正跑完的检查，可以凭两边的"非失败"被记成 `still-passing`；没运行过的 `new-check` 也稀释着 passing 数字。v0.7 重写为三值格：非决定性（skipped/timeout/aborted/error）落在 `indeterminate`，既不记功也不记账，summary 新增独立计数；`new-check` 只有真跑过且决定性通过才计入 passing。记账要求基线决定性 pass，记功要求基线决定性 fail——**未知永远不能向任何一方借确定性**。

**信任三态**。audit 的签名裁定从二态改为三态。旧逻辑在**没有 signer 的机器**上（密钥丢失、换机器审计）会把带签名的检查点误读成可疑；现在只有本机实际持有的密钥、面对点名该密钥的检查点，才有资格**驳斥**（`badCheckpoints`，真正的伪造指控）；本机无法裁定的（`unverifiableCheckpoints`）是**能力缺失而非指控**，不再使 audit 失败。锚文件自身的签名现在也会被验证（`anchorForged`），且锚携带 `workspaceKey`——审计可以仅凭锚文件重导出被签名的字节。

**引擎的诚实边界**。git 不可用时（WorkspacePort 新可选能力 `gitAvailable?()`），每条 git 查询各自失败返回空集——"什么都看不见"曾被吞成"什么都没变"，增量选择悄悄缩成空。现在变更集显式标记 `degraded`，引擎**强制全量跑**并在 `VerifyOutcome.degraded` 透出。中止的基线不再落盘——abort 的基线曾照常写盘，之后的回归判定对着半成品真值运行；现在已观测的证据仍全部入链、落 `baseline/aborted` 标记、检查点窗口照常闭合，返回值携带 `aborted` 标志，下一次 verify 诚实报告 `no-baseline`。signer 加载失败大声降级：链内 `trust/signer-unavailable` marker + verbose 日志——静默降级与诚实的 unsigned 部署从此可区分。`requireBaseline: 'warn'` 从"配置了但没接线"变成真通知：本轮动了工作区而没有基线时，回合结束经 `agent.inject` 注入纠正性提示。死配置 `driftNoticeMs` 删除（配置降至 22 项，v0.9 增至 24 项，v0.10 增至 26 项，v0.11 增至 28 项，v0.12 增至 31 项，v0.13 增至 32 项，v0.14 维持 32 项——MCP 服务器不读配置，走环境变量，见 §五·十八；v0.15 亦维持 32 项——宿主适配器同样只走环境变量，见 §五·十九与 §五·二十）。

**正确性收口（soundness closure）**。monorepo workspace 子包检查不再丢失：CheckSpec 新增 `cwd`（相对 root），子包检查真正在子包目录执行、id 含 cwd（cwd 缺省时 checkId 与旧格式逐字节一致），`packages/*` 单层 glob 现在真正展开——同 argv 的兄弟包检查不再互相顶替。影响图补盲：动态 `import('...')` 与多行 ESM import 现在产生边；Python dotted import（`pkg.mod`）在扫描集内尝试解析——多出的边只造成过选，绝不漏选。`git status --porcelain -z` 的 rename 条目解析修正（旧路径曾被截掉 3 个字符成为幻影路径；解析提为纯函数 `parsePorcelainZ`）。Windows 盘符绝对路径（`C:\...`）统一进路径域：observe 的 touched 归类、LSP root 前缀比较（大小写不敏感）、证据库守卫均修正。EvidenceStore 写入改单飞队列——并发的 append/mark/checkpoint 曾可能都链到同一个 tail，后一条的 `prev` 指向一条已不存在的行：**正确代码与它自己的竞态**。证据输出捕获改用 StringDecoder，多字节字符跨 chunk 边界不再碎成 U+FFFD。工程卫生：CI 改 `npm ci` 并加 windows 矩阵；`check-bundle` 错误路径不再崩溃；`untouchedChecks` 输出修正。

## 五·十一、完备性闭合（v0.8.0）：账目对得上，事实守得住

v0.7 关掉的是「未知冒充通过」的路径；v0.8 关掉的是另一类失真——**账目与事实本身**：摘录账面记不齐、日志经不起崩溃与重启、适配层把事实译错。五个方向，每一条都对应一个曾经真实存在的错误行为。

**摘录账目真话（excerpt.ts）**。v0.5 的 balanced 摘录声称"硬夹逼保证永不超预算"，但预算只约束内容、不约束省略 marker——账面可能超支。v0.8 把预算不变量升级为 **`text` 总长（含 marker 与连接换行）≤ budget**，且对两种策略统一成立（`head` 是恰为 budget 的逐字切片，消费者无需知道策略就能信赖 `text.length <= budget`）。账目侧新增 `keptOriginalChars` 字段（`text` 中来自原文的精确字符数），闭合不变量 `omittedChars + keptOriginalChars === normalized.length` 严格成立——marker 会虚增 `text` 长度，所以对账永远对 `keptOriginalChars`，不要对 `text.length`；marker 打印的也永远是最终省略数，不是截断前的估计。显著失败行**永不被截半**：装配超出预算时按「尾窗最早行 → 头窗尾部 → 退化 head 语义」的顺序牺牲，`truncated` 保持为真使损失可见。单巨行场景头窗与尾窗双重计数（同一段字符账面记两遍）的隐藏 bug 一并修复。

**存储完备性（evidence / checks / hash）**。五件曾经"守不住事实"的事：

1. **跨进程证据去重**：append 幂等曾只在进程内成立——进程重启后重放同一条证据会真的再落一行盘。现在首次变更日志时做一次全量扫描，把每个已在链上的地址重建入去重缓存，同一地址的 append 跨进程也是真 no-op。
2. **半行崩溃自动恢复**：进程在写最后一行中途死掉会留下一条"有前缀、没有闭括号"的撕裂行——下一次启动曾永远把它当 corrupt 报。现在启动扫描发现**尾行**撕裂即原子重写去掉残行，并把修复本身作为 marker `log/recovered-partial-tail` 落链（后续行仍链向新尾）。**中间**行的 corrupt 不恢复：对手重写的是完整行，撕裂是崩溃的物理签名——那是篡改，审计继续报。
3. **config 与自动发现同命令去重**：显式配置与自动发现命中同一命令时不再跑两遍，显式配置优先。
4. **canonicalJson 环检测**：循环引用以清晰的 `TypeError` 报错（此前是栈溢出）。
5. **盘符大小写漂移归一**：`c:\ws\...` 与 `C:/ws` 折叠进 `$WORKSPACE`（Windows 盘符大小写不敏感，工具经常吐出另一种形态）；反斜杠 root 保持历史行为，存量 digest 稳定。

**Node 适配层保真二期（node-ports）**。`npm` / `pnpm` / `yarn` 在 Windows 上是 `.cmd` 垫片，Node 的 spawn 拒绝执行——**pnpm 曾因此在 Windows 上无法作为检查命令**。解法不是开 shell（那是本端口拒绝打开的注入面），而是**解析**垫片：npm 生成的 `.cmd` 遵循稳定模板，解析出目标脚本后直接 `spawn(node, [script])`——无 shell、无注入面；非标准垫片给清晰的 spawnError 而不是乱码。`CommandResult` 新增 `killedBySignal`：被外部信号击杀是事实，此前该事实被吞；win32 下恒缺省——Windows 不跨进程传播信号，诚实地说"不知道"而不是编一个。并发写临时文件名唯一化 + rename 重试（Windows EPERM 竞争：杀毒/索引器短暂锁文件不再丢数据）。

**执行与判定收口（runner / report / engine）**。被外部信号杀死的检查记为 `error` 并在记录中注明信号——此前信号死亡被吞成无退出码、再被误判成 `timeout`，两种死因混为一谈，预算与超时归因全部失真。forcedAll 的选择构造曾在三处重复，收敛为单一函数 `forcedSelection`。runner 首次获得直接单测（`test/15-runner`）：并发 clamp、预算 skip、abort 传播、乱序完成重排、killedBySignal 判定、spawnError、excerpt 贯通——此前这个并发调度核心只被集成测试间接覆盖。

**适配层诚实二期（index / observe）**。启动即探测磁盘基线——首轮 prompt 曾说"尚无基线"的谎（基线可能上一会话就建好了，只是还没读盘）；现在第一句话就是真话。turn-stopping 的等待观察器落盘：等待中的观察器在回合结束曾不落盘，drift 检测下一轮读到的是旧状态。mutation 分类收敛为单一事实源（分类规则移入 observe.ts）：**未知工具默认按 mutation 记**——宁可保守记在 agent 头上，也不把改动漏成 external。`pathsIn` 移除 `'source'` 内容键：`source` 是"代码片段内容"的常见参数名而非路径，带该键的编辑工具曾把整段代码文本混进 touched 集合，把不属于本会话的文件错怪给 agent。

## 五·十二、贝叶斯验证调度器（v0.9.0）：认证到 0.97 就停，而不是全跑

v0.8 及以前，「跑哪些检查」是纯集合运算：变更集 → 影响闭包 → 闭包内全部跑完。「跑完」是当时唯一诚实的选项——跳过任何一个都是把未知藏起来。但这条成本曲线是线性的，而**边际信息递减**：一个连续 200 次全绿的老检查，再跑一遍买到的确定性接近零，账单却是全额时长。v0.9 把「跑哪些」从集合运算变成**信息增益决策**：预测性测试选择（Google 2015–2021、Facebook 2019 的那条工作线）首次应用于 agent 断言——证据日志本来就是一个带标签的历史数据集（checkId × 状态 × 时长），从中学习每个检查的两个经验参数（**多 flaky**、**多慢**），然后按「每毫秒买到的确定性」给运行排序，**认证到目标后验就停**。新模块 `src/core/bayes.ts` 是纯函数、零 I/O、零时钟——这些数字会进证据与报告，内容寻址纪律要求比特级确定性（所有可能把迭代顺序泄漏进结果的 Map 一律按排序键遍历）。

**先验：从历史与影响学出 π**。每个检查被建模为一个**非对称二元信道**——对「工作区（就该检查所断言的内容而言）是健康的」这一个二元命题的带噪传感器：

| 参数 | 语义 | 公式 |
|---|---|---|
| π | 先验健康概率 P(healthy) | clamp(1 − ρ·s, 0.05, 0.999) |
| ρ | 失败倾向 | (failures + 1) / (runs + 5) —— Beta(1,4) 的后验均值（Laplace 平滑） |
| s | 影响强度：本变更集对这个检查作用多强 | 阶梯见下表，对一切正向证据取最大值 |
| α | 假阳率 P(观测 fail \| healthy)，即 flake | 无历史 0.05；否则 clamp(flips / (2·max(1, runs−1)), 0.01, 0.3) |
| β | 假阴率 P(观测 pass \| broken)：坏了却绿（陈旧缓存、夹具漂移、从未真正断言） | **固定 0.02，永不学习** |

ρ 的平滑是有立场的：从没跑过的检查 ρ = 0.2（怀疑态度），200 次全绿的老兵衰减到 ρ ≈ 0.005。非决定性记录（error/timeout/aborted/skipped）计入失败侧——一个不断 error 的检查，它的 pass 不值得信任，怀疑的方向是对的。flips 只在**相邻决定性观测**（pass↔fail）间计数：`pass → error` 不算翻转——error/timeout 是「没有答案」，不是「另一个答案」；对称 flake 模型下相邻观测分歧率 ≈ 2α，故 α ≈ flips / (2·(runs−1))，分母保持含全部记录，interleave 时系统性偏低——记为粗糙，不假装修正。影响强度 s 的阶梯：

| s | 证据 |
|---|---|
| 1.0 | 变更文件精确命中检查的具体（非 `'*'`）路径模式（精确文件或显式 glob `dir/**`、`dir/*`），或 LSP 确认边从变更文件通向检查覆盖的文件 |
| 1/(1+d) | 经 d ≥ 1 跳**近似**反向依赖到达覆盖文件（d=1 → 0.5，d=2 → 1/3）；对具体声明的检查，距离档可以低于 0.5——模糊耦合是弱于一揽子声明的证据 |
| 0.7 | 仅裸目录前缀匹配（`paths: ['src']` 覆盖 `src/a.ts`）：作者声明的是区域，没有任何确认 |
| 0.5 | 检查声明 `'*'` 一揽子覆盖，或完全没有正向证据：候选池已被上游闭包判为受影响，「说不上来为什么」按 wildcard 档计，绝不记 0，也绝不给只有长链近似传播的具体声明检查免费抬轿 |

π = clamp(1 − ρ·s, …) 的含义是**影响强度缩放失败倾向**：够不着检查的变更（s→0）不动它的老兵记录，直接命中（s=1）全额记账。无图时阶梯退化为纯路径匹配（1.0 / 0.7 / 0.5）——不发明没有声明的传播。

**排序：按信息增益定价每一次运行**。`rankByInformationGain` 为每个候选计算**期望信息增益**（nats）：

VOI = H(p₀) − [P(pass)·H(p₁|pass) + P(fail)·H(p₁|fail)]

其中 p₀ 是当前 claim 概率（各检查健康概率之积），p₁ 是把该检查的因子换成观测后验后的 claim 概率，P(obs) 对因子现值边缘化。因为因子更新是真贝叶斯步，E[p₁] = p₀ 精确成立（鞅），凹性 H 上的 Jensen 不等式给出 **VOI ≥ 0**——跑一个检查永远不会增加期望不确定性（浮点下限截到 0，让数值与定理一致）。排序键是 **voiPerCost = VOI / max(1, 期望时长)**：期望时长取历史下中位，无历史回退 `checkTimeoutMs / 4`——便宜且不确定的排前面，昂贵且已沉淀的老兵排后面。贪心排序、平局按 checkId 字节序，**比特级可复现**。

**波式调度与三种提前停**。引擎按此分波执行（每波 `concurrency` 个），每波结束用真实结果更新各检查后验，然后按优先序检查三个停机条件：**(1) 认证达成**——claim 后验 ≥ `certifyTarget`，剩余检查不必跑，成为带各自先验的 planned skip；**(2) 首个决定性 fail**——断言已死，归因证据已经足够，剩余检查救不回来；**(3) 预算耗尽 / 调用方 abort**——如实按降级结束。非决定性结果（timeout/aborted/error/skipped）**不更新因子**：检查保留先验、计为未决——既不赦免也不定罪。计划的足迹全程可审计：`VerifyOutcome.schedule` 携带 `{ mode, waves, stoppedEarly: 'certified' | 'failed' | 'budget' | null, skippedByPlan: [{checkId, priorHealthy}] }`，并随 `proof/verified` marker 入链（scheduler/waves/stoppedEarly/plannedSkips/confidence）。

**分级信任：proven 不再假装 100%**。ProofReport 新增 `confidence`（claim 后验）与 `confidenceBasis`（这个数是怎么挣来的）：`full-coverage`——全部受影响检查跑到决定性结果，**后验仍 < 1**（每个因子带着 flake 残差，这是诚实不是 bug）；`certified-subset`——后验过线提前停，没跑的检查以 planned skip 列出、各自带先验；`degraded`——没过线就结束（预算、中断，或决定性失败）。`proven` 的语义从「全跑且全绿」升维为「**后验 ≥ certifyTarget**」：跳过的检查不是被忽略，而是把剩余不确定性如实带进后验。叙事输出直接说人话：`PROVEN (p≈0.97) — 2 passing — 0 failing — 2 stale/unrun`、`STALE (p≈0.61, target 0.97) — …`。评级规则相应变化：bayesian 模式下旧的「unverified>0 → stale」被「confidence ≥ target → proven，< target → stale」替换，优先级原位继承（排在回归之后——死掉的断言永远不被「认证」）；改动集不覆盖任何检查仍是 `unproven`——空乘积是空洞的确定性，不是证明。工具面同步：`proof_verify` 的返回值新增 `confidence` / `confidenceBasis` / `certifiedSkips` / `stoppedEarly` / `waves`（仅在带后验时出现，legacy 路径省略以保证规范值字节稳定），渲染多出一行置信说明。

**健全性宪法不回退**。提前停是**特权不是默认**：候选池仍然是影响闭包，闭包的保守规则一字未动——全局失效器（lockfile/tsconfig/CI）与 uncertain 图仍把池**放大到全部检查**；引擎级 whole-batch 旁路（完全不经波式调度）保留给 `all: true`、git 事实不可用（`degraded` 强制全量）与 `scheduler: 'set'`（行为级 kill-switch：整批全跑、旧二值评级，逐位复现 v0.8 结果）。只有「健康、非强制、bayesian 调度」的运行才被允许凭证据提前停。两个调度器共享同一套 runner、证据链与摘录——不同的只是决策规则。新配置两项：`scheduler`（默认 `'bayesian'`）与 `certifyTarget`（默认 0.97）。

**诚实边界**。**(1) 独立乘积近似是最大的已知失真**：`confidence` 是各检查健康概率的连乘，隐含检查相互独立——共享同一批变更文件（或同一夹具、同一套测试跑两遍）的检查，失败是相关的，乘积会**高估**证据强度；替代方案（对全部检查建模联合分布）恰恰需要我们没有的真值数据，所以这个数应读作**排序信号而非标定概率**。**(2) β = 0.02 是承认的猜测**：假阴率需要「确实断了」的标注数据才能学习，而日志只记录观测；固定常数是诚实的猜测，在这里学一个数出来才是假精度。**(3) 先验只和日志一样好**：证据日志短的检查先验保守（ρ = 0.2 起步），这不是缺陷而是设计——没有历史就没有便宜话可讲。

## 五·十三、类型化断言合约（v0.10.0）：断言与证据之间的契约

到 v0.9 为止，`proof_claim` 的 `claim` 是一段自由文本——引擎能证明的只有「受影响检查零回归（且后验过线）」，至于这句话**应该**证明什么，机器无从判定。「我重构了 X，行为不变」「我加了新功能 Y」「性能没变慢」是三种证明义务完全不同的断言，但一道泛化的 no-regressions 门区分不了它们：重构还欠一条「公共 API 没动」，新功能还欠一条「新增路径被测过」，性能主张欠的是一次真实的测量。v0.10 把 claim 从自由文本升维为**合约类型**（`kind`）：声明你做的是哪一类事，就自动绑定那一类断言应负的证据义务——**断言与证据之间从此有契约**。每条义务都可判定（met / not met），义务 id 固定供引擎与工具接线，未 met 时 detail 直接说缺什么、怎么补。

**四类合约与义务矩阵**（义务 id 固定；`zero-regressions` 永远排第一）：

| kind | 适用场景 | 义务（按固定顺序） | 未 met 的后果 |
|---|---|---|---|
| `behavior-preserving` | 重构 / 优化 / 内部清理 | `zero-regressions` + `api-surface-unchanged` | proven 降级 `stale`，detail 点名新增/移除的公共符号 |
| `behavior-adding` | 新功能 / 新模块 | `zero-regressions` + `new-paths-covered` | proven 降级 `stale`，detail 点名未被检查覆盖的源码文件 |
| `perf-budget` | 性能主张 | `zero-regressions` + `benchmark-evidence` + `within-budget` | proven 降级 `stale`，detail 点名超预算的 benchmark 及耗时 |
| `docs-only` | 纯文档变更 | `docs-only-changes` + `jury-review`（`zero-regressions` 为空真——docs-only 不跑检查，该义务诚实移交 `docs-only-changes` 承担） | 义务未 met 即 `stale`；全 met 也只有封顶置信（见下） |

**API 面机制（`api-surface-unchanged` 的证据）**。behavior-preserving 的第二义务是「公共 API 面**双向 diff 为空**」——既不许少（破坏性变更），也不许多（悄悄扩面）。面从以下几个环节装配：

1. **入口推导**：默认从项目 `package.json` 推导——`main`、`exports["."]`（字符串，或对象里的 `types`/`default`/`import`/`require` 条件）、`types`/`typings`。每个声明路径做**存在性探测**：原样 + 扩展名变体（`.ts`/`.tsx`/`.d.ts`/`.js`/`.jsx`/`.mjs`/`.cjs`），以及编译产物的 `src/` 等价物（`dist/x.js` → `src/x.ts`）。显式配置 `apiEntryPoints` 优先（只用真实存在的文件）。所有声明都解析不到文件 → **不产出面**——宁可没有面，也不要一个错的面。
2. **import 闭包**：从入口沿**相对导入边**做有界 BFS（深度 ≤ 10、文件 ≤ 500）——面不只看入口文件，而是入口的公共面所立足的全部内部模块。截断会落 `api-surface/truncated` 链上标记：静默截断的面就是错的面加了步数。
3. **五形态提取**（逐行正则，跳过注释与空行）：① `export` 具名声明（`const`/`let`/`var`/`function`/`class`/`abstract class`/`interface`/`type`/`enum`，含 `async`/`declare`/`function*`/`const enum` 变体、多声明符 `const a = 1, b = 2` 与解构导出全量上报）；② `export { a, b as c }`（单/多行折叠、含 `export type { … }`；别名才是导入方绑定的名字，字符串别名原样保留）；③ `export default …` → 记为 `#default`；④ `export * from …` → 记为 `#*`（再导出的面变了也是面变了；`export * as ns` 额外记 `ns`）；⑤ `export = …`（TS CommonJS）→ 记为 `#=`。每个条目形如 `文件#符号名`，排序去重。
4. **内容寻址快照与双向 diff**：建基线时把 API 面作为**非寻址附件**挂在基线上（`apiSurface` 字段；`baselineId` 只哈希 {createdAt, workspace, checkIds, root}，附件不改变基线身份，v0.10 之前的旧基线读回该字段为 `undefined`）。断言时计算当前面，与基线面做**双向 diff**——`added` 与 `removed` 都必须为空，义务才 met；未 met 时 detail 逐个点名（`public API changed — added: …; removed: …`）。
5. **提取刻意偏向过报**：漏掉一个导出 = 漏掉一次破坏性变更（错误通过）；多报一个幽灵导出只是让诚实的断言多干一点活（错误失败）。拿不准就报。

**`new-paths-covered`（behavior-adding 的义务）**：变更集中每个源码文件（按扩展名判定：js/ts/jsx/tsx/mjs/cjs、py、go、rs、java、kt、rb、php、cs）必须被 ≥1 个检查的 `paths` 覆盖，且该检查本次拿到**决定性通过**——新行为必须骑在被测过的路径上。未 met 时 detail 点名未覆盖文件并提示补检查。

**`benchmark-evidence` 与 `within-budget`（perf-budget 的义务）**：前者要求本次运行真的存在 kind='benchmark' 的检查且拿到决定性结果（pass/fail 都算——失败的 benchmark 也是一次测量，只是进不了预算）；后者要求其 `durationMs` ≤ 断言携带的 `budgetMs`（缺失 `budgetMs` 本身即未 met，detail 要求写出毫秒数）。benchmark 检查**不受影响分析裁剪**：perf-budget 断言会把全部 benchmark 检查并进运行集强制执行——性能主张必须产出新鲜的测量，无论影响分析认为 benchmark harness 是否被波及。benchmark 检查两个来源：显式配置 `kind: benchmark`，或脚本名 `bench` / `benchmark` / `perf:bench` 自动发现。

**docs-only 的陪审语义（与 v0.9 分级信任的咬合）**。纯文档变更**不跑任何检查**——对文档正确与否的机器测量本来就不存在，硬跑检查只会制造伪证据。两条义务：`docs-only-changes`（变更集全部是文档类路径——`.md`/`.markdown`/`.txt`/`.rst`/`.adoc` 与图片等，且不命中全局失效器；`requirements*.txt` 挂着文档扩展名却是依赖声明，正是要防的洗白通道，守卫直接复用 `GLOBAL_INVALIDATORS`，两模块永不漂移）+ `jury-review`（claim 必须携带 `review` 自评——写下评审者应复核什么）。义务全 met 时 grade 为 `proven`，但 confidence 被**结构性封顶**在 `juryConfidenceCap`（默认 0.8），`confidenceBasis` 为 `jury-only`，叙事直说其 regime：

```
PROVEN (p≈0.80, jury evidence — self-attestation is capped)
```

这正是 v0.9 分级信任的自然延伸：`full-coverage` / `certified-subset` / `degraded` 说的是「这个数是测量、测量到了什么程度」，`jury-only` 说的是「这个数是自证的**上限**，不是测量」——陪审证据永不冒充实验。裁决落链为 `claim/jury` 标记（携带 claim、review 摘要 200 字符、grade、未 met 义务 id）；报告的 `root` 是 `merkleRoot([])`——对空证据集的承诺，本身就在说：这个裁决靠的是链上 marker，不是检查记录。义务未 met 时 grade 为 `stale`，叙事为 `STALE (jury obligations unmet)`——点名的义务才是理由，一个不再有含义的概率不是。

**`proof_claim` 的新参数**：

| 参数 | 类型 | 语义 |
|---|---|---|
| `claim` | string（必填） | 人类可读的断言文本——保留为陈述，不是规范部分 |
| `kind` | 四选一 | 合约类型：`behavior-preserving` / `behavior-adding` / `perf-budget` / `docs-only`；**省略则与 v0.9 行为完全一致** |
| `budgetMs` | number | perf-budget 必填：benchmark 的 `durationMs` 必须不超过此值 |
| `review` | string | docs-only 必填：留给评审的自查说明（空白文本 = 义务未 met） |
| `entryPoints` | string[] | API 面入口的逐断言覆盖；省略则由 `package.json` 推导或 `apiEntryPoints` 配置 |
| `changed` | string[] | 本次变更文件（原有参数） |

**运行制度与健全性**。带 kind 的断言走全批（whole-batch）制度而非波式调度——义务需要证据，贝叶斯计划性跳过恰好可能跳过断言所依赖的那个检查，所以合约运行不做提前认证（perf-budget 另加强制 benchmark）。义务判定在运行之后做，依据是本次的新鲜记录与「现在」的工作区面。**义务未 met 绝不 proven**：一次 otherwise-proven 的运行只要携带任何未 met 义务，grade 一律封顶 `stale`（更差的评级保持原样；confidence 与 basis 保留运行挣到的数字——数字说测到了什么，义务说还缺什么）。合约摘要随 `proof/verified` 边界标记入链（kind、未 met 义务 id、是否 jury）。向后兼容：不声明 `kind` 的 claim 与 v0.9 行为**完全一致**，自由文本断言保留为人类陈述。旧基线诚实降级：v0.10 之前建立的基线没有 `apiSurface` 附件，`behavior-preserving` 的 `api-surface-unchanged` 直接判 not met，detail 明确提示重建基线（re-run proof_baseline）——不可比较的面永远不是一次通过。义务判定是纯函数（无时钟、无随机、无文件系统），一切多值 detail 先排序——同一输入永远产出字节级同一裁决。

## 五·十四、证据分级体系（v0.11.0）：把一半的世界请回证明体系

到 v0.10 为止，证明体系只承认能被机器测量的断言——「测试全绿」「API 面没动」「benchmark 在预算内」。剩下的一半世界（可读性提升了、错误信息更友好、迁移指南与代码一致）只有一个出口：docs-only 自证，封顶 0.8。v0.11 把**证词（testimony）**作为一等证据请回体系——不是把证词伪装成测量，而是给每一级证据配上它所能承担的最强诚实机制：测量可复算，审议可审计，背书可问责。三级证据一张表：

| Class | 来源 | 完整性机制 | 信任的表达 |
|---|---|---|---|
| **A 机器测量** | 检查运行：退出码 + 归一化输出入链 | **确定性复算**：任何人重跑命令、比对 digest | `claimProbability` 的因子（v0.9 语义，一字不动） |
| **B LLM 陪审** | 陪审对断言的审议裁决（`attest/jury`） | **可审计**：完整陪审包落链——逐字 prompt（含量规全文）、量规版本、提交方声明的模型身份、独立性档位、完整逐字输出；第三方可重放比对 | `attestationFactor = p^classBTrust`（纯陪审路径）；混合力度 `w = classBTrust`（融合路径） |
| **C 人类背书** | 具名人类的 endorse / reject（`attest/human`） | **问责到人**：approver / approvedAt / scope（断言全文 + 证据根）入链；经宿主审批 seam，模型说了不算 | endorse 轻折扣 `0.95^classCTrust`；reject 崩塌 `(1−0.95)^classCTrust` |

**Class B：完整陪审协议（request/submit 二段式）**。第一步 `proof_jury(claim, context)`：`juryPrompt` 以纯字符串拼接**确定性**装配审议 prompt——`=== CLASS B JURY DELIBERATION ===` 头、`--- RUBRIC jury-rubric/v1 ---`、量规全文、`=== CLAIM ===`、`=== CONTEXT ===`、`=== OUTPUT ===`——同一（断言， 上下文， 量规， 版本）永远产出字节相同的 prompt，因为 **prompt 本身就是证据**，「重放这个 prompt」才有确定含义。请求落链为 `attest/jury-requested` marker（claimId、promptDigest、rubricVersion、**逐字 prompt**——只有摘要的请求没法被重放）；工具返还 `{claimId, rubricVersion, prompt, instruction}`，渲染以 `ACTION:` 行指示「按量规审议，然后带 JSON 裁决调 proof_jury_submit」。断言身份是 `claimIdOf(claim)` = sha256(断言文本) 前 16 hex——**改写断言就是新断言**，需要新证词。第二步模型审议后调 `proof_jury_submit(claimId, verdict, probability, reasoning, model?)`：防御性校验（verdict 三值、probability 有限且 ∈ [0,1]、reasoning 非空——参数 schema 是对模型的承诺，不是边界）；claimId 必须匹配链上**最新**请求（模型可能落后好几个请求，修法是重新 `proof_jury`）；请求 marker 缺逐字 prompt 则拒绝记录。通过后**全包落链**：kind / claimId / gen / prompt / rubricVersion / model / independence / verdict / probability / output / at——一份可被第三方整体重放的审议记录。

**量规（`JURY_RUBRIC`，版本 `RUBRIC_V1` = `jury-rubric/v1`）**是每份 Class B prompt 携带的审议契约：只依据给定材料裁决（不用断言主题的外部知识、不假设 CONTEXT 之外的工具与会话）；`verdict` 三值——材料支持则 uphold、矛盾则 reject、不足则弃权；`probability` 是「断言为真」的**主观概率**（校准的判断，不是测量——报告你自己的推理真正支持的那个数）；证据不足就弃权，**诚实的 abstain 比自信的猜测对记录更有价值**；`reasoning` 说明哪些材料支持或削弱断言。输出格式：恰一个 JSON 对象 `{"verdict": "uphold"|"reject"|"abstain", "probability": <0..1>, "reasoning": "<text>"}`，前后不许有别的东西。**来源警告**明示：输出、prompt、声明模型身份将逐字作为 Class B 证据落上防篡改链，任何第三方可用同一或不同模型重跑此精确 prompt 并比对输出——「以你的答案是永久、公开、可复算产物的方式审议，因为它就是」。量规文本逐字冻结在源码里：改量规是代码变更，review 可见，无法在链中途静默换尺；`RUBRIC_V1` 标记每条证词审议时用的是哪版文本。

**可复算的具体含义**。陪审不是确定性的，所以 B 类证据不是裁决本身，而是整个复算包。这套包不能让审议像哈希一样可复算——它让审议**可审计**：任何人拿冻结的 prompt 对声明的模型重放，检查记录的输出是否该模型真的倾向于说的话。不会重放的裁决**可被检测**——这是非确定性证人所能提供的诚信上限，也足以支撑争议（篡改的裁决与真实重放的输出分布对不上）。

**可申诉的具体含义**。链是 append-only，再审议不能覆盖它争议的记录——它在 `gen + 1` 追加，读取方（`activeAttestations`）按（claimId, kind）取**最高 gen**（同 gen 后写的赢）：旧裁决留在链上作为申诉的对偶，被超越但可见。B 与 C 两信道**独立解析**：陪审申诉抹不掉人类背书，再背书也抹不掉陪审记录——不同证据信道，不同申诉过程。

**Class C：审批 seam 与风险接受**。`proof_endorse(claim, decision, approver?)` 的 pre-execute 钩子恒返回 `ask`（双语 displayReason）：模型调用、宿主提问、**人类**决定——只有审批通过，execute 才把 `attest/human` marker 落链（approver 默认 `host-approver`、approvedAt、scope = {断言全文, evidenceRoot}、decision、gen——再背书/撤回同样以 gen+1 超越）。证据根是审批时可寻址的最强锚（基线根；无基线记 null——背书一条无锚断言，记录说的就是这个事实）。**为什么背书不改数字——数学必然**：审批 seam 是二值的，从背书方诱导出的自报置信不是证据，于是人类「对」的概率建模为常数 `humanProbability = 0.95`（不是测量，是 Class C 的 seam 拒绝采集数字后顶上来的建模选择；0.95 < 1 是刻意的——永不犯错的人类背书会让每条被背书的断言不可证伪）。endorse 的因子是 `0.95^0.9 ≈ 0.955`，**永远够不着 0.97 的 certifyTarget**——把背书当确定性转移去乘，数学上一次也过不了线。所以 endorse 在融合里根本不碰数字（`fuseConfidence` 原样返回 current）：它买的是**等级**——`endorsementUnlock`：机器 grade 因「差目标」而是 `stale`、零回归、无 new-failure、义务全 met 时，背书把 grade 解锁为 `proven`——人类接过了机器跨不过的剩余风险（**风险接受**，不是确定性转移），confidence 保持机器测得的数字，basis 记为 `attested`。**背书买不了缺失的工作**：义务未 met、有回归、有新失败时解锁不生效——缺失的工作不是剩余风险（测试钉死：扩大 API 面后即使背书在链上，grade 依然不 proven）。**对称锁**：显式 reject（人类驳回或陪审 reject）把数字乘 `(1−0.95)^0.9` 崩塌；崩塌后 fused < target 而 grade 还是 proven 时降回 `stale`——被宣誓证人否认的断言，不能保留数字已不再支持的等级。

**两套权重数学，各有其位**。信任权重是**声明的策略常数**，不是学出来的——不存在「这个证人历史上对了几次」的标注集，一个调好就没人再调的常数不如一个诚实的声明值。配置两项：`classBTrust` 0.7、`classCTrust` 0.9。

1. **`attestationFactor = p^w`（log-odds 指数折扣）——纯陪审路径的货币**。`claimProbability` 是因子乘积，factor = p^w 使 log(factor) = w·log(p)：信任权重是对证据 log-odds 贡献的**线性折扣**。w = 0 → factor 1（零信任零证据——连 p = 0 都动不了断言，0^0 = 1）；w = 1 → factor p（全信）。关键性质：w ∈ [0,1]、p ∈ [0,1] ⇒ p^w ∈ [p,1]（测试做了 [p,1] 网格扫描）——**证词只能弱化，不能放大**：断言不能靠堆证人被论证到高于其先验与机器证据支持的水平，证人最多做到弃权（factor 1）。这是对自利证明系统正确的怀疑方向。方向不需要特判：reject 自带低 p 而来，p^w 恰在此时低——**方向活在概率里，权重只携带信念**。abstain 恒 factor 1（「我说不清」是证据的缺席，缺席不是反面的证据）；读不出概率的值（NaN 会毒化整个乘积、>1 会放大断言）按弃权处理。`llm-jury` 契约的 confidence 就是 Π attestationFactor（机器因子是中性 1——没跑任何命令）：强陪审 uphold p=0.99 付 `0.99^0.7 ≈ 0.993`，过 0.97 线即 proven。
2. **`fuseConfidence = (1−w)·c + w·p`（可靠性混合）——机器认证已存在时**证人谈论的是**整个断言**，诚实的模型随之不同：以概率 w 证人可靠（置信应成为其断言值），以 1−w 是噪声（机器数站住），期望即线性混合——以力度 w 把数字**拉向**证词值。陪审断言 0.99 @ w=0.7 能把 0.94 的机器认证拉过 0.97 目标（0.3·0.94 + 0.7·0.99 ≈ 0.975——救活），同一陪审断言 0.1 则崩到 ≈ 0.35。混合值**永不超过证人自己的断言**（两个混合端点就是 p 和 current）。Class C 不混合：endorse 数字不动（风险接受，等级解锁），reject 走上面的重折扣乘进 current。

为什么是两套而不是一套：p^w 是「证人作为断言乘积里又一个独立分量」的正确代数——在那里它只能加残余怀疑；混合是「机器已经挣到认证、证人谈论整个断言」的正确模型。**用哪套由「机器是否已经说话」决定，不由哪套数字好看决定**。

**`llm-jury` 契约（引擎合约系统的第五类 kind）**。与 docs-only 一样 `skipChecks` 不跑任何机器检查，但动机相反：docs-only 是没有值得测量的东西，llm-jury 是**已经决定**裁决属于证词——再跑机器检查会让一条机器记录悄悄覆盖（或洗白）断言从未请求的陪审。义务三条（id 固定）：`zero-regressions`（无机器记录时空真，诚实移交审议义务承担）+ `jury-delivered`（链上该 claimId 有 B 类**活动**裁决——任何裁决含 abstain 都算「送达」，是否帮到断言完全是下一条的事；只有 `attest/jury` 能满足，人类背书不能；无裁决时 detail 直接指路 `proof_jury` → `proof_jury_submit`）+ `jury-upholds`（活动裁决为 uphold 且 probability ≥ 0.5——0.5 是「断言为真概率」的一致性下限，低于它的 uphold 是陪审自相矛盾）。grade：义务全 met 且 Π factor ≥ `certifyTarget` 才 `proven`，否则 `stale`；basis：链上无活动证人或存在 B 证人 → `jury-only`（该路径本就没有机器记录），仅 C 证人 → `attested`。裁决摘要随 `claim/jury` 边界标记入链（claimId、gen、verdict、probability、factor、model、independence——完整 prompt/output 已在 attest marker 里，边界不重复倾倒）。**`verify()`（无契约路径）永不读 attestation**——v0.9 纯机器语义逐字节锁定（测试：链上种一条敌意 B 类 reject，verify 的 confidence / basis / grade / schedule 全部不变）。

**`ConfidenceBasis` 的两个新语义**：`attested`——机器证据与 B/C 证人融合后的数字（机器后验被逐证人混合，或无机器记录时纯 C 证人）；`jury-only` 从 v0.10 的 docs-only 专用扩展为「无机器记录的纯 B 路径」。叙事直说 regime：`PROVEN (p≈0.97, machine + B/C attested)`。

**三个新工具的用法**：

| 工具 | 参数 | 行为 |
|---|---|---|
| `proof_jury` | `claim`（必填）、`context`（可选，缺省时 CONTEXT 段为 `<no additional context>`） | 冻结审议 prompt（确定性拼装）返还给模型；请求落链 `attest/jury-requested`（含逐字 prompt 与其摘要） |
| `proof_jury_submit` | `claimId`、`verdict`、`probability`、`reasoning`（必填）、`model`（可选，默认 `'session-model (unverified)'`） | 校验裁决形状与请求绑定后，全包落链 `attest/jury`；gen = 链上该 claim 最高 gen + 1（**再提交即申诉**）；返回 `recorded` / `gen` / `factor`（默认策略的 p^0.7，全精度供第三方复算）与申诉指引 |
| `proof_endorse` | `claim`、`decision`（`endorse` / `reject`）、`approver`（可选，默认 `'host-approver'`） | pre-execute 恒 `ask`——人类批准才执行；落链 `attest/human`（scope 含断言全文与基线证据根）；再决定以 gen+1 超越 |

模型面进入 B/C 证据的入口就是这三个工具；融合发生在引擎的合约路径上（机器类 kind 的 `verifyContract` 读链上活动证人做混合/解锁，`llm-jury` 契约以证词积认证）。本版 `proof_claim` 的 `kind` 参数面板仍为 v0.10 的四类——`llm-jury` 合约由引擎合约系统定义并消费（§九 `05`/`18` 的引擎级测试直接经 `verifyContract` 驱动它）。

**诚实边界（详见 §十）**：v0.11 的独立性档位实际是三者中最弱的 `same-session`（宿主尚无隔离模型 seam，链上如实标注）；模型身份是提交方声明、插件无法验证；量规判断仍是主观概率；`humanProbability` = 0.95 与混合模型都是建模/评分规则选择，不是推导出的后验。

## 五·十五、PTC 证据合成（v0.12.0）：让断言的无检查地带获得构造出来的验证

到 v0.11 为止，一条断言若恰好落在没有任何现成检查的地方，出路只有两条：要么义务如实报 not met（`new-paths-covered` 的 detail 说「add a check whose paths cover them and make it pass」，可检查发现只认仓库自己声明的构建元数据与宿主显式配置——agent 写的测试文件进不了检查池），要么把断言降级成陪审自证。**没有现成检查的断言曾是死路。** v0.12 打开第三条路：**插件自己为这个缺口构造一个验证**——新模块 `src/core/synthetic.ts`（纯函数、零 I/O、零时钟）定义全部领域原语。角色随之改变：agent 从「被验证者」变成「参与构造证据的共谋者」，但边界同样清晰——**它只能左右测试的真值（断言写多严是它的自由），执行结果本身无法伪造**。

**两工具协议（conjure/run 二段式）**。第一步 `proof_conjure(claim, paths)`：插件冻结请求——断言全文与其 claimId（sha256 前 16 hex）、待覆盖路径、确定性的脚手架模板 `SYNTHETIC_TEMPLATE` 落盘到 `syntheticDir`（默认 `.proof-synthetic/synthetic-<claimId>-<seq>.mjs.template.mjs`，seq 只是防覆盖的碰撞保险，不携带任何身份语义），并把完整请求作为 `synthetic/requested` marker 上链——此时 `scriptDigest` 为 `null`，因为请求时还没有可哈希的东西；**先锁请求，正是为了让事后换脚本无处可藏**。模板自带确定性断言循环与固定末行协议（`SYNTHETIC: PASS` / `SYNTHETIC: FAIL: <原因>`），文件头第一屏就警告：这份源码将逐字哈希进它自己证据的 `scriptDigest`——删掉一条断言不是私人编辑，而是铸造新地址、旧 pass 就此失效。agent 照模板把属性测试/最小复现写进沙箱目录（WorkspaceWatch 溯源，作者归因为 `agent`）。第二步 `proof_conjure_run(claim, entry)`：插件按序防御——(1) 链上必须已有匹配的 `synthetic/requested`（无请求的执行正是「事后凭空造测试」这一步要防的动作）；(2) 脚本必须在盘；(3) 能力筛检必须通过——**拒收即返回 findings、status 为 `skipped`、不执行、链上不落任何东西**（被拒的测试除了它自己的被拒之外不证明任何事）。通过后经**插件自己的 CommandPort**（VerificationRunner）执行，记录带合成元数据重新寻址入链，`synthetic/run` marker 闭环。

**「共谋者但不可伪造」的三个结构答案**。1) **内容寻址**：脚本源码的 sha256（`scriptDigest`）连同沙箱档位、筛检结论、作者归因一起进入 `SyntheticEvidenceMeta`，参与 `evidenceId` 的内容寻址——「通过的测试」与「运行的源码」无法悄悄分家，弱化一条断言就是铸造新地址，同一输出的两个不同脚本是两条不同证据。2) **插件持端口执行**：执行走插件持有的执行端口，agent 的工具面碰不到执行结果——它能写空断言（这是 β 定价的），但伪造不了一个没跑过的 `SYNTHETIC: PASS`。3) **marker 闭环**：请求先于脚本上链（digest 为 null），执行时对盘上现状重新哈希——两步之间被调包的脚本只能以它**自己的** digest 运行，可见。

**β 定价：把「自利测试」放进数学而不是禁令里**。合成检查的假阴率 β 从 0.02（organic，`BAYES_CONSTANTS`）升到 `syntheticFalsePass`（默认 0.15，7.5 倍）——测试作者是断言的利害关系方，「写个必过的空测试」这一最廉价的假 pass 不是机械事故而是遗漏，0.02 定价的是独立维护者的套件，这里必须另定价。闭式更新 P(healthy | pass) = π(1−α) / (π(1−α) + (1−π)β)：同样的历史（1 次运行 1 次通过 → π = 5/6，α = 0.01）、同样一次 pass——organic 后验 ≈ **0.9960**，synthetic ≈ **0.9706**（端到端测试逐字断言了这个不等式与 basis）。α 与 π 不受影响：合成检查照常从历史学 flake 与失败倾向，折扣定价的是**谁的手写了断言**，不是传感器其余的行为；失败的合成检查照样定罪——折扣只定价自写的 pass。该默认值刻意**不**放进 `BAYES_CONSTANTS`（那是「不再重调的定律」）：它是承认的建模猜测，故经 `PriorInput.syntheticFalsePass` / 配置可覆盖，有真值数据的宿主可以定价自己的经验。

**义务打通：tier ladder 与普通 spec 并池**。`behavior-adding` 的 `new-paths-covered` 接受合成覆盖，但按档位让路：**当次 organic run > 当次 synthetic run > 链上最新 organic > 链上最新 synthetic**（新鲜胜陈旧、独立胜自证——陈旧的独立证据强于新鲜的自证证据，兜底若开了门却拒收 organic 反而不自洽）。合成覆盖在 detail 里点名：`N covered by synthetic evidence (discounted)`。`verify()` / `verifyContract()` 把链上**已执行过**的 conjure spec 以普通 `CheckSpec` 并入检查池（`source: 'synthetic'` 是唯一特殊处，选择/定价/重执行一切如常；只有请求没有执行的是 offer 不是检查，不会被悄悄执行）。

**`ConfidenceBasis` 的第六个语义**：本次运行的全部决定性记录都来自合成检查时，basis 为 `synthetic`——`full-coverage` 在此技术上为真、实质上误导（唯一说话的检查是断言作者自己写的）。优先序钉死：`jury-only > attested > synthetic > certified-subset > full-coverage > degraded`。叙事直说 regime：`PROVEN (p≈0.97, synthetic evidence — conjured tests, discounted)`。grade 本身绝不在 `synthetic` 上分支——β 抬升已在因子内部完成了定价。

**沙箱档位如实分档**。`SyntheticEvidenceMeta.sandbox` 是字面量联合 `'screened-subprocess' | 'ptc-runtime'`，v0.12 固定落 `'screened-subprocess'`——**静态筛检不是沙箱**，档位标签必须是观察不是愿望；宿主将来提供 ptc-runtime seam（在真沙箱运行时内执行）时切换档位，探测点已留。能力筛检是**deny-list**：`FORBIDDEN_CAPABILITIES`（`child_process`、`net`、`http`、`https`、`dgram`、`worker_threads`）的一切拼写（带/不带 `node:` 前缀、静态/裸/字面量动态 import、`require`、多行列表与 re-export）加上 `process.env` 读取（成员与计算成员形式）都在执行**之前**被拒；`fs` 刻意放行（读不了 fixture 的属性测试测不了任何东西，边界由 cwd 承担）。扫描跑在原始文本上、注释也扫——被注释掉的禁用导入照样报（deny-list 的安全方向是拒绝惰性脚本，绝不放过活脚本）；模板自身干净通过筛检（模块名只以不带引号的形式出现在警告散文里，筛检只匹配带引号的 specifier），所以提交脚本上的任何 finding 都来自作者自己的增改。

**与 v0.9 / v0.10 / v0.11 的咬合（四个子系统互相成就）**。v0.9 的调度器为合成检查定价（β 进 `computePriors`，VOI 排序与提前停一切照常）；v0.10 的合约把合成覆盖接受为 `new-paths-covered` 的兜底（tier ladder 明示折价）；v0.11 的 basis 体系把 `synthetic` 排在证词之后、机器基之前（读者必须知道唯一说话的检查出自谁手）；本版的请求/执行协议则保证进入这条流水线的每条合成证据都真的运行过、真的被筛检过、真的以逐字源码寻址。新配置三项：`syntheticDir`（默认 `.proof-synthetic`，钉进 `DEFAULT_IGNORE_DIRS`，永不进入检查发现——沙箱是验证的**输出**，不是能使验证失效的源输入）、`syntheticFalsePass`（0.15）、`syntheticTimeoutMs`（60000）。

## 五·十六、覆盖感知证明（v0.13.0）：跑过、绿、且真的执行过改动

到 v0.12 为止，`proven` 的语义是「跑过的都绿」——受影响的检查全部重跑、零回归、后验过线。这个定义里藏着一个报告读者**看不见的洞**：检查的 `paths` 匹配了变更文件，只说明**选择**认为该检查管这个文件；它不说明检查的进程真的**执行**了变更处的代码。一条测试套件可以全绿，而没有任何测试 import 改动所在的模块；一个 lint 可以绿着跳过新扩展名；一个 typecheck 在编辑之前就已经是绿的。「全绿」是关于**检查**的陈述，不是关于**变更**的陈述。v0.13 把 `proven` 从「跑过、绿」升维为「**跑过、绿、且真的执行过改动**」——第三维的证据由检查子进程自己留下，零插桩取数。

**零插桩取数：`NODE_V8_COVERAGE`**。验证开始前，引擎在证据库旁创建本轮的覆盖率暂存目录（`${storeDir}/coverage/<时钟 nonce>`——nonce 只是并发/顺序运行互不共享子目录的物理保险，刻意不进入任何哈希材料，运行身份仍是证据的纯函数），并为每个检查子进程注入环境变量 `NODE_V8_COVERAGE=<dir>/<sha256(checkId) 前 16 hex>`——Node 原生的 V8 inspector 覆盖率开关：**零插桩**（无 babel 钩子、无 import 改写、无 mock），继承了该环境变量的每个 node 进程——检查本身，以及它经 npm/.cmd 垫片与 scripts 派生的嵌套 node 测试进程——在退出时把原始 V8 覆盖率 JSON 写入该目录。跑完解析（新模块 `src/core/coverage.ts`，纯函数、零 I/O）：

1. **执行判定**：文件有任一函数的任一 range `count > 0` 即**执行过**；出现在报告里但全部 range 计数为 0 是**加载未执行**（分桶保留，v1 未用于更强判定）；进程从未加载的文件根本不出现在报告里。
2. **域过滤**：root 之外的一律丢弃（其他检出；`node:` 内部模块根本不以 `file:` 开头）；路径含 `node_modules` 段的一律丢弃——依赖代码被执行是**依赖**的覆盖率，不是本工作区变更被执行（按段匹配，pnpm 式嵌套 `pkg/node_modules/dep` 也抓得住）。
3. **URL 归一**：`file:///C:/…` 三斜杠与 `file://C:/…` 两斜杠双形态、百分号解码、Windows 盘符大小写漂移（盘符形态大小写不敏感比较、POSIX root 保持敏感）全部归一为工作区相对 `/` 路径。
4. **防御性解析**：垃圾 JSON / 形状不对（`result` 缺失或非数组）返回 `undefined`，按「没有报告」处理，绝不按「空覆盖」处理；同一脚本在报告里出现多次时执行压倒加载；空 `result` 不是 undefined——「进程没加载本工作区任何文件」本身就是信息。

对伪造 profile 的防御是**每轮隔离 + mtime 时间窗**（v0.22 加固：每轮验证在各自的暂存目录里收集，只采纳 mtime 落在本轮 `[spawnedAt, collectedAt]` 窗口内的 profile——窗口外哪怕一份，整轮覆盖即降级为 `basis: 'none'` 并落 `coverage/untrusted` marker）——它抬高的是伪造成本（从「继承环境变量」变成「在引擎自己的暂存目录里赢下与引擎时钟的赛跑」），**不是密码学保证**。这就是把「检查执行了什么」从声明变成观察的全部含义——以及这个观察的诚实边界。

**证据级附件：覆盖率参与内容寻址**。每条**决定性通过**的证据记录挂上 `coverage` 附件——该记录自己的运行与变更集的交集/差集（`changedExecuted` / `changedUncovered`）。与 v0.12 合成证据的 `scriptDigest` 同一纪律：**附件参与 `evidenceId` 内容寻址**——一条记录不能声称执行过它从未运行过的变更；同样的绿色输出、不同的执行足迹，是两条不同的证据。采集时序是承重的：**重新寻址发生在第一条 append 之前**——链上永远不会先出现 plain 记录、再出现它的 enriched 双胞胎（审计必须能从存储字节重算出恰好这个地址）。非决定性记录不携带附件：fail 自己就击沉了 grade，非决定性（timeout 等）可能在 V8 刷盘前就死了——半执行什么也证明不了。暂存目录**用后即删**（FsPort 新可选能力 `removeDir`；内存实现没有它也照常），删除失败只损失暂存卫生不损失证据——下次运行重建目录。

**门控语义：`unproven` 与 `stale` 的分界线**。`applyCoverageGate` 在 uncovered 非空时把 `proven` 降为 `unproven`，并把覆盖率摘要（basis + uncovered）**无条件**挂上报告——即便 basis 是 `'none'`、即便门没拦：「测不了」是证明读者应得的事实，不是可静默省略的字段。两个降级名词说的是两件不同的事：

| | `stale` | `unproven`（覆盖降级） |
|---|---|---|
| 判定种类 | **过程**判定 | **证据**判定 |
| 含义 | 验证没跑完（检查未跑 / 跳过 / 超时 / 中断） | 过程完成、全部绿——但绿的证据从未执行变更 |
| 重跑能救吗 | 能：把没跑完的检查跑完 | **不能**：缺的不是更多运行，是真正触达变更的检查 |
| 维度 | 检查侧（`unverified`：哪些检查没拿到裁决） | 变更侧（`uncovered`：哪些变更文件没被执行——`unverified` 的对偶） |

边界规则：`regressed` 与 `stale` **永不被覆盖门改写**——回归有自己的理由，stale 自己就挡住了 proven；只有 otherwise-proven 的运行才可能被降级。门控次序**钉死**：机器 grade 之后、义务封顶与 κ 背书融合之前——覆盖率是机器证据维度，与机器裁决一起受审；这个位置对融合语义是承重的：**被覆盖率打成 `unproven` 的断言不可能再被背书解锁**——解锁条件要求 grade 是 `stale`（人类能接受的剩余风险），而「变更从未执行」不是剩余风险，是缺失的工作，与未 met 的义务一样，背书买不了工作。

**三档模式（config `coverage`）与选择建议**：

| 档位 | 无数据时 | 有数据时 | 适用 |
|---|---|---|---|
| `observe`（默认） | 不拦，但 basis `'none'` 如实可见 | uncovered 非空 → unproven | 大多数部署：真实 Node 检查进程得到执行覆盖的诚实；数据缺失环境（fake 端口、非 Node 工具链）可见降级，而不是新增一种失败 |
| `require` | **也拦**（`no-coverage-data`）：无数据本身即不合格 | 同上 | 严格部署：已承诺覆盖率插桩存在，缺席即发现 |
| `off` | 不注入、不门控 | 不注入、不门控 | 逐字节回到 v0.12 行为 |

「生产行为与无数据环境分离」正是 observe 默认的来源——同一个运行要么拿着证据说话，要么显式说「我测不了」（这也正是 Fake 测试端口向后兼容的来源：Fake 命令端口不读注入的 env，observe 下无数据不拦，05 测试逐位核对了默认 observe 与 off 在 fake 端口上 grade / confidence / basis 逐位相等）。**非 node 生态按档选型**：pytest / go test 等进程不产 V8 数据——observe 不拦（永远不门控）、require 会拦（每条断言都 unproven），部署者按自己的生态选档。

**与 conjure 的咬合：盲区的处方**。未执行被点名时，模型收到的不只是坏消息，还有现成的出路——叙事直接提示 `proof_conjure` 可合成真正执行变更的测试：v0.12 的合成证据协议恰好就是「构造一个验证」的机器，conjure 一个 import 变更模块并对它断言的测试，跑过即真的执行了变更，盲区闭合。最说明问题的是一个真事：门控落地当天，**特性抓到了自己历史用例的盲区**——π（v0.12）的既有 conjure 测试用例被查出「脚本从未触碰变更文件」（绿色断言从未 import 它声称覆盖的模块），用例被改写为真正 import 并断言变更模块后才重新成立。选择维度说「这个检查管这个文件」、执行维度说「它根本没碰」——两条证据第一次同时在场，历史用例的缝隙立刻现形。

**叙事与展示**。执行过时评级行挣得尾注：

```
PROVEN (p≈0.97, change-executed) — 3 passing — 0 failing
```

未执行时 NOT PROVEN 点名前 3 个文件并给处方：

```
UNPROVEN (p≈0.97) — 1 passing — 0 failing — unexecuted change (src/feature.mjs) — proof_conjure can synthesize a test that executes them
```

（两个分支都要求 basis `'v8'`——basis `'none'` 时什么都没测过，点名「未执行」恰恰是这个维度要消除的不诚实。）`proof_verify` 的返回值新增 `coverage` 块（`VerifyValue.coverage`，仅在 observe/require 采集运行时出现，off 与旧 session log 无此字段——规范值字节稳定），渲染为紧跟置信行的一行**三态展示**：

```
coverage: change-executed (1 file(s) of the change observed running)
⚠ coverage: unexecuted change — src/feature.mjs never ran under any green check (paths matched, execution did not); proof_conjure can synthesize a test that executes them
ℹ coverage: no execution data this run (mode observe lets this pass ungated; mode require would not)
```

`VerifyOutcome.coverage` 同形透出（basis / uncovered / executedCount）；`proof/verified` 边界 marker 携带覆盖足迹（mode / basis / executed / uncovered）。

**工程细节**。`establishBaseline` **不注入**覆盖率（v1）：基线是对工作区检查的一次测量，不是对某个变更集的主张——此时没有「changed」可门控，跳过注入还省每检查一次磁盘写入；覆盖维度归验证所有。每检查子目录名用 `sha256(checkId)` 前 16 hex（specId 内嵌命令、可能带空格/冒号/整串 argv，不是每个平台都安全的路径段；采集方从记录自己的 checkId 重导出同一名字，无需 spec 池）。mkdirp 失败被吞：子进程写不出 profile、采集无数据、observe 降级 basis `'none'`——诚实的答案，而不是崩溃的验证。新配置 1 项（现 32 项）：`coverage`（默认 `observe`）；工具数不变（9 个）。新测试文件 `test/20-coverage`（26 例）+ `05` 增 4 例（真进程端到端 change-executed / **头条盲区实证**：paths 匹配但从不执行 → unproven 点名 / require+无数据、off 对照 / 向后兼容逐位）。


## 五·十七、开放标准与 MCP 服务器（v0.14.0）：证明走出本 harness

验证核心从此有了规范文本：**Agent Proof Protocol（APP/1.0）**——一份开放标准（[PROTOCOL.md](./PROTOCOL.md)，八节：Concepts / Vocabulary / Content addressing / Tamper evidence / Exchange format / Verification API / Security / Conformance），任何实现都能说，不必是本插件。方言被完整命名：五张线上词表（verdict 8 值、grade 5 值、check status 6 值、chain 3 模式、ClaimKind 5 类）、`sha256(canonicalJson(v))` 内容寻址、哈希链 + 签名检查点 + 带外锚点的防篡改证据，以及一个 **Proof Bundle 交换格式**——manifest（`protocol` / `appFingerprint` / `workspaceKey` / `createdAt` / `files[{path,sha256,bytes}]`）在前、`evidence.jsonl`（连同存在时的 `baseline.json` / `anchor.json`）在后；验证方对生产者**零信任**：重算每一份摘要、走链、复核逐条自寻址、解析锚与基线，一切不能从字节重导出的结论都拒绝。`appFingerprint()`（`src/app/protocol.ts`）把词表与三条承重规则字符串一起摘成**实现指纹**——词表值或规则任何一变，指纹必变；消费方对指纹复现不出来的 bundle 只能拒收，不许猜方言。

与标准同时落地的还有 **Proof MCP Server**：`dsh-proof-mcp` bin（检出目录里也可 `node --experimental-strip-types src/app/mcp-entry.ts` 直跑）是手写的 MCP JSON-RPC 2.0 over stdio 服务器，**零新增 npm 依赖**（运行时依赖仍然只有一个），恰好暴露五个一致性工具——`proof_status` / `proof_baseline` / `proof_verify` / `proof_claim` / `proof_bundle`，全部经环境变量配置（见 §五·十八）；`kind` 非法时报错而不是静默回退（与 DSH 工具面的刻意差异），jury / endorse / conjure 三族刻意不上 MCP 面——宿主审批 seam 与会话上下文不是一台开放服务器能假设的东西。

**H1 信任加固（本版安全修复）**。检查点的 `count` 从此必须是安全整数、且等于走链实数的记录数（新增 `malformedCheckpoints` 审计通道）——伪造的小 count 曾能把检查点窗口抹成零、把截断洗白成「全覆盖」，如今对账只认链上实走数；rewind / 锚比较只采信锚 keyId 匹配的可验证检查点——伪造检查点（外来 keyId + 虚报 count）不再能洗白链重写（新对抗用例 THE ADVERSARY II，连同貌似合理的 `anchor.count + 1` 伪造、Infinity/负数/小数 count、外来 key 顶替锚点共 5 例进 `09`）。测试 388 → 424：`test/21-protocol` 把词表逐字钉死并与核心实际产出交叉核对、`test/22-bundle` 以篡改矩阵攻击交换格式、`test/23-mcp` 以真实子进程驱动真实服务器；`src/app/` 新增五个模块——protocol、bundle、mcp-server、mcp-entry，外加供 lib 使用方导入的 `index.ts` 桶文件。

## 五·十八、MCP 快速上手

三步——服务器说纯 MCP JSON-RPC 2.0 over stdio，无需安装 DSH。

**第一步 · 安装**

```sh
npm i -g dsh-proof          # 或者不安装直接 npx dsh-proof-mcp
```

**第二步 · 在宿主里登记**。Claude Desktop（`claude_desktop_config.json`）：

```json
{
  "mcpServers": {
    "dsh-proof": {
      "command": "dsh-proof-mcp",
      "env": {
        "DSH_PROOF_ROOT": "/path/to/your/project",
        "DSH_PROOF_TRUST_DIR": "/path/to/trust/root",
        "DSH_PROOF_EVIDENCE_STORE": "host"
      }
    }
  }
}
```

通用命令行形态（任何能拉起命令的 MCP 客户端）：

```sh
DSH_PROOF_ROOT=/path/to/project dsh-proof-mcp
# 或直接从检出目录运行：
node --experimental-strip-types src/app/mcp-entry.ts
```

服务器**不读 `cordis.yml`**——每个旋钮都是环境变量：`DSH_PROOF_ROOT`（它验证的工作区根，默认 cwd）、`DSH_PROOF_TRUST_DIR`（密钥与锚点，默认 `$DSH_HOME/proof`）、`DSH_PROOF_EVIDENCE_STORE`（`host` | `workspace`，默认 `host`）、`DSH_PROOF_PTL_DIR`（v0.18 起的透明日志目录，供 `proof_publish` / `proof_log_verify`，默认 `<信任根>/ptl`）。协议版本协商接受 `2025-06-18` / `2025-03-26` / `2024-11-05`。MCP 侧全部走环境变量，不增减配置表（§八，v0.19 起 33 项，v0.21 维持不变——v0.21 的费率卡走 `proof_verify` / `proof_economics` / `proof_sla_quote` 的工具参数，不是配置）。

**第三步 · 首跑**。打开任意项目目录，让 agent 调 `proof_baseline`——发现的检查全部真跑一遍，签名链与锚点就此建立；再调 `proof_verify` 拿到带回归归因的分级裁决。`proof_claim` 声明完成并证明它；`proof_bundle` 打包 manifest + 日志，交给另一台机器或第三方。

注意：证词与合成工具**刻意不在 MCP 面上**——`proof_jury`、`proof_endorse`、`proof_conjure` 需要宿主持有的人工审批 seam 与会话上下文，开放服务器无法假设；它们留在 DSH 插件里，审批提示归宿主。

## 五·十九、宿主适配器（v0.15.0）：所有 agent 的公共基础设施

v0.14 让验证核心可以被任何 harness **说**；v0.15 补完定位升维——从「DSH 的一个插件」到**所有 agent 的公共基础设施**。任何宿主现在按三层接入，每层只做它做得动的事：**工具面 = `dsh-proof-mcp`**（上面的 MCP 服务器，一致性工具清单由协议版本冻结——APP/1.4 起为十三工具，仅此而已）；**执行面 = 宿主适配器**——pre 工具门（证据库守卫给出货真价实的 `deny`，基线门 `ask`/`warn`）、post 工具观察（工具调用实际动了哪些文件，观察时即留指纹——溯源）、回合/漂移检测（回合边界上拦截并点名工具流之外的改动，外加一次性的 baseline/verify 提醒）；**上下文面 = 注入**（SessionStart / `chat.params`）`proof:policy` 段落与工具指引——模型在第一次犯错之前就知道规则存在。工具服务器能跑检查；它拦不住一次工具调用、看不见调用落地、停不下一个回合——这道缝正是适配层补上的。

`src/adapters/shared/` 是宿主无关核心，三个模块。**`paths.ts`** 逐字镜像 engine 的私有推导，导出适配器需要的全部工件位置（日志、基线、锚点、会话目录）——适配器钩子与 MCP 服务器不共享地址空间（每次钩子调用都是一个独立进程），双方对「证据住在哪」的一致，只能靠推导规则的字节级相同；并顺手关闭 DSH 适配器一直没关的 H10 洞：这里的证据库守卫按**大小写不敏感**比较路径（Windows 上 `.PROOF/evidence.jsonl` 与 `.proof/evidence.jsonl` 指同一个文件；多拦一次调用，好过放走整条证据链）。**`session.ts`** 把 DSH 的观察器重写为可序列化快照——touched/read/指纹以 load-apply-save 的值形态存在、原子化落盘，因为「每个插件一个长寿对象」是 DSH 给你的家，逐钩子独立进程的宿主没有；漂移规则与 `observe.ts` 逐 case 对齐。**`gates.ts`** 把每个宿主都需要的三种判定收为纯函数（pre 工具、基线探测、回合结束评估），语义在能迁移处镜像 DSH 适配器、在宿主 seam 更强处刻意偏离——真实的 `deny`，而不只是 `ask`。

本版随附两个适配器。**Claude Code 适配器**是 `dsh-proof-cc` bin（`dsh-proof-cc <pre-tool-use|post-tool-use|stop|session-start>`），经 `.claude/settings.json` 钩子接线（[examples/claude-code.settings.json](./examples/claude-code.settings.json) 可直接粘贴）：PreToolUse 以 `permissionDecision` 的 `ask`/`deny` 应答，Stop 以 `{decision:'block'}` 应答、理由喂回模型（漂移每次 stop 重新武装，baseline/verify 提醒每会话一次性），SessionStart 注入 `additionalContext`；工具面经 `claude mcp add proof -- dsh-proof-mcp` 登记。**OpenCode 适配器**是一个 plugin（`lib/adapters/opencode/plugin.js`，由 `opencode.json` 的 `plugin` 数组点名），运行时鸭子类型探测自己的接入面——`tool.execute.before/after` 加 `chat.params`——并在该 API 持续演进期间优雅降级：探测不成已知形状的面留空、打一行 stderr，MCP 工具照常工作。OpenCode 没有 Stop 钩子，漂移锚定在**下一次工具调用**（外部改动后的第一个调用被持起并给出漂移叙事；每个不同漂移集每个插件生命周期至多浮出一次），持起形态为 `{error:{message}}`。已知盲区，如实说明：shell 命令字符串里的路径在任何宿主上都**不可提取**（DSH 也一样）——shell 造成的改动靠漂移检测兜底；OpenCode 没有回合结束 seam。测试 424 → 493（`test/24-adapters-shared` 27 例——对真实 engine 的推导字节对齐、大小写变体洞、会话即值、原子落盘；`test/25-cc` 23 例——真实目录上的处理器 + **真实子进程**上的真实协议；`test/26-opencode` 19 例——鸭子类型矩阵、下次调用漂移锚点、绝不向宿主抛异常的敌意上下文）；`src/adapters/` 新增三个目录——`shared/`、`claude-code/`、`opencode/`。

## 五·二十、适配器快速上手：Claude Code 与 OpenCode

上面的 MCP 快速上手给了任何宿主工具面。MCP 给不了的是强制——拦住一次工具调用、观察它动了什么、停下一个回合——所以 v0.15 随附两个宿主适配器。

**Claude Code**——每项目登记一次工具面，然后把 hooks 对象粘贴进 `.claude/settings.json`（项目级）或 `~/.claude/settings.json`（用户级）；带 matcher、全部可配置项与注释块的完整文件在 [examples/claude-code.settings.json](./examples/claude-code.settings.json)：

```sh
claude mcp add proof -- dsh-proof-mcp
```

```json
{
  "hooks": {
    "PreToolUse":  [{ "matcher": ["Write", "Edit", "MultiEdit", "NotebookEdit", "Bash"],
                      "hooks": [{ "type": "command", "command": "dsh-proof-cc pre-tool-use" }] }],
    "PostToolUse": [{ "matcher": ["Write", "Edit", "MultiEdit", "NotebookEdit", "Bash", "Read"],
                      "hooks": [{ "type": "command", "command": "dsh-proof-cc post-tool-use" }] }],
    "Stop":        [{ "hooks": [{ "type": "command", "command": "dsh-proof-cc stop" }] }],
    "SessionStart":[{ "hooks": [{ "type": "command", "command": "dsh-proof-cc session-start" }] }]
  }
}
```

**OpenCode**——合并进项目的 `opencode.json`（完整文件见 [examples/opencode.json](./examples/opencode.json)）；从检出目录接入请先 `npm run build`，再把 `plugin` 指向检出目录里的编译产物：

```json
{
  "plugin": ["dsh-proof/lib/adapters/opencode/plugin.js"],
  "mcp": {
    "proof": {
      "type": "local",
      "command": ["dsh-proof-mcp"],
      "environment": { "DSH_PROOF_EVIDENCE_STORE": "host" }
    }
  }
}
```

两个适配器（连同 MCP 服务器）都经同一组环境变量配置，门与工具永远守同一份证据库：

| 环境变量 | 含义 | 默认 |
|---|---|---|
| `DSH_PROOF_ROOT` | 要验证的工作区根 | 钩子进程的 cwd（即项目目录） |
| `DSH_PROOF_TRUST_DIR` | 信任根——密钥、锚点、适配器会话 | `$DSH_HOME/proof` |
| `DSH_PROOF_EVIDENCE_STORE` | `host`（证据放工作区外）\| `workspace`（`.proof`，受守卫） | `host` |
| `DSH_PROOF_EVIDENCE_DIR` | 工作区相对证据目录（仅 workspace 模式） | `.proof` |
| `DSH_PROOF_PTL_DIR` | 透明日志目录（MCP 服务器与 `dsh-proof-ptl` CLI 的两个透明日志工具；非适配器旋钮） | `<信任根>/ptl` |
| `DSH_PROOF_REQUIRE_BASELINE` | 基线门：`off` \| `warn` \| `ask` | `warn` |
| `DSH_PROOF_DRIFT` | `0` 关闭漂移检测 | 开 |
| `DSH_PROOF_ENFORCE_TURN_END` | `0` 关闭回合结束提醒 | 开 |

**再写一个适配器**——`src/adapters/shared/` 本身就是适配器 cookbook：`paths.ts`（一切工件住在哪，engine 字节对齐保证）、`session.ts`（观察即值，每个会话 id 一份快照）、`gates.ts`（三种判定的纯函数）。宿主特定代码刻意保持薄——翻译你宿主的钩子载荷、调用共享函数、渲染你宿主的应答形状——已随附的两个适配器就是参考实现：哪个宿主长得像你的，就抄哪个。

## 五·二十一、诚实性收口（v0.16.0）：这一轮到底观察到了什么？

v0.16 是一个**诚实性收口版**：对核心发出的每一个判定做一次深读审计，全部高优先问题一次修完。这些问题共享同一个形状：置信度词表早已建起来（grade、basis、先验——v0.9 到 v0.13），但它的两条消费线——grade 与 basis——都从没校验过「实际观察到了什么」。**先验不是观察（H2）**：一波验证零决定性观察，贝叶斯 verify 不再给 `proven`——降为 `stale`；certified-subset 提前停如今要求**本波**产出过决定性记录；非决定性记录留在 `pending`，不再被悄悄挪走；沉睡的 `runCheckIds` 字段激活，confidence 点名真正跑过的检查。**背书不是工作的替身（H3）**：`proof_endorse` 不能再为从未跑过、或被覆盖门拦下的检查付费解锁——风险接受如今以工作完成为前提（`unverified = 0` 且门未拦），对应测试叙事同步反转。

**检查定义本身成为证据（H5）**：基线为发现的每个 npm 脚本体锚定 `scriptDigest`，verify 逐个比对——漂移的检查强制重跑、按 synthetic 档（falsePass 0.15）折价、summary 里点名警告一行，「agent 偷偷改 test 脚本」的攻击面闭合；基线锚定过、发现池里却**消失**的检查如实上报并阻止 `proven`，「删掉失败检查的定义」的攻击面闭合。**失败即闭合（H6）**：git 查询失败从「静默空答案」改为 throw→降级→强制全量验证（假 proven 方向堵死）；基线快照时的 git 失败以 `snapshotDegraded` 附件透传。**超时成为被观察的状态（H7）**：命令端口上报 `timedOut` 标志，真实超时在两个平台上都记 `'timeout'`——此前生产端口报告不了这个死因、真实超时全被记成 `error`；全套件首个真实超时测试就此落钉。

其余清剿同一纪律：API 面提取不再漏掉 `export const x: number = 1`、解构类型注解不再产出幻影名（H4——behavior-preserving 对惯用 TS 重新成立）；观察器的 `pathsIn` 数组分支不再绕过键白名单（patch 行 / argv 数组不再被误当路径），本会话用过 shell 后，touched 集之外的变更归因从 `external` 降为 `unknown`——宁可归因不了，也不误指外部（H9）；`.PROOF` 大小写变体与反斜杠配置不再穿透工作区证据守卫（H10）；签名私钥读失败仅 ENOENT 才生成新钥，杀软瞬时锁不再触发静默轮换（H11）；预算耗尽或超时的基线拒绝锚定、落 `aborted` 标志（H12）——半真基线不再上链；`proof_endorse` 审批提示显示 agent 自报的 approver 名，冒名至少可见（M5）；verify 与 baseline 强制重发现，中途加脚本无法静默逃逸（M7）；config→engine 透传补上最后三个缺口——`lspQueryBudget`、`logger`、`verbose`（M14）。测试 493 → 543（+50），零新增配置键：scriptDigest、vanished、timedOut 都是内部观测字段，不是旋钮。

## 五·二十二、剩余缝隙全部收口（v0.17.0）：数学实际说了什么，测试实际没测什么

v0.17 接续 v0.16 收尾：对核心发出的每一个判定做同一场深读，这一轮把深读报告的中优先批次全部清零，连同审计顺带暴露的测试基建缺口一并补上。最大的一处在调度器本身（M3）：贝叶斯更新曾从各因子的**原始先验**而非**当前值**出发，折叠因子域因此漂移（E[p₁] ≠ p₀，差 13.5pp），一条已经失败过的检查，重跑价值被低估 61%——你最想重跑的那条恰好被排成最不值得跑；排序数学如今在全因子域上精确。置信度词表不再小处说谎（M4/M10/M13）：工具层不再丢弃 `synthetic`/`attested`/`jury-only` 基数，canonical 值不再携带「没有基数的概率」（ClaimValue 带 basis 与 regime 短语）；llm-jury 断言不再因为接受了人类背书而被惩罚——endorse 是风险接受不是证据，它只能让乘积不变、绝不变差，reject 的否决权原样保留；越界的陪审概率如今在两层裁夺上都让整条证词不可用。

工具面的静默一律改为保守或可见（M5/M6/M8/M9/M15/M18/M19）：`proof_claim` 缺 claim、非法 kind 干净报错，不再静默降级到无契约路径；`FsPort.walk` 返回 `{files, truncated}`，>2000 文件的工作区图不完整时 `graph.truncated=true`，选择判 uncertain 全跑——此前静默漏掉的导入方会造出假 `proven`；`src/**/*.ts` 这类不支持形状过包含全跑，不再静默永不匹配（死检查是披着绿字的谎话）；锚文件存在但不可解析浮出 `anchorUnreadable` 信号；signer 瞬时失败在引擎与存储两层重试、只缓存成功，恢复后签名自动回来，不再永久 unsigned 毒化；显式 `changed` 路径归一，反斜杠与 `./` 前缀不再误判 uncovered；`proof_verify.claim` / `proof_baseline.reason` 两个死参数接线进 marker，τ 门降级文案区分病因、`anchorMismatch` 进结构化输出与横幅同批落地（M19）。`canonicalJson` 按构造单射（M17）：bigint/symbol/function/`Date`/`Map` 等奇异值抛 `TypeError`，不再折叠成与别的值相同的字节——两个不同的 payload 不再可能铸出同一个 evidenceId；非有限数维持 legacy 折叠，并显式 pin 为决策而非事故（见 §十）。合成筛检堵上三类绕过（M11——反引号模板、Unicode 转义、`node:` 前缀拼写的 `process`），`SYNTHETIC: PASS` 末行协议强制校验（M12）：空脚本 exit 0 不再计为 pass。

审计还抓住了测试在装样子：audit 五通道（`badCheckpoints`、`headMismatches`、`unsignedCheckpoints`、`anchorMismatch`、`corruptLines`）如今真实触发覆盖——`08` 的 fakeAudit 是伪装成覆盖的格式化器测试；`fuseConfidence` 首次获得直接单测；`MemoryFs` 计数 `mtimeMs`，LSP 缓存失效从此可测。测试 543 → 584（+41），配置维持 32 项（零新增）：以上没有一样是旋钮。

## 五·二十三、证明检查点的透明日志（v0.18.0）：交付历史从此可被公开核验

v0.18 之前的一切证明都发生在*单个工作区内部*——链、检查点、锚点。v0.18 把目光转向外部，回答企业审计的那个问题：「agent 交给我一份绿色的 bundle；谁证明我看过的历史在*事后*没有被悄悄改写？」答案是把 certificate transparency / sigstore 用在证书与签名上的那套打法搬到 agent 交付证据上：一条 **Proof Transparency Log（PTL，证明透明日志）**——追加只读、哈希承诺、可公开核验的已签名检查点公共日志。发布即镜像，不是重推导：工作区最新的签名检查点 `{count, head, at, sig, keyId}` 原样落为一枚 Merkle 叶（RFC 6962 树；叶哈希 `SHA-256(0x00 || canonicalJson(entry))`——规范化字节，任何语言的任何实现都重算出同一棵树），日志操作者在每次追加后对整棵日志签一个**签名树头（STH）**，操作者密钥刻意与工作区链签名密钥分离（`logId` 即操作者 keyId）。从此任何只持公开数据的人都能核对审计者真正需要的三件事：**完整性（completeness）**——RFC 6962 包含证明，*这条*交付的检查点确实在日志里；**时序（ordering）**——序号只增、STH 时间戳不回退（缩小树、同尺寸换根、回拨时间戳的新头一律拒绝落盘）；**不可回溯（immutability）**——RFC 6962 一致性证明，每一个旧签名树头仍可从每一个新树头导出，截断或改写过的历史无法复现操作者已经签过的根。

日志是**哑公证**，这是明说的原则：它逐字托管工作区签名、从不去验证它——拿工作区公钥裁定那个签名始终是审计者的工作，与「发布过程是否清白」是两个独立问题。一个核心，三面接入。**引擎**长出 `publishCheckpoint()`（`ptlDir`；按叶哈希幂等——重放同一检查点是同一事件而非新事件，重复发布永远无法给树注水；单飞队列串行化，并发发布不会双追加）。**MCP 服务器**新增 `proof_publish` / `proof_log_verify`——这就是 **APP/1.0 → APP/1.1** 升版的全部内容，而且是一次诚实升版：协议工具面 5 → 7，`PROTOCOL_VERSION` 本身是指纹材料，1.0 消费方拒绝 1.1 manifest，而不是去猜它从未同意过的工具语义；其余分毫未动——寻址、链与 bundle 格式逐字节不变，旧 bundle 的可验性一如往昔。**独立 CLI**（`dsh-proof-ptl append | head | verify`；检出目录里 `node --experimental-strip-types src/app/ptl-entry.ts` 直跑）给非 MCP 审计者同样的能力：`verify --bundle` 依序跑四检 `leafMatch → inclusion`（对 bundle 钉住的**发布头**，不是当前头）`→ consistency`（发布头 → 当前头）`→ headSignature`，任何失败都点名坏在哪一检。bundle 增加可选的 `transparency` manifest 记录（`{logId, sequence, leafHash, publishedHead, inclusionProof}`）：`verifyBundle` 只做结构校验，日志级证明归日志——三步审计指南见 [examples/ptl-workflow.md](./examples/ptl-workflow.md)。配置维持 32 项：透明日志是部署物不是旋钮——由环境变量 `DSH_PROOF_PTL_DIR` 寻址（默认 `<信任根>/ptl`，与密钥同侧，在它为之发布的所有工作区之外）。

领域层是 `src/core/transparency.ts`——RFC 6962 §2 / §2.1.1 / §2.1.2 的递归直译，验证器写成生成器的精确镜像，用 RFC 自己的 §2.1.3 工作例逐字钉死，并以一套独立朴素实现对全部树形 n = 0..33 与 178 对一致性证明做差分测试。诚实边界，如实写出：v1 是**单操作者文件日志**——密码学保证的是日志自身历史不可被无感改写（改一字节根必动、截断树必缩，二者都过不了签名树头或一致性证明，回退防护再拒一层），但**不**保证抓到向不同验证者出示不同树的**分叉视图（split-view）**操作者；抓它需要多见证或审计者间 gossip——完整的 CT 答案，明确列为 future work，不是本版的属性。对拿它对接审计框架的采购团队，口径刻意克制：PTL 提供的恰是这类框架要的三件证据原语——completeness、ordering、immutability——这是证据/可审计性对话（含 NIST 正在形成的 agent 安全标准化方向）的**入场券**；本项目声称的是能力对齐（alignment），绝不是合规（compliant）或认证（certified）。测试 584 → 632（+48：`test/27-transparency` 25、`test/28-ptl-cli` 12、`05` 五例引擎发布、`23` 两例 MCP 工具、`22` 三例 bundle 记录、`21` 的 1.1 指纹钉死）；`src/` 新增 `core/transparency.ts` 与 `app/ptl-entry.ts`。

## 五·二十四、跨代理责任 DAG（v0.19.0）：多智能体系统的可追责信任拓扑

v0.19 之前的一切证明的都是*单个工作区里的单个 agent*。而一旦编排者开始**委派**，证明就退化成糊涂账：父任务把工作发下去，子代理回报「做完了」，父任务的裁决便默默继承了一份自报——而且来自最希望它被相信的那一方；谁欠谁什么证明，账本一团浆糊。v0.19 用**责任 DAG（Responsibility DAG）**取代糊涂账：被委派的任务携带**证明义务（proof obligation）**，父任务的 `proven` 以*全部子任务 `proven` 为前提*，图的每条边都是任何人都能从字节重验的 proof bundle——多智能体系统第一次有了可追责的信任拓扑。

领域层是 `src/core/obligations.ts`（纯函数、确定性、零 I/O）。`TaskObligation` 在委派时铸造——子代理必须使其为真的 claim、可选的验收标准、发行方工作区、父任务——其身份按 claim 的同款做法内容寻址（`obligationIdOf`：规范化记录 sha256 的前 16 hex），改写 claim 即铸造新义务，绝不静默改旧账。合成整张 DAG 的是严格优先序的**合成格**：①**伪造与 regressed 压倒一切**——*声称* `proven` 但 bundle 验不过的子任务是**伪造（forgery）**，在父级记 `regressed`，且**任何豁免都买不动它**（豁免只解缺工作，绝不解坏工作/伪造——与 v0.11「背书买不了坏工作」完全对称）；②任一未豁免的*缺工作*子任务（未提交、`stale`、`unproven`、`no-baseline`）把父级拖为 `stale`；③全部子任务 proven 或已豁免时，父级 grade 取其**自身**证据——纯委派者（自己无证据）为 `proven`，自己没有可失败的东西。合成对整棵子树递归进行并带备忘录（被两个父任务共享的孙任务只合成一次、对两者答案一致——菱形），而义务只能被提交的 bundle 或豁免解除——**绝不**被绿色子树单独解除：领了义务却什么都没交的任务，哪怕子树全绿，在父级仍是 *unsubmitted*，因为没有人证明过**它**的 claim。

**DAG 的每条边是一个 v0.14 bundle。** worker 在*自己的*工作区里证明义务——`proof_baseline` → 干活 → `proof_verify`/`proof_claim` → `proof_bundle`——把导出物交回来；编排者以零信任 `verifyBundle` 裁决（摘要重算、链重走，提交方说什么都不信），`bundleFingerprint`（manifest 文件摘要列的顺序无关哈希）锚定这次提交到底站在哪些字节后面——v0.14 的交换格式在这里兑现。引擎长出四个动词：`delegateTask`（铸造 `task-<n>`、拒绝不存在的父任务、`detectCycles` 纵深防护、`delegation/created` marker 落链）；`submitDelegation`（`verifyBundle` 的裁决成为 `artifactVerified`；`claimedGrade` 缺省刻意两值——验过且带基线 → `proven`，其余 → `no-baseline`——细等级是提交方必须*显式声明*的工作区本地判断，而声明了 artifact 撑不住的等级按伪造定价）；`taskVerdict`（从 marker 重建全图递归合成；父级自身证据经 `ownGrade` 注入）；`waiveDelegation`（记名的风险接受——`by` 与 `reason` 必填——只记账；豁免抬不抬得动裁决是合成格的事，对伪造与 regressed 由语义拒绝）。

协议升版 **APP/1.1 → APP/1.2**——又是一次纯工具面扩张，7 → 10：`proof_delegate` / `proof_delegate_submit` / `proof_task` 加入 MCP 一致性面；寻址、链与 bundle 格式分毫未动，指纹按构造移动（`test/21` 当时钉死三代指纹——1.0、1.1、1.2 互不相认；v0.20 钉到第四代）。`proof_delegate` 返回 `instruction`——可直接粘进 worker 初始 prompt 的移交文本，写明 claim、验收标准、worker 侧的五步协议，以及那句让拓扑成真的话：*你的 "proven" 是父任务 "proven" 的前提*。角色一行说清：编排者说 `proof_delegate` / `proof_task`；worker 说 `proof_verify` / `proof_bundle` / `proof_delegate_submit`；第三方审计者说 `proof_log_verify` 与 bundle 自己的字节。dsh 侧另有实验性 **agent-team 桥**（`src/dsh/agent-team.ts`，经 `agentTeamBridge` opt-in，默认 false）：dsh 已发布的插件类型尚无 team 接口，桥在运行时对 4 个候选事件 seam 做鸭子类型探测（`agent/team:delegated`、`agent/delegation`、`team/task-created`、`agent/subtask`——每个订阅各自 try/catch），每个事件从 `unknown` 收窄（证明不了自己形状的被跳过，绝不被猜测），探测命中即把委派镜像为链上签名义务、并把 worker 移交 `instruction` 写回宿主能把内容送到子代理的通道。桥内任何路径都不向宿主抛异常——失败降级为一行 stderr，显式工具始终是第一等路径；实验 seam 绝不惊扰没要过它的部署。

测试 632 → 668（+36：`test/29-obligations` 20——全量合成矩阵、递归、菱形、环检测；`05` 引擎六例——诚实/伪造/豁免/参数防御/三层传播/marker 事实；`23` MCP 五例——移交文本、提交前总览、诚实 bundle proven、伪造 bundle 点名归责、畸形用法拒绝；`08` 插件接线五例——agent-team 桥：事件防御性收窄、委派镜像+instruction 注入、seam 探测优雅降级、opt-in 默认不动、移交文本内容）；`src/` 新增 `core/obligations.ts` 与 `dsh/agent-team.ts`。配置 32 → 33 项——唯一的新键是 `agentTeamBridge`（默认 false）：责任 DAG 本身是协议不是旋钮，唯一的旋钮是实验桥的 opt-in。

## 五·二十五、训练数据飞轮（v0.20.0）：部署本身在积累数据资产

到 v0.19 为止，一切价值都在**使用时**兑现：验证过的完成、归因好的回归、可审计的委派。v0.20 把同一份日志一直在悄悄积累的第二份资产捡起来：**诚实工作的副产品——带标签的 agent 行为数据集**。日志里的每一条记录都是 (检查, 变更集, 证据, 判定) 四元组，而判定是哈希链保护下的机器验证基线差分——**客观标签，不是模型对自己的自评**。一个部署只要在证明自己的工作，就无论有意无意都在积累「带真值标签的 agent 轨迹数据」——这类数据通常要花人工标注预算去近似，在这里是诚实工作的免费副产品。

**飞轮的在线一半从 v0.9 就在转**：贝叶斯调度器已经在从日志学每个检查的 flakiness 与成本——部署验证得越多，调度先验越准（用得越多，调度越聪明）。v0.20 装上**排气阀**：积累的数据从此可以离开机器，成为可导出、可验证的数据集（新纯领域模块 `src/core/training.ts`，schema `dsh-training/1`）——这是数据网络效应的**诚实版**：资产是使用的副产品、随使用复利增长、且归**部署方**所有。

**一个 schema 两种样本。** **verification** 样本——一条决定性观测：检查、变更集、判定，加上该判定按成文惯例表挣得的标量 `reward`（`VERDICT_REWARD`，刻意不是旋钮，逐 manifest 快照）：记功 `still-passing`/`fixed` 1.0，中性 `new-check`/`still-failing` 0.5（预置失败不是 agent 的错——记 0 与记 1 同样不诚实），记账 `regression`/`new-failure` 0.0——而 `indeterminate` **根本不进数据集**：未知不是零，一次真实的 pass 被当成回归惩罚，比没有数据更糟。**flip-pair** 样本——同一检查决定性子序列里的一次相邻 fail↔pass 分歧，按 DPO 固定方向装订（`rejected` 恒为 fail 侧、`chosen` 恒为 pass 侧；时间方向保留在两个 `recordedAt` 里）——日志免费铸造的偏好对。

**隐私与因果纯度是缺省，不是要记得做的功课。** `private` 保真档（缺省）导出**零输出字符**——只有结构、标签与 digest——数据集可以在任何人读完它每一行之前就离开机器（`full` 档补上归一化摘录、截到 200 字符；降级方向永远是沉默，绝不是泄漏）。`agent-only` 溯源过滤（缺省）在变更集里出现**一条**外部归属路径时，**作废整个会话的 verification 标签**——reward 1.0 断言的是「agent 的编辑让套件保持绿」，而人类同时也在改工作区时这句话为假——flip-pair 不受作废影响（同一链内的 pass-then-fail 是关于检查的时间事实，无论哪只手动了文件）。manifest 即使（恰恰）在被过滤成空时也如实记录所用过滤器。

**数据集内容寻址、链上锚定。** 每个样本的 `sampleHash` 是其规范化摘要的前 16 hex；manifest 的 `root` 是全体样本地址的 Merkle root——改一条样本的一个字符，root 即变，数据集无法在事后被悄悄改标；两份导出不信任任何导出方即可比对。reward 表作为**快照**随 manifest 走（没有铸造法则的数字是无标签数据），每次导出再以 **anchor** 锚定——导出时刻最后签名检查点的 `{count, head, keyId}`（无签名链则诚实无 key 地取最后一个良构检查点）——持有日志的消费方重导出 root 对得上，对不上就知道手里是另一条链。引擎动词是 `exportTrainingData`（`path` 选项把 JSONL 样本与 manifest 文档原子落盘）；MCP 面是 `proof_training_export`——这就是 **APP/1.2 → APP/1.3** 升版的全部内容（10 → 11，同一诚实条款下的又一次纯工具面扩张：其余分毫未动、指纹按构造移动、`test/21` 现在四代指纹字面钉死）。样本本体**永不进 MCP 响应**——只有 manifest、anchor 与 `sampleCount`；要样本就传 `path`，`writtenTo` 告诉你 JSONL 落在哪。

诚实边界，本节说一遍、清单里留三条：reward 表是**成文惯例不是客观真理**——标签底下的判定是机器验证的差分，1.0/0.5/0.0 的定价是声明的政策；flip 配对是**相邻启发**（相邻指导出日志决定性子序列里的相邻，不是说两次观测之间世上什么都没发生）；**跨部署合并数据集的信任问题未解**——这是谁的数据？被投过毒吗？把数据集来源锚进透明日志（防 data laundering）是未来方向，不是本版的能力。

测试 668 → 685（+17：`test/30-training` 8——全部判定类别与两个翻转方向的真值排气、reward 表钉死、private/full 保真、外部作废、确定性、样本寻址、空日志；`05` 引擎六例——端到端导出（flip pair/counts/root/anchor）、缺省 private、缺省 agent-only 与无溯源数据的诚实降级、`path` 落两个文件、注入时钟确定性、空链；`23` MCP 四例——private 缺省且样本不上线、full+`path` 写出 JSONL、非法枚举大声拒绝、参数面钉死）；`src/` 新增 `core/training.ts`；配置维持 33 项——飞轮是协议，不是旋钮。

## 五·二十六、验证经济学（v0.21.0）：信任的单位成本

到 v0.20 为止，一切都是让信任**可复算**；v0.21 给信任装上**单位成本**——一次验证花了多少钱、这些钱买到了什么、一个 `proven` 等级值得保多少。种子在 v0.9 就埋下了：贝叶斯调度器按**每毫秒期望信息增益**给检查排序——单位成本的确定性，当时是调度决策。v0.21 把这套隐式计量显式化为账本与报价。新纯领域模块 `src/core/economics.ts` 把钱可以诚实计价的两样东西——实测时长（每条记录的 `durationMs`）与消费掉的人工评审（B/C 证词，上游计数）——变成报表，再把 `proven` 等级变成保险式要约。

**运行账本。** 带费率卡运行的验证（`proof_verify` 的 `economics: {computePerMs, humanReviewPerItem?}`——MCP 面直接收；或引擎的 `VerifyOptions.economics`）返回——并落链——一份把该次运行重述为费用与购买声明的账本：`computeMs`（**全部**记录的实测时长之和——超时的检查同样烧掉了那些毫秒）、`cost`（费率卡注入、绝不硬编码——换卡，同一份证据重新定价）、`assertions`（决定性数：每条决定性检查答案是一个被验证的断言）与 `costPerAssertion`、`confidencePurchased`（后验 − 先验——这次验证真正**买到**的边际置信）、`confidencePerDollar`、`infoNats`（逐因子的带符号熵减之和，单位 nat——**花钱得知坏消息也是信息**，向失败折叠的因子诚实地记负号）与 `natsPerDollar`。账本的诚实纪律就是它的意义所在：`skippedCount` 让沉没成本可见，而不是把「花了钱没买到断言」藏起来；缺先验的购买是 `null`，绝不是零（没人定过价的购买不许假装发生过）；零成本的每美元比值是 `null`，绝不是 `Infinity`；每个金额舍入到六位小数，浮点尘埃永不进报表。

**SLA 精算——三扇门，没有第四扇。** `proof_sla_quote`（引擎动词 `slaQuote`）把带等级的证明变成 `dsh-proof/SLA-1` 的保险式要约：**`proven`** 等级 + [0,1] 内的实测置信 → **offer**——`premium = coverageAmount × (1 − confidence)`，残余风险（`pUndetected = 1 − confidence`）敞口的期望损失；`minPremium` 抬底，`deductible` 逐字透传、绝不折进保费。**没有第二个 β**：这里的置信在进门前已吸收全部假阴折扣（organic 0.02、synthetic 0.15），`1 − confidence` **就是**缺陷未检出的综合概率——再乘一个 β 等于给折扣打折、悄悄压低账面。**`regressed`** 等级诚实**拒保**——"the delivery failed verification"：给已知的损失卖保障不是承保。`stale` / `unproven` / `no-baseline`（以及没有实测置信的 `proven`）走**人工核保**——由人来接手，而不是发明一个数。每份报价按自己的定价内容寻址（`quoteId`：同输入同字节、保额改一分钱即是另一份报价、改写拒保措辞不重定价），并以 `economics/quote` marker 落链——报出的保费事后无法被悄悄改写。

**除外条款——诚实边界写进保单。** 每份报价逐字携带五条除外条款，它们全是本项目自己写进文档的盲区，如今重述为承保条款：shell 归因盲区（改写命令行藏住的缺陷）、单操作者透明日志（另一操作者手里的分叉视图）、检查点之后的尾窗（只有链覆盖没有检查点覆盖）、人类背书是风险接受而非验证事实、非决定性结果什么也没验证（它们没回答的面不在保）。**没人能引用的除外条款等于没人许过的承诺**——测试把五条逐字钉死。

**接缝在 MCP 面收口。** `proof_verify` 直接接受 `economics: {computePerMs, humanReviewPerItem?}`（边界大声校验——费率卡是宿主输入，负价与 NaN 一律拒绝、绝不带着算）；账本落 `proof/verified` marker（定价是**链事实**）；新纯查询工具 `proof_economics` 从链自己的字节**逐字回放**最近一条带账本的验证 marker——绝不重算价格、绝不采信调用方的转述，链上还没有账本时如实报缺省并附上确切的补救方法。协议升版 **APP/1.3 → APP/1.4**——第四次工具面扩张（11 → 13：`proof_economics`、`proof_sla_quote`），与前三次同一诚实条款：其余分毫未动、指纹按构造移动、`test/21` 现在**五代指纹字面钉死**。费率卡是**查询参数不是配置键**——配置维持 33 项；同一条链换卡即重定价，无需重新部署任何东西。合约三路径各有诚实口径：`docs-only` 诚实计零（无机器算力、无付费评审）；`llm-jury` 计它消费掉的证词（`humanReviewItems` = 该裁决实际依赖的 B/C 证人数）；机器路径把**最终**置信（κ 融合之后、等级实际依赖的那个数）作为账本的 posterior。

诚实边界，本节说一遍、清单里留三条：费率卡是**部署方注入的成本基础，不是真实账单**；`pUndetected` 是**模型概率，不是精算理赔史**；premium 是**示意性、基于模型的报价，不是金融产品**——`dsh-proof/SLA-1` 与训练 reward 表同一精神、同一限度：给残余风险定价的成文惯例。

测试 685 → 720（+35：`test/31-economics` 24——单位成本账本（算力/断言/置信/信息各按美元计）、null 纪律（零成本绝不除、缺先验绝不装）、带符号 infoNats、退化熵端点、沉没成本可见、六位小数金额规范、offer 数学精确、退化但合法的置信端点、minPremium 抬底、deductible 透传、一句话拒保、四路人工核保、五条除外逐字钉死、quoteId 寻址（保额一分钱即变、费率卡不入地址）、输入防御；`05` 引擎六例——贝叶斯验证端到端定价、预算耗尽的运行如实展示全部跳过且不购置信、`slaQuote` 链上确定性、`slaQuote` 边界拒绝且分毫不上链、机器合约路径以最终置信作 posterior 携带账本、llm-jury 裁决定价其消费的证词；`23` MCP 五例——定价 offer（保额 10000 × 置信 0.97 恰为 300）、诚实拒保、畸形用法大声拒绝、缺账本的确切补救、收口的接缝——定价 `proof_verify` 铸出账本、`proof_economics` 从链上逐字回放）；`src/` 新增 `core/economics.ts`；配置维持 33 项——定价随工具调用走，不是旋钮。

## 五·二十七、全量深读审计全部兑付（v0.22.0）：「自报即真」在哪里复生，就在哪里拔除

v0.16 与 v0.17 是对核心判定面的两轮深读；v0.22 把同一纪律一次性铺满整个代码库。**27 个 agent 的对抗审计逐行读完了全部代码**——`src/` 的 21,563 行与 `test/` 的 17,683 行——提交 34 条高危、85 条中危、68 条低危发现。汇总报告的元发现是结构性的，点名了三个反复复发的模式：修复只关「点到名的那扇门」（H3 的解锁枚举漏了 `vanished`，H12 的守卫漏了 `'error'`）；**信任决策点在每个新产品面重生**（PTL 发布、bundle 验证、委派、MCP 面各自重新发明了「自报即真」）；防御被「学习」或「邻道」悄悄侵蚀（β 折扣被历史先验复利冲掉、筛检被清单外的全局 `fetch` 绕开）。v0.22 关闭全部 34 条高危与绝大多数中危，且每处关闭都有测试钉死——720 → 857（+137），其中相当比例是对抗性用例：审计自己的 PoC 攻击（漂移体先验洗白、凭空捏造的委派 bundle、`reject@0.99` 抬置信）如今都是必须保持「攻不破」的可执行测试。

**主线一：每个新面都停止相信自报。** 委派提交从此要求**信任根**：`submitDelegation` 额外要求 bundle 的证据链携带签名检查点——本链有锚时点名义务铸造方的锚键（铸造方的锚就是子任务证明必须回答的根），铸造方从未锚定时至少要求某个良构签名检查点（签名是空日志伪造者唯一无法自给的东西）；无锚证据无论字节多自洽，派生等级一律封顶 `unproven`，并钉上 `bundle evidence not anchored` 问题。申报超过证据支撑的 `claimedGrade` 被封顶且差异记录在提交上；`ownGrade` 降级回它的本相——**申报**：`taskVerdict` 从链上的 `proof/verified` marker 派生本工作区自己的等级，高于派生值的自报被拒绝并写明理由。`waiveDelegation` 长出了授权：豁免的 `by` 必须解析到持有义务铸造方锚键的主机——其他任何人的豁免被大声拒绝**且留痕**，越权的豁免至少是个可见事件。PTL 栈在两个面上关了同一个洞：CLI 的 `append` 选点方式与引擎完全一致，且本地密钥与所选检查点的 keyId 匹配时，检查点签名在入树**之前**就被核验——外来 `keyId` 不再能借操作者之手公证化；`verify --bundle` 从四检扩为六检，裁定 bundle 钉住的 `publishedHead` 的签名与 logId（而不是解构即弃），缺席的 STH 不再算通过。而 `verifyBundle`——DAG 的零信任权威——如今把 `malformedCheckpoints` 镜像进问题清单，并在验证方持有点名密钥时**真的裁定**检查点签名；一条只是*携带*着没人核验过的 `sig` 字段的链，报告为新增的第四种链模式 `signed-unverified`——「有签名」与「签名被验过」是两个不同的主张，链模式不得免费替你做第二个。

**主线二：学习先验不再为被篡改的脚本体作证。** v0.16 的脚本漂移防御给漂移检查定价 β = 0.15——一次性——而学到的先验（旧体五次全绿后 ≈ 0.836）永远复利：`"test"` 脚本被改成 `node -e ""` 后照样借用旧体的绿色历史，单次伪造 pass 即越过默认 0.97 目标。两个动作关死它。漂移 id 的历史被**时间切片**：只汇总链上首次记录该 id 漂移**之后**的记录——首次检出时这样的记录不存在，id 以冷先验计价（ρ = 0.2，π ≤ 0.9，而任何 ≤ 0.9 的因子都把断言乘积压在 0.97 目标之下），此后**新脚本体**凭自己的记录逐次诚实地重新挣得先验。未审查的脚本体另有自己的 β（`driftedFalsePass`，缺省 0.5——高于合成档：这些字节替换了基线担保过的内容，出自握有该断言利益的手，无人筛检），新体单次 pass 落在 ≈ 0.94，肉眼可见地够不着 0.97：重新认证需要多次诚实观测或刷新基线，**「把测试改成空转」不再是一份证明**。同一套完备性纪律抵达了背书解锁（其枚举漏了 `vanished`、`scriptDrifted` 与基线完整性——被删除的检查定义、未重新锚定的脚本体、被篡改的基线都是缺失的工作而非残余风险，三者如今都不能解锁）与基线文件本体：`loadBaseline` 复算 `baselineId`，剥离一个字段（`scriptDigests`、`apiSurface`）——此前与「老版本基线」不可区分、静默关闭对应防御——如今触发 `baselineTampered` 并把等级封顶 `stale`。

**主线三：观察层不再对工具名与 shell 失明。** 工具名分类器曾是要求变异词被界定符包围的词正则——`MultiEdit` 与 `NotebookEdit`（Claude Code 真实存在、文档在案的变异工具）一个都匹配不上，而门是允许清单语义，失配即放行：workspace 模式下 agent 经这两个工具直写 `.proof/evidence.jsonl` 零拦截。分类如今是**锚定的整名清单**（大小写不敏感，未知名默认按 MUTATION 处理）——`MultiEdit`/`NotebookEdit` 与其他变异工具一样进 `deny`，`notebook_path` 与其他路径键一样被提取；反向的 bug 一并死去——`Read`/`Grep` 不再被误判为变异，读过的文件不再被记成「动过」，漂移检测重新生效。shell 命令字符串——v0.13 H9③、开天以来一直敞着的洞——如今在门上被扫：shell 类工具的命令字符串与证据库及信任工件（锚、密钥、host 模式证据库目录、两种工作区身份拼法）的一切拼法做文本匹配，保守处理。host 模式——**默认部署形态**——第一次在适配层有了结构化守卫：信任根已知时，以绝对路径写入 `<trustRoot>/workspaces/<key>` 的调用被拒绝并说明理由。诚实的边界保持诚实：**未知信任根的 host 模式仍不设防**——「证据库在沙箱之外」是共享门能够执行、不能凭空创造的宿主属性。支撑同一层的还有：`workspaceKey` 归一（同一目录的四种拼法不再裂成四个身份、四个锚），附迁移探测（发现旧键存量时 stderr 一行说明如何迁移）；适配器会话存储携带内容摘要（被篡改的会话文件被拒绝加载而不是静默吞下）；`DSH_PROOF_*` 环境契约收敛到唯一一处解析（`resolveAdapterEnv`，CC 钩子、OpenCode 插件与 MCP 入口共享——v0.21「设了变量、守卫看守幻影目录」的分裂已死）；OpenCode 的 before 钩子改为 **fail-closed**——抛异常的门调用持住工具调用，而不是挥手放行。

其余收口，逐项点名：**V8 覆盖**每轮独立暂存（时钟 nonce + 单调轮序号——并发与顺序运行永不共享目录），只采纳 mtime 落在本轮 `[spawnedAt, collectedAt]` 窗口内的 profile；窗口外一份即整轮覆盖降级 `basis: 'none'` 并落 `coverage/untrusted` marker——陈旧目录里预埋的伪造 profile 不再一票决定「执行过」。**训练导出**前置完整性审计（链过不了自己的 `audit()` 就拒绝——大声拒绝、分毫不写——然后才蒸馏第一个样本）、按当前基线锚点切片日志（锚定批次曾对着自己建的基线自比较，凭空铸出 reward-1.0 正样本）、同内容样本去重（绿工作区重复 verify 不再稀释 reward 表）；MCP 的 `path` 参数在**面与引擎两层**都被约束在工作区相对路径内。**经济学**长出输入域总闸：一切金额压在 1e15 资金上限下（舍入会溢出的输入在门口被拒、绝不带着算——quoteId 碰撞 PoC 已死）、grade 词表强制（外来等级走人工核保，绝不落 proven 分支）、非有限或负的 `durationMs` 记为 unknown，绝不上报表为数字。**矛盾证词**在解析时被拒：verdict 与 probability 方向不一致的陪审记录（`reject` 配 0.99）不再进入运算——此前数学只读 probability，一句宣誓过的「拒绝」反而把认证置信**抬过**目标。**合成筛检**追上 Node ≥ 18：零 import 即可出网的全局 `fetch`/`WebSocket`（连同 `cluster`/`worker_threads`/`dns`/`tls` 一族）进入 deny-list——最容易的外泄通道不再从只认 `require` 拼法的筛检眼前扬长而去。**Python 影响**终于解析当年绝对形态修复从未覆盖的三种形态（`from .mod import x`、带 `__init__.py` 候选的 `from . import x`、裸 `import pkg.mod`）。**进程树**在 POSIX 上整树回收（子进程成为自己的进程组长，超时击杀连孙进程一起带走——持有 stdout 管道的孙进程曾让整批验证永久挂起）；**LSP 查询**与墙钟期限竞速（挂死的语言服务器把依赖图降级为近似，不再挂死整轮）。协议侧长出**指纹祖先表**：验证方认可本族谱说过的每一种方言（APP/1.0–1.3，从活常量以只换版本字节的方式重算，绝非陈旧字面量）——五次升版不再孤儿化既有 bundle，旧 bundle 在今天的实现上照常验证、标记 `legacyProtocol`，而不相干的版本/指纹对仍被拒绝并点名两枚摘要。

诚实边界照例如下（本仓库家规）——审计**刻意留下**的三处：shell 命令匹配是**保守子串扫描**（改写后避开全部受卫拼法的命令仍可能溜过；守卫宁可误拦，漏过归因的仍由漂移检测兜底）；V8 覆盖防御是**隔离 + mtime 时间窗，不是密码学保证**（能把带窗口内 mtime 的文件写进本轮目录的进程仍能击穿它——v0.22 把伪造成本从「继承环境变量」抬到「赢下与引擎时钟的赛跑」，没有把它变成不可能）；未配置信任根的部署里，**PTL 操作者密钥可能仍落在它公证的日志目录旁边**（`<ptlDir>/ptl-operator-key`）——显式传 `--operator-key`（或设 `DSH_PROOF_OPERATOR_KEY_DIR` / 信任根）即可分离。

测试 720 → 857（+137，对抗占比很高：审计的 PoC——漂移先验洗白、凭空 bundle、`reject@0.99`、shell 直写证据库、`MultiEdit` 直通、覆盖 profile 预埋、quoteId 碰撞——如今全部钉成必须失败的可执行攻击）。配置维持 33 项——未审查体 β 走引擎级 `EngineOptions.driftedFalsePass`（缺省 0.5），是与 `syntheticFalsePass` 同层的可覆盖建模猜测，不进 cordis.yml；其余一切修复都是关上的门，不是旋钮。

---

## 五·二十八、统一验证读取（v0.23.0）：每个信任决策只走一扇门

v0.22 把审计账全数兑付——随后第二轮 **23 个 agent 的普查又逐行读完了结果**，提交 19 条新高危，其中 **42% 是修复自己引入的**。这个数字本身就是设计指令。反复发作的病从来不是缺少防御，而是**写了却没人咨询的防御**——没人递钥匙的验签器、没人读的审计裁决、恰好漏掉一个调用点的 suspect 过滤。所以 v0.23 不是再砌一层墙，而是三个让「砌墙却忘了开门」难以重犯的结构性动作。

**动作一：统一验证读取。** 一切信任消费者如今经同一个导出视图读链（`core/evidence.ts` 的 `createVerifiedView`）：单遍读取（一次走链完成 suspect 位置判定、可用即验签、代际回退——某 label 全部 marker 皆 suspect 的升级前旧日志，返回最后一条并带 `degraded` 标，而不是静默忘记整个部署的历史）。裸解析路径全部转 `@internal`——未来的消费者想接错线都找不到那扇门。经这扇门，v0.22 的四条最重死通道全部接活：`submitDelegation` 现在真把 `anchorSigner` 递给 `verifyBundle`（三态验签终于有了生产调用方）；引擎的漂移边界扫描与其余读者同样过滤 suspect；MCP 面的 marker 读取走同一视图；而 `audit().ok`——v0.22 的判定从未咨询过它——如今与 `baselineTampered` 同乘四路消费者：过不了自己审计的链铸不出 `proven`，无论哪个单一通道是干净的。

**动作二：纪元感知。** v0.22 的漂移时间切片问「链上何时首次记录此 id 的漂移」——这个答案跨越基线世代，drift → 重锚 → drift 的循环让每个新身体继承上一个身体重挣的历史。边界改为**世代化**：只有当前基线锚点之后的 marker 才算数；委派任务号从验证后的 marker 计数以 `max + 1` 派生，升级（或 suspect 清洗）不再把 `task-1` 回卷到既有义务上。同一纪元纪律关掉尾部吸收洗白：`preSignAudit` 拒绝为本进程从未写出的 `baseline/saved`/`baseline/established` 行公证（作者身份+位置双证），`savePtlHead` 拒绝延伸自己无法验签的存量头——**不确定=失败**，CLI 面、引擎面、bundle 面一视同仁，因为发布谓词处处都是「所选 checkpoint 验签通过，否则拒绝发布」。

**动作三：值扫描，不枚举。** 名单病饿死了。命令扫描不再枚举键名（`command`/`cmd`/`script`——v0.22 查了三个、漏了无数个）：变更类调用携带的**每一个字符串值**都过受卫拼法扫描——`{commandLine:…}`、`{code:…}`、argv 向量、还没人命名的键，全在同一张网里。路径层同样待遇：唯一的 `foldHostPath`（设备命名空间前缀剥离、盘符相对 `C:x` 投影、大小写、分隔符、尾点形变——曾经散在四份互不一致实现里的一切折叠）成为**唯一**折叠，守卫、DSH 面与引擎导出约束共同消费；`\\?\` 前缀与盘符相对写入不再掉进四份半吊子折叠的缝里。相对的 `DSH_PROOF_TRUST_DIR`/`DSH_HOME` 现在是响亮的启动失败，而不是把钥匙静默搬进工作区。

其余账目，逐项点名：**bundle 验证**镜像核心的 head-liar 检查（假链头上的**重放**签名判 `invalid` 而非 `verified`）、把搭载在最后一个 checkpoint 之后的记录从脚注升格为 problem、拒绝结构完好但记录为空的日志；**委派组合**不再把未提交叶子默认成 `proven`（没人证明过的叶子是 `unproven`）、own-`regressed` 的子不再被缺失兄弟洗成可豁免 `stale`——豁免赦免缺失的工作，从不赦免劣化的证据；**require 档覆盖门**的合成排除改锚定池成员身份而非记录字段（自删脚本如今记 `error` 不记 pass）；**贝叶斯旋钮域**在一切边界被校验（`driftedFalsePass:0` 不再把漂移防御反转成一发认证、`certifyTarget:0` 不再让门槛塌缩）；`proof_*` 工具调用豁免 OpenCode 的基线 ask（ask 曾死锁唯一能解开它的工具）；合成筛检抓计算成员与别名形态（`globalThis['fetch']`、`(0, fetch)`、`const f = fetch`）并拒绝 `node:vm`/`node:module`；Python 影响对带点 specifier 双向解析（`./x.component` 是文件名；`from . import x` 到兄弟而非祖父）加分号语句与括号导入表；漂移重挣阶梯按影响档如实记载——通配检查的新身体约 4 次诚实绿灯即重越 0.97，直改命中需约 13 次，这是诚实的数字，不是好听的数字。

全部的验收门：第三轮普查自己的 PoC 攻击对着这份代码**重跑**——九个里八个如今恰好死在它们曾经穿过的那道缝上（被吸收的尾部拿不到签名、伪造 STH 拿不到延伸、未提交叶子组合出 `unproven`、重放 checkpoint 报 `invalid`），第九个由其目标重写自带的纪元测试覆盖。测试 857 → 951（+94，绝大多数为对抗用例或 KAT）。诚实边界移动了但没有消失，清单在第十节如实更新：形状取证依旧拦不住可写日志上**形状合法**的追加——只有签名裁决能，而 v0.23 的赌注是：一扇永远被咨询的验证之门，胜过任何数量可能不被咨询的墙。

---

## 六、架构：领域核心 + 薄适配层

对齐 DSH 自己的「接口 / 实现 / 消费者」三分法：

```
dsh-proof/
├── src/
│   ├── core/                 ← 纯领域层，零 @deepseek-ai/* 依赖（21 个模块）
│   │   ├── ports.ts          # 唯一的对外接口（Command/Fs/Clock/Workspace/Signer/Resolver）
│   │   ├── hash.ts           # 规范化 JSON + 内容寻址 + Merkle root + 输出归一
│   │   ├── checks.ts         # 客观检查发现（多语言 + monorepo 子包 cwd）
│   │   ├── evidence.ts       # 证据模型 + append-only 事实源 + 基线 + 判定知识格
│   │   ├── impact.ts         # 反向依赖闭包 + 变更影响选择
│   │   ├── bayes.ts          # 贝叶斯验证调度（先验/后验/信息增益排序，纯函数）
│   │   ├── changeset.ts      # 内容锚定变更集 + 来源归因
│   │   ├── regression.ts     # 回归判定与嫌疑文件归因
│   │   ├── runner.ts         # 增量验证调度（并发/超时/预算/可取消）
│   │   ├── report.ts         # 证明装配与五档评级（含 docs-only 陪审报告）
│   │   ├── excerpt.ts        # 智能摘录（balanced / head）
│   │   ├── trust.ts          # 哈希链 + 检查点签名 + 带外锚点
│   │   ├── contract.ts       # 类型化断言合约（五类 kind 与义务、API 面提取/diff、docs 分类）
│   │   ├── attest.ts         # 证据分级 B/C（量规、陪审包、信任算术、申诉解析，纯函数）
│   │   ├── synthetic.ts      # PTC 证据合成（脚手架模板、能力筛检、合成 spec，纯函数）
│   │   ├── coverage.ts       # 覆盖感知证明（V8 报告解析、变更集聚合、unproven 门控，纯函数）
│   │   ├── transparency.ts   # 证明透明日志（RFC 6962 Merkle 树、包含/一致性证明、STH 与验证器镜像，纯函数）
│   │   ├── obligations.ts    # 跨代理责任 DAG（证明义务、递归合成格、环检测、bundleFingerprint，纯函数）
│   │   ├── training.ts       # 训练数据飞轮（dsh-training/1：verification/flip-pair 两类样本、VERDICT_REWARD 惯例表、隐私两档、agent-only 过滤、样本寻址与 merkleRoot，纯函数）
│   │   ├── economics.ts      # 验证经济学（运行账本：computeMs/cost/断言数/每断言成本/购置置信/信息 nat；SLA 精算：三扇门、premium=coverage×(1−confidence)、SLA_EXCLUSIONS 五条、quoteId 内容寻址，纯函数）
│   │   └── index.ts          # 领域导出
│   ├── engine.ts             # ProofEngine —— 宿主调用的命令式门面
│   ├── node-ports.ts         # Node 实现（spawn / fs / git / Ed25519）
│   ├── config.ts             # Schemastery 配置
│   ├── index.ts              # Cordis 插件入口
│   ├── dsh/                  ← 薄 Cordis 适配层
│   │   ├── tools.ts          # 九个模型可见工具（含 B/C 证词三工具、合成证据二工具）
│   │   ├── observe.ts        # 脏区追踪 + 漂移检测
│   │   ├── prompt.ts         # proof:policy 段落
│   │   ├── lsp-impact.ts     # 宿主 LSP → DefinitionResolverPort 适配
│   │   └── agent-team.ts     # 实验 agent-team 桥（opt-in：4 候选 seam 鸭子类型探测 + 优雅降级，永不炸宿主）
│   ├── app/                  ← APP/1.4 开放标准层（零 @deepseek-ai/* 依赖，任何宿主可实现）
│   │   ├── protocol.ts       # APP/1.4 协议常量：五张词表 + 媒体类型 + 实现指纹 appFingerprint()
│   │   ├── bundle.ts         # Proof Bundle 交换格式装配（manifest + 逐文件摘要重算 + transparency 记录）
│   │   ├── mcp-server.ts     # 手写 MCP JSON-RPC 2.0 服务器（恰好 13 工具，零新增依赖）
│   │   ├── mcp-entry.ts      # 独立进程入口：环境变量装配引擎，stdio 收发
│   │   ├── ptl-entry.ts      # dsh-proof-ptl CLI：透明日志 append | head | verify（非 MCP 审计者路径）
│   │   └── index.ts          # 桶导出（protocol + bundle + MCP 契约，供 lib 使用方）
│   ├── adapters/             ← 宿主适配层（三目录七文件，零 @deepseek-ai/* 依赖）
│   │   ├── shared/           # 宿主无关核心：paths / session / gates
│   │   │   ├── paths.ts      # 工件位置推导（与 engine 逐字镜像；证据库守卫关 H10 大小写洞）
│   │   │   ├── session.ts    # 可序列化会话快照（逐钩子独立进程的观察语义；原子落盘）
│   │   │   └── gates.ts      # 纯函数门：pre 工具（deny/ask）+ 基线探测 + 回合结束评估
│   │   ├── claude-code/      # Claude Code 钩子适配器
│   │   │   ├── entry.ts      # dsh-proof-cc bin：<pre-tool-use|post-tool-use|stop|session-start>
│   │   │   └── hooks.ts      # 四个钩子处理器（许可决策/溯源观察/漂移+一次性提醒/上下文注入）
│   │   └── opencode/         # OpenCode 插件适配器
│   │       ├── plugin.ts     # 运行时鸭子类型探测 tool.execute.before/after + chat.params，优雅降级
│   │       └── vendor.ts     # 宿主 API 形状收窄器（探测不到 = 留空不炸宿主）
│   └── vendor/dsh-tools.ts   # 契约快照（pinned to dsh v0.2.1-alpha.1）
├── test/                     # 31 个测试文件（951 个测试）：真实 shell 集成、信任对抗、变更集溯源、LSP 影响融合、智能摘录、位置无关寻址、Node 适配层、runner 直测、贝叶斯调度核心、类型化断言合约、证据分级 B/C、PTC 证据合成、覆盖感知证明、协议词表钉死、bundle 篡改矩阵、MCP 真子进程集成、适配器共享层字节对齐、Claude Code 真子进程协议、OpenCode 鸭子类型降级、透明日志 RFC 6962、PTL CLI、跨代理责任 DAG、agent-team 桥、训练数据飞轮、验证经济学、v0.22 对抗审计收口
├── PROTOCOL.md               # Agent Proof Protocol (APP/1.4) 开放标准（英文规范，十二节）
├── cordis.patch.yml          # bundle 层
└── examples/
    ├── cordis.yml               # --patch 本地调试
    ├── claude-code.settings.json # Claude Code 钩子接线（可粘贴进 .claude/settings.json）
    ├── opencode.json            # OpenCode 接入（plugin 数组 + mcp.local 配置）
    └── ptl-workflow.md          # 透明日志三步审计指南（agent 交付 → 操作者发布 → 第三方核验）
```

**为什么领域核心不碰 `@deepseek-ai/*`：**

1. DSH 是开发者预览版，破坏性变更频繁。核心逻辑与 harness 版本解耦 → 升级不重写。
2. **可测性**：`test/` 用内存 Fs、假命令端口、假时钟就能覆盖全部判定逻辑；`test/07-integration.test.ts` 再用**真实 shell** 跑一遍，951 个测试全绿。
3. 同一个核心可以被别的宿主（CLI、CI、其他 harness）复用。

**为什么 `vendor/dsh-tools.ts` 是契约快照而不是活依赖：**

DSH 官方原话：「一定会有破坏兼容性的变更」。把用到的契约面最小化并钉死版本，比跟着 latest 跑更稳。运行时 `@deepseek-ai/dsh-tools` / `@deepseek-ai/cordis` 从用户的 dsh 安装本身解析（`peerDependencies`），**不重复打包、不重复注册表**。

---

## 七、技术要点

| 技术 | 做法 | 收益 |
|---|---|---|
| **内容寻址证据链** | `evidenceId = sha256(canonical(record))`，`proofRoot = merkleRoot(证据地址)` | 可复算、可跨会话比对、单条记录篡改即被 `audit()` 抓出 |
| **哈希链 + 签名检查点 + 带外锚点**（v0.2） | 每行 `prev = sha256(上一行)`；检查点由宿主 Ed25519 密钥签名并镜像到工作区外的锚点 | 对抗「被审计者自己重写日志」：全量重写/回滚/换基线全部可检测 |
| **内容锚定变更集 + 来源归因**（v0.3） | 基线快照携带脏文件内容摘要；变更 = 与快照的字节差异；工具触达集区分 agent/external | 陈旧脏区不再冤枉会话；用户 IDE 手改不再记在智能体头上；「还原也是变更」也能抓到 |
| **LSP 双源影响融合**（v0.4） | `goToDefinition` 放在导入说明符上：验证近似边 + 发现别名导入盲区；并集语义；缓存 + 预算 | 精度提升不牺牲覆盖；monorepo 别名断链不再漏判；降级显式可见 |
| **诚实性加固**（v0.7） | 判定知识格三值化（`indeterminate`）；签名裁定三态（可驳斥 / 不可裁定 / 未签名）；git 不可用 → `degraded` + 强制全量；abort 基线不落盘；日志写入单飞队列 | 未知永不冒充通过：skipped 不再算通过、能力缺失不再误判伪造、并发写不再断链、半成品真值不再锚定后续判定 |
| **完备性闭合**（v0.8） | 摘录预算约束 `text` 本身（含 marker），`keptOriginalChars` 账目闭合；append 跨进程幂等 + 尾行撕裂自愈（`log/recovered-partial-tail`）；Windows `.cmd` 垫片解析直 spawn node；`killedBySignal` 死因事实；临时名唯一化 + rename 重试 | 账目对得上（省略数可复算）、事实守得住（崩溃与重启不再留残行/重复行）、死因不再被译错（信号≠超时） |
| **反向依赖闭包** | import 图 + 传染式 BFS | 增量验证，省时间也省 token |
| **基线差分回归归因** | `baseline ∘ delta = proof` | 区分「本来就坏」与「被你改坏」 |
| **接口 / 实现 / 消费者分层** | 领域核心零框架依赖 | 可测、可复用、抗上游抖动 |
| **事件溯源事实源** | append-only JSONL，与 DSH session log 同构 | 「模型说的一切都能从日志重建」的同类不变式 |
| **纯投影 UI 卡片** | `presentCall` / `presentResult` / `presentationMeta` 无 I/O 无时钟 | session-log 回放逐字节复现 |
| **守门式执行策略** | `tools/pre-execute` waterfall + 单调拒绝 | 运行时强制，而非祈祷模型听话 |

---

## 八、配置

全部可调项都在 `cordis.yml`，代码里没有硬编码旋钮（DSH 的设计要求）。

```yaml
- insert:
    - id: dsh-proof
      name: dsh-proof
      config:
        evidenceStore: host        # host=日志放宿主信任根（默认，移出智能体可写区）| workspace=放回项目内
        evidenceDir: .proof        # 证据目录（workspace 模式下生效）
        trustDir: ''               # 信任根（密钥+锚点）；默认 $DSH_PROOF_TRUST_DIR 或 $DSH_HOME/proof
        checkpointEvery: 25        # 每 N 条记录自动追加签名检查点（边界必加）
        autoDiscover: true         # 从构建元数据自动发现客观检查
        checks: []                 # 显式检查，可设 exclusive: true 关闭自动发现
        checkTimeoutMs: 120000     # 单个检查超时
        verifyBudgetMs: 300000     # 单批验证总预算
        concurrency: 2             # 并发检查进程数
        scheduler: bayesian        # 验证调度：bayesian=信息增益波式调度+分级信任（默认）| set=旧全批行为（行为级退路）
        certifyTarget: 0.97        # 认证阈值：claim 后验 ≥ 此值即 proven（"p≈0.97"的那个 p）
        impactGraph: true          # 构建反向依赖图
        lspImpact: true            # 用宿主 LSP 验证/扩展影响边（含别名导入盲区）
        lspQueryBudget: 400        # 单次建图的语言服务器查询预算
        impactGraphLimit: 20000    # 图规模上限（防 monorepo 卡死）
        requireBaseline: warn      # off | warn | ask
        driftDetection: true       # 工具流之外的改动检测
        enforceOnTurnEnd: true     # 本轮改了东西但没证明 → 注入提醒
        promptSection: true        # 发布 proof:policy 段落
        promptScope: proof:policy
        headChars: 2000            # 每条证据保留的输出摘要长度
        excerptStrategy: balanced # 摘录策略：balanced=头+显著失败行+尾 | head=传统前N字符
        normalizeHome: true          # 把用户主目录归一为 $HOME（隐私+跨机器可比）
        apiEntryPoints: []           # API 面入口（工作区相对路径）；缺省 [] = 从 package.json main/exports["."]/types 推导
        juryConfidenceCap: 0.8       # docs-only 陪审自证的置信上限（grade 可 proven，confidence 永不超过此值）
        classBTrust: 0.7             # B 类证据（LLM 陪审）信任权重：log-odds 指数/混合力度，弱证人只能弱化断言（§五·十四）
        classCTrust: 0.9             # C 类证据（人类背书/驳回）信任权重：endorse 轻折扣 0.95^0.9≈0.955，reject 崩塌 (1-0.95)^0.9
        syntheticDir: .proof-synthetic # π：合成证据沙箱目录（脚手架与测试脚本落于此；钉出检查发现，永不成为客观检查）
        syntheticFalsePass: 0.15      # π：合成检查假阴率 β（agent 自写测试的定价；organic 为 0.02，见 §五·十五）
        syntheticTimeoutMs: 60000     # π：单个合成测试执行的协作超时
        coverage: observe             # υ：覆盖感知证明门控：observe=有覆盖率数据才门控（默认，无数据降级为 basis 'none' 如实可见）| require=无数据也不给 proven | off=不注入不门控（逐字节旧行为），见 §五·十六
        agentTeamBridge: false        # v0.19 实验 dsh agent-team 桥：4 候选事件 seam 鸭子类型探测 + 优雅降级；opt-in，除非你的 dsh 构建会发 team 事件，否则保持 false
        verbose: false
```

**透明日志不占配置项（v0.18）。** 上表维持 32 项不变——PTL 是部署物，不是旋钮：MCP 服务器与 `dsh-proof-ptl` CLI 经环境变量 `DSH_PROOF_PTL_DIR` 寻址日志目录（默认 `<信任根>/ptl`，即 `$DSH_PROOF_TRUST_DIR/ptl`），引擎侧是 `EngineOptions.ptlDir`；不配置即功能关闭，`proof_publish` / `publishCheckpoint()` 返回干净的配置错误。操作者密钥在 `<日志目录>/operator-key/` 首用时生成，与工作区链密钥刻意分离。

**责任 DAG 只占一个配置项（v0.19）。** 上表 32 → 33 项（实测 `src/config.ts` 的 `Config` 接口逐键清点，schema 与接口两侧同为 33）——委派、提交、合成、豁免全是协议动词，不是部署分歧点；唯一的新键 `agentTeamBridge`（默认 false）是实验 agent-team 桥的 opt-in：dsh 已发布的类型没有 team 接口，桥对 4 个候选事件 seam 做运行时鸭子类型探测并优雅降级，实验 seam 绝不惊扰没要过它的部署。

**训练数据飞轮不占配置项（v0.20）。** 上表维持 33 项不变（实测同上）——两类样本、reward 惯例表、隐私两档、agent-only 过滤全是协议语义，不是部署分歧点；保真档与过滤档按调用逐次指定（`proof_training_export` 的 `fidelity` / `provenanceFilter` 参数，缺省即安全侧：private + agent-only），数据集落盘位置由调用时的 `path` 给出。刻意不设全局缺省旋钮的理由写在 `VERDICT_REWARD` 的文档里：逐导出可变的 reward 表是一个标签没法对比的数据集。

**验证经济学不占配置项（v0.21）。** 上表维持 33 项不变（实测同上）——费率卡（`computePerMs`、可选 `humanReviewPerItem`）是**查询参数不是全局配置**：随 `proof_verify` 的 `economics` 参数、`proof_economics` / `proof_sla_quote` 的调用参数逐次注入，不配置即不定价、链上无账本。刻意不进配置的理由与 reward 表同源：价格是部署方对成本基础的**声明**，硬编码进插件或落成全局缺省都会让同一份证据没法在不同费率下重新对账——换卡重定价是特性（`src/core/economics.ts` 本身不含任何价格）。

**v0.22 硬化不占配置项。** 上表维持 33 项不变——全部修复是关上的门与被观察的事实，不是新旋钮；唯一的新常数是引擎级 `EngineOptions.driftedFalsePass`（未审查脚本体 β，缺省 0.5，与 `syntheticFalsePass` 同层的可覆盖建模猜测），刻意不进 `cordis.yml`。

**`requireBaseline` 三档**

- `off` —— 不拦，只做记录与报告
- `warn` —— 默认。本轮动了工作区但还没有基线 → **回合结束时经 `agent.inject` 注入纠正性通知**（提示先跑 `proof_baseline`，之后的失败才能归因到你的改动）
- `ask` —— **没有基线就不许改工作区**，走用户审批

**显式检查示例**（想要精确的增量验证就配 `paths`）：

```yaml
        checks:
          - label: 单元测试
            command: [pnpm, test, --, --run, tests/unit]
            kind: test
            paths: ['src/**', 'tests/unit/**']
            timeoutMs: 180000
          - label: 类型检查
            command: [pnpm, exec, tsc, --noEmit]
            kind: typecheck
            paths: ['src/**', 'tsconfig.json']
```

---

## 九、开发与验证

```sh
npm install
npm run typecheck     # tsc --noEmit，离线可跑
npm test              # 951 个测试（node:test）
npm run build         # 产出 lib/
npm run bundle:check  # 打包契约自检
```

测试分层：

- `01`–`04` —— 纯核心：哈希、检查发现、影响分析、证据与判定
- `05` —— 引擎端到端（内存端口；v0.9 增补波式调度用例：提前认证、首败停、`set` 回归、确定性、预算降级；v0.10 增补四类合约端到端与旧基线无 API 面的诚实降级；v0.11 增补证据分级 5 例：链种 B 裁决零命令认证、双向申诉覆盖、背书风险接受与 reject 崩塌+对称锁、背书只解目标差不买工作、纯机器隔离——`verify()` 永不读链上证词；v0.12 增补合成闭环 4 例：真进程请求-执行闭环、筛检拒收零执行零落链、β 定价端到端（synthetic < organic 且 basis 点名 regime）、behavior-adding 合成兜底；v0.13 增补覆盖门控 4 例：真进程端到端 change-executed（记录挂覆盖附件、重寻址后链仍自洽、暂存无残留）、**头条盲区实证**（paths 匹配但从不执行 → unproven 点名 + conjure 处方）、require+无数据与 off 对照（同一夹具两种相反 grade）、向后兼容（默认 observe 在 fake 端口上与 off 逐位相等）
- `06` —— 漂移检测
- `07` —— **真实 shell 集成**：真的 `npm run --silent test`，真的退出码，真的回归归因
- `08` —— 插件接线：九个工具、pre-execute 钩子（基线门、证据库守卫、`proof_endorse` 恒 ask 的审批 seam）、提示词段落、纯投影、配置校验、陪审请求冻结/裁决校验/审批后落链、合成请求冻结（脚手架逐字返还 + `synthetic/requested` 落链）/合成经端口执行落链/筛检拒收以协议结果（而非报错）返回、覆盖三态投影（v8-executed 渲染与传递 / v8-unexecuted 点名前 3 文件 + conjure 处方 / none 如实声明 observe 与 require 之别；off 与旧日志无字段无线、敌意形状安全降级）；v0.19 增补 agent-team 桥 5 例——事件防御性收窄（不认识的形状静默跳过、链不可用降级 stderr）、委派镜像 + instruction 注入可变载荷、`attachTeamBridge` 逐 seam 探测且拒收的注册拖不垮其余（无可写通道则 stderr 点名 taskId 手工接线）、默认配置不订阅任何 team seam（opt-in）、移交文本携带 claim/ids/worker 协议
- `09` —— **信任对抗**：链断裂、全量重写（用本包自己的哈希函数）、回滚、基线替换、真实 Ed25519 密钥；v0.14 追加 H1 加固 5 例——THE ADVERSARY II（外来 keyId + 虚报 count 的伪造检查点无法洗白链重写）、貌似合理的 count（`anchor.count + 1`）同样判 malformed、count 对账只认走链实数、Infinity/负数/小数 count 全拒、锚只认自己 keyId 的检查点（外来 key 的后到完好检查点不能顶替）
- `10` —— **变更集溯源**：陈旧脏区豁免、还原即变更、未跟踪文件、外部回归不记账、引擎端到端
- `11` —— **LSP 影响融合**：goToDefinition 验证近似边、别名导入盲区发现、缓存与预算、降级不缩窄
- `12` —— **智能摘录**：显著失败行优先、整行尾窗、省略记账、（文本， 配置）纯函数确定性
- `13` —— **位置无关寻址**：跨机器 / 跨检出目录 / 跨用户名同址、`$HOME` 隐私、Windows 双斜杠形态
- `14` —— **Node 适配层**：`porcelain -z` 解析（rename/copy 双端、幻影路径）、git 能力探测、多字节 UTF-8 跨 chunk 捕获、Windows `.cmd` 垫片解析（真实 npm 模板、非标准垫片清晰报错）、`killedBySignal`、并发写唯一临时名 + rename 重试
- `15` —— **runner 直测**：并发 clamp、验证预算 skip、abort 传播、乱序完成重排、`killedBySignal` 判定（信号 ≠ 超时）、spawnError、excerpt 贯通
- `16` —— **贝叶斯调度核心**：公式阶梯逐档核对（ρ 平滑、s 的 1.0 / 1/(1+d) / 0.7 / 0.5、π 双侧 clamp、α clamp）、后验单调性与全概率恒等式（鞅）、VOI 非负且与独立转写的公式吻合、确定性 / 乱序不变、(π, α) 网格扫描
- `17` —— **类型化断言合约**：五形态提取逐形态核对（含别名/字符串别名/多声明符/解构/`export =`/`export * as ns`）、入口推导与闭包截断、义务矩阵全分支（四类 × met/not met × detail 文案）、`requirements*.txt` 陷阱守卫、封顶值逐字兑现、纯函数确定性（同输入同字节、记录乱序不变）
- `18` —— **证据分级（B/C 证词）**：量规存在性与结构化输出指令（英文 rubric 逐项核对：三值裁决、主观概率、弃权规则、Class B 落盘与重放警告）、`juryPrompt` 字节级确定性与段落结构（含量规版本覆盖）、`claimIdOf` 稳定 16-hex 身份（改写即新断言）、因子数学（p^w 语义、abstain 中性、w=0/w=1 边界、**[p,1] 网格扫描**、NaN/越界防毒、C 类 endorse 0.95^0.9 与 reject 0.05^0.9）、`activeAttestations` 链读纪律（垃圾载荷防御、gen 申诉解析、同 gen 后写者赢、B/C 独立信道、(claimId, kind) 确定性排序）、llm-jury 义务矩阵全分支、模块级确定性
- `19` —— **PTC 证据合成（32 例）**：模板协议（末行 PASS/FAIL、文件内链上警告、脚手架自筛干净）、`sandboxEntryFor` 确定性与「seq 防碰撞不携带身份」、沙箱目录钉出发现的字面量同步、筛检双向精度（deny-list 恰为锁定集、静态/裸/动态/require 各拼写、node: 前缀、多行与 re-export、process.env 成员/计算形式、注释内导入照报、名字仅含禁用模块的本地 fixture 放行、findings 去重排序）、β 定价（同历史 0.15 vs 0.02 且别的不动、`syntheticFalsePass` 只覆盖它、闭式后验、端到端折价）、记录（合成元数据上链、**同结果不同 scriptDigest 即不同 evidenceId**、冻结时钟深度相等）、义务 tier ladder 全分支（latest 合成兜底点名折价、无覆盖维持 not met、organic 兜底不被误称 synthetic、混合覆盖逐桶点名、当次 organic 压过一切兜底、pre-ο 记录经 spec 池判 synthetic）、入口点纯函数确定性
- `20` —— **覆盖感知证明（26 例）**：V8 解析（执行/加载未执行分桶、root 外与 node_modules 段丢弃、盘符大小写与双斜杠形态、百分号解码、垃圾 JSON 与异形防御、空 result 是合法报告、执行压倒加载）、聚合（executedSets 并集、零 executedSets 钉死 basis 'none'、重复坍缩、非源码文件入 notApplicable 不参与门控）、门控三档全分支（observe 无数据不拦 / 有数据 uncovered 拦、require 无数据拦 `no-coverage-data`、off 永不拦）、`applyCoverageGate`（unproven 降级与摘要挂载、grade 保序——regressed/stale 永不被改写、none basis 诚实附挂不拦截）、`makeEvidence`（coverage 附件参与内容寻址、自寻址、同输入同记录）、模块级确定性
- `21` —— **协议词表（APP/1.4）**：`src/app/protocol.ts` 的五张词表逐字钉死，并与核心实际产出交叉核对——verdict 对 `verdictOf` 全真值表、grade 对五个行为夹具、chain mode 对 `walkChain`、status 对决定性/非决定性划分；常量声称一个核心产不出的值、或核心长出一个常量没钉住的值，都必须在这里失败。v0.18 增补 1.1 升版指纹钉死：`PROTOCOL_VERSION` 是指纹材料，词表与规则未动、仅版本 1.0 → 1.1 也必须移动指纹——APP/1.0 方言被拒绝而非被猜测；v0.19 再钉三代：1.0 / 1.1 / 1.2 三代指纹字面钉死且互不相认；v0.20 钉到四代——1.3 的指纹字面与前三代同列，四代互不相认是 pin 的属性、不只靠活摘要；v0.21 钉到**五代**——1.4 的指纹字面与前四代同列，五代两两互不相认
- `22` —— **bundle 篡改矩阵**：用真实 `EvidenceStore`（内存 Fs，`09` 同款 fakes）铸造诚实 bundle，再按伪造者的方式逐个攻击——改日志一字节、调包基线、虚报锚点、改写 manifest 方言（appFingerprint 不匹配即拒）；全程 MemoryFs，不碰真实磁盘
- `23` —— **MCP 真子进程集成**：spawn `node --experimental-strip-types src/app/mcp-entry.ts`，经 stdio 上的换行分隔 JSON-RPC 2.0 驱动握手与协议版本协商、十三工具契约（1.1 增 `proof_publish` / `proof_log_verify` 两工具的发布-审计用例；1.2 增委派三工具五例——移交文本、提交前总览、诚实 bundle 合成 proven、伪造 bundle 点名归责、畸形用法拒绝；1.3 增训练导出四例——private 缺省且样本永不进响应、full+`path` 把 JSONL 数据集落盘、非法保真档大声拒绝绝不静默降级、参数面钉死——fidelity/provenanceFilter 枚举与 private 缺省写进 schema 本身；1.4 增验证经济学五例——定价 offer（保额 10000 × 置信 0.97 恰为 300）、regressed 诚实拒保且理由上链、畸形用法（等级/保额/币种）大声拒绝、缺账本时给出确切补救、**收口的接缝**——`proof_verify` 在 MCP 面直接收 `economics` 费率卡、铸出账本、`proof_economics` 逐字回放）、baseline → verify → status → bundle 全链（真实 `npm test`、真实证据、真实 Ed25519 链）与错误路径（未知工具、非法 kind、畸形 JSON 行）——零 stub，证明任何外来 harness 都能端到端驱动证明协议
- `24` —— **适配器共享层（27 例）**：推导字节对齐的旗舰纪律——跑一个**真实 ProofEngine**，核对文件落点与 `deriveProofPaths` 所说分毫不差；H10 大小写变体洞（`.PROOF/evidence.jsonl` 守卫必须拦）、会话即值（观察/漂移/窗口推进）、跨进程原子持久化、pre 工具门与回合结束门的优先级矩阵
- `25` —— **Claude Code 适配器（23 例）**：处理器单测（真实目录上的许可决策/观察落盘/漂移+一次性提醒/SessionStart 上下文）、入口**真子进程**（向 stdin 喂 JSON，断言单行 JSON 应答；post→mutate→stop 全程每步独立进程、只共享会话文件）、坏输入（不可解析的 PreToolUse 答 `ask`；未知事件名静默退出 0）；外加 `examples/claude-code.settings.json` 的纯 JSON 与 matcher 形状钉死
- `26` —— **OpenCode 适配器（19 例）**：vendor 收窄矩阵、before 门的证据库守卫/ask 基线门/warn 默认放行、**漂移锚点**（无 Stop 钩子——after 观察到的漂移在下一次工具调用持起并点名文件）、after 观察跨三种真实载荷形状持久化、合成上下文上的注册与端到端持起（`{error:{message}}` 形态）、chat.params 注入、无面上下文降级为 no-op、抛异常/返回垃圾的注册器绝不炸宿主
- `27` —— **透明日志核心（25 例，v0.18）**：叶哈希 `SHA-256(0x00 ‖ canonicalJson)` 逐字节钉死（键序不可移动叶地址）、RFC 6962 §2.1.3 工作例逐字核对（audit path 与 PROOF 两组已知答案）、**差分 Merkle**（独立朴素递归对 n = 0..33 全树形一致）、包含证明全位置全尺寸成立且可对**历史树头**验证、伪造形状全拒且永不 throw、一致性 178 对全验且「旧根可从新树导出」（前缀包含 + 一致性双钉）、STH 签名数据恰为规范化载荷、追加以叶哈希幂等、`loadPtl` 跳过残行且可读前缀幸存、`savePtlHead` 拒绝一切回退（缩树/同树换根/回拨时间戳）、**THE SPLIT-VIEW DETECTOR**（改写中段条目铸出签名头无法调和的第二历史；截断尾部被头守卫与数学双重拒绝）、交换两行条目必动根（有序树而非集合）
- `28` —— **PTL CLI（12 例，v0.18）**：真实子进程驱动 `dsh-proof-ptl`——append 发布最新签名检查点并签新 STH、重复 append 幂等（duplicate=true 不增树）、自检绿/一字节篡改后失败、带 transparency 记录的 bundle 全链绿、**日志增长后旧 bundle 仍验过**（历史不可回写）、leafHash 翻一位即 leafMatch 失败退出 1、无记录 bundle 干净报错、用法错误退出 2 且永不吐栈、verify 永不凭空铸造操作者密钥
- `29` —— **跨代理责任 DAG（20 例，v0.19）**：`obligationIdOf` 手工重算钉死（规范化字节 sha256 前 16 hex，键序无关、改一字符即搬家）、`bundleFingerprint` 手工重算且顺序无关、**THE ACCOUNTABLE DELEGATION**（两个验过的 bundle 合成一个诚实的 proven 裁决）、全量合成矩阵（每个子状态 × 豁免与否 × 每档自身 grade）、优先序（regressed 压缺工作压自身 grade，账目列表诚实）、无子任务即自身证据（undefined 读作 proven）、**FORGERY**（声称 proven 但 artifact 验不过 = regressed，措辞逐字钉死，豁免救不了）、递归四例（regressed 孙辈层层上传、未提交孙辈拖 stale、伪造中间层在顶层浮出为伪造、纯组织者子树全绿仍 unsubmitted）、菱形（共享孙任务只合成一次、对两父答案一致）、`detectCycles`（委派方向路径规范化、自环/不相交环/悬空父引用/干净森林）、`composeTaskVerdict`（自裁伪造点名且封顶、环拒绝折叠点名 blocker、未铸造 taskId 报告不抛）、豁免可见性（被豁免子从 blockers 消失、伪造同胞不消失）、`childrenByParent` 分组确定性
- `30` —— **训练数据飞轮（8 例，v0.20）**：**THE GROUND-TRUTH EXHAUST**（全部判定类别 × 两个翻转方向的样本真值——记功/中性/记账各就各位、indeterminate 排除在样本之外、flip 的 rejected 恒 fail / chosen 恒 pass）、reward 表是钉死的法（逐 manifest 快照、改表即改数据集身份）、flip 配对只看决定性子序列的相邻（非决定性记录不断邻也不造对）、保真两档（private 零输出文本、full 摘录恰 200 字符）、溯源过滤（一条外部编辑作废全部 verification 标签、绝不动 flip）、确定性（同输入两次逐字节相同、日志乱序蒸馏出同一数据集）、内容寻址（`sampleHash` 为规范化摘要前 16 hex、root 改一字符即动）、空日志是合法数据集
- `31` —— **验证经济学（24 例，v0.21）**：**THE UNIT COST OF TRUST**（运行账本把算力/断言/置信/信息各按美元成报）、null 纪律（零成本不除出 `Infinity`、两个每美元比值皆 null；缺先验不装零、`confidencePurchased` 为 null 且无因子恰 0 nat）、**infoNats 带符号**（花钱得知断言破了仍是信息——负熵差如实入账）、退化端点熵为零（H(0)=H(1)=0，一个因子落定到确证恰 ln 2）、`skippedCount` 让沉没成本可见（非决定性时间是花了钱没买到断言的时间）、金额至多六位小数（`7400ms × 0.0001` 读作 0.74 而非 0.7400000000000001）、proven 出 offer（premium = coverage × (1 − confidence) 恰确）、置信端点退化但合法（P=0 全额承保、P=1 只剩底价）、minPremium 抬底、deductible 逐字透传绝不入保费、regressed 一句话拒保（措辞钉死）、四路人工核保（stale/unproven/no-baseline/无置信，置信越界含 NaN 同路）、**五条除外条款逐字钉死且随每份报价携带**（没人能引用的除外条款等于没人许过的承诺）、quoteId 寻址（同输入同字节、保额一分钱即另一份报价、**费率卡不入地址**——换卡重定价不动报价字节）、输入防御（保额有限且严格为正、费率卡有限非负 USD、可选金额字段有限非负、账本也防御自己的费率卡）

本地调试：

```sh
# 编辑 examples/cordis.yml 里的绝对路径后
pnpm dsh web --patch /absolute/path/to/dsh-proof/examples/cordis.yml
```

---

## 十、诚实边界

- **检查发现是启发式的。** 复杂 monorepo、自定义构建系统、Bazel/Nx/Turborepo 编排请用 `checks` 显式配置，并给出 `paths`，增量验证才会精确。
- **依赖图是近似的。** 动态 `import()`、多行 ESM import 与 Python dotted import 已在 v0.7 纳入解析；反射与运行时字符串拼接的路径仍然无法解析。近似**偏向过覆盖**（多跑一次，绝不漏判）。
- **claim 后验是独立乘积近似（v0.9）。** `confidence` 是各检查健康概率的连乘，隐含「检查相互独立」——共享同一批变更文件（或同一夹具、同一套测试跑两遍）的检查，失败是**相关的**，乘积会高估证据强度。这是模型已知最大的失真源；替代方案（对全部检查建模联合分布）恰恰需要我们没有的真值数据。所以这个数应读作**排序信号而非标定概率**，下游不得把它表述成赔率。
- **β = 0.02 是承认的猜测（v0.9）。** 假阴率（工作区坏了、检查却绿）需要「确实断了」的标注数据才能学习，而证据日志只记录观测，没有「真值断裂」一列。固定常数是诚实的猜测；在这里学一个数出来才是假精确。α 同理只是粗糙估计（flips 只配对决定性观测、分母含全部记录，interleave 时偏低——记为粗糙，不假装修正）。
- **certified-subset 的跳过以先验形式留在账上（v0.9）。** 提前认证没有跑的检查不是被忽略：每个都以 `skippedByPlan` 记录（携带各自先验）、随 `proof/verified` marker 入链、可审计，剩余不确定性如实进入后验。先验只和证据日志一样好——日志短的检查先验保守（ρ = 0.2 起步），这是设计而非缺陷。
- **摘录是记账的省略，不是无损摘要（v0.8）。** 预算约束的是 `text` 总长——省略 marker 与连接换行同样计入；对账字段是 `keptOriginalChars`（`omittedChars + keptOriginalChars === normalized.length` 严格闭合），不要用 `text.length` 对账（marker 会虚增它）。`head` 策略是恰为 budget 的逐字切片，同样满足 `text.length <= budget`。
- **检查点存在窗口期（v0.2）。** 最后一个签名检查点之后的记录受哈希链保护但不受检查点保护；窗口由 `checkpointEvery` 界定，且每次基线/验证/断言边界都会闭合它。窗口内截删不再是不可见的：`proof_status` 的 `tailRecords` 直接暴露最后一个检查点之后还有多少条记录。删除锚点文件可以造成「回滚不可检测」——锚点因此放在智能体沙箱之外；若整台主机被攻陷，本插件的威胁模型不适用。
- **半行恢复只修尾行撕裂（v0.8）。** 启动时只把「有前缀、没有闭括号」的**最后一条**残行原子重写掉（并落 `log/recovered-partial-tail` marker）；完整行的损坏不恢复、不改写——那可能是篡改，审计继续报。崩溃恢复与篡改检测的界线就在这里：撕裂是崩溃的物理签名，整行重写不是。
- **签名密钥的边界。** 密钥防的是「被审计的智能体」，不是「能读宿主文件的人」；主机被完全攻陷时一切本地信任机制都失效。在**没有 signer 的机器**上（密钥丢失、换机器审计），带签名的检查点无法本地裁定——审计报告为 `unverifiableCheckpoints`：这是**能力缺失，不是伪造指控**，audit 不会因此失败；rewind 覆盖也不依赖密钥（锚的 count/head 比较仍然约束日志）。
- **`killedBySignal` 的平台边界（v0.8）。** 该字段只在子进程能如实报告信号死因的平台上出现；win32 下恒缺省——Windows 不跨进程传播信号。信号死亡在本插件记 `error` 并注明信号（不再误判为超时），但 Windows 上外部击杀只能表现为退出码/错误，插件不会编造一个信号名。
- **API 面是正则提取的保守过报近似（v0.10）。** 逐行正则看不见运行时动态生成的导出（动态计算的导出名、字符串拼出的再导出）；提取刻意偏向过报——漏报一个导出等于漏掉一次破坏性变更（错误通过），多报只是让诚实的断言多干活（错误失败）。入口推导依赖 `package.json` 声明与存在性探测，声明与真实入口不符时请显式配置 `apiEntryPoints`。
- **docs-only 的陪审是自证，不是实验（v0.10）。** `review` 是作者自评：confidence 封顶 `juryConfidenceCap`（默认 0.80）、basis 为 `jury-only`、叙事直说 `self-attestation is capped`。这个数是**上限不是测量**，不得当作实验证据引用。
- **perf-budget 的 `durationMs` 受机器噪声影响（v0.10）。** 预算判定基于 wall-clock 时长测量，受机器负载、频率漂移与并行进程影响，跨机器不可比。`budgetMs` 应留余量，边界值附近的判定波动是预期行为而非回归。
- **B 类证词的独立性只有最弱档（v0.11）。** `independence` 分档为 `same-session` / `fresh-context` / `isolated-model`，而本版工具实际写入的是 **`same-session`**——陪审在作者智能体自己的上下文里审议，污染风险最高的一档，链上如实标注。模型身份同样是**提交方声明而非可验证事实**（插件无法验证应答者是谁），记为 `'session-model (unverified)'`；能抓住冒名顶替的不是声明，而是第三方拿同一 prompt 重放比对输出的审计。权重（`classBTrust` 0.7）是声明的策略常数，不是从数据里学出来的——不存在「这个证人历史上对了几次」的标注集。
- **陪审的 `probability` 是主观概率，不是测量（v0.11）。** 量规要求陪审报告「你的推理真正支持的那个数」，但 LLM 的自报数字没有对标任何频率保证；p=0.99 与 p=0.9 的差别应读作措辞强度而非校准差距。全部证词数学（p^w、混合）都是在**消费**这个主观数，不会让它变得更客观。
- **`humanProbability` = 0.95 是建模选择（v0.11）。** Class C 的审批 seam 是二值的（批准/驳回），不采集数字置信，于是人类「对」的概率以常数 0.95 入账——不是测量，也不该被调参成「看起来能过 0.97 目标」的值。0.95 < 1 是刻意的：永不犯错的人类背书会让每条被背书的断言不可证伪。
- **可靠性混合是评分规则选择，不是推导出的后验（v0.11）。** `fuseConfidence = (1−w)·c + w·p` 把「证人以概率 w 可靠、否则是噪声」建模为线性期望——选择「混合」而不是「乘积」是因为机器认证已存在时证词谈论的是**整个断言**而非又一个独立因子；它不是从任何先验推出的后验，边界情况（w→0 保机器数、w→1 采纳证词值）是设计锚点而非定理。两套数学各有其位：纯陪审路径用 p^w 折扣（只能弱化），融合路径用混合（可救活也可崩塌）——用哪套由「机器是否已经说话」决定，而不是由哪套数字好看决定。
- **静态筛检不是沙箱（v0.12）。** 合成脚本的执行前置筛检是文本层 deny-list：计算式 specifier（`import(buildName())`）、别名通道（`createRequire` / `eval` / `new Function`）与大小写混淆的 specifier 它看不见——文本看不见运行时值。真正约束失控脚本的是沙箱 cwd 限制、执行超时（`syntheticTimeoutMs`）、输出摘录上限与宿主将来的 ptc-runtime 档位；筛检的职责只是让**容易的**外联尝试在执行之前大声失败。档位标签因此如实写 `'screened-subprocess'`，不冒充沙箱。
- **合成 β = 0.15 是承认的猜测，且这个数按构造学不出来（v0.12）。** 假阴率需要「确实断了」的真值标注才能学习，而一条自利的测试（空断言、漏掉会破的输入）按构造**不产生任何可学的破坏信号**——日志里它永远是绿的。0.15 与 0.02 一样是定价立场而非测量；它刻意放在可覆盖的 `syntheticFalsePass` 而不是「不再重调」的 `BAYES_CONSTANTS` 里，正因为它是建模猜测，不是定律。
- **合成覆盖永远弱于 organic 同侪（v0.12）。** 同样一次 pass，合成检查的后验抬升天然更少（端到端：synthetic ≈ 0.9706 < organic ≈ 0.9960）；义务 tier ladder 里合成让路于同档 organic；全部决定性记录皆合成时 basis 改名 `synthetic` 并在叙事里点名折扣。合成覆盖应读作「断言作者自己跑过并通过的验证」，不是独立确认——三层机制（β、tier ladder、basis）编码的都是这同一句话。
- **执行覆盖是文件粒度（v0.13）。** v1 的「执行过」= 文件有任一函数的任一 range `count > 0`——它不区分执行了变更的那几行还是同文件的隔壁函数，一个只触达未改代码的测试与真正执行变更的测试在此粒度下等价。行级/符号级判定（需要基线内容 blob 或 LSP 符号映射把变更定位到行/符号）是演进方向，不是本版能力；读 `change-executed` 时请记住它说的是「这个文件」，不是「这一行」。
- **非 node 生态没有覆盖数据（v0.13）。** `NODE_V8_COVERAGE` 是 Node 运行时开关：pytest、go test、cargo test 等进程继承变量但不产 V8 profile，覆盖维度对它们是 `basis: 'none'`——observe 不拦（该生态永远不门控），require 则每条断言都 unproven。这是部署决策不是缺陷：纯 node 工具链可放心 `require`，混合/非 node 生态请留在 `observe`，或干脆 `off`。
- **「加载未执行」桶未参与更强判定（v0.13）。** V8 报告天然携带第三种事实——文件被 import 但从未跑过一行；v1 解析并保留该分桶，却只把**执行**用于门控。「加载未执行」本是「依赖图以为它会被用到、实际没有」的现成证据（更强的嫌疑文件排序、更精确的 `new-paths-covered`），v1 未消费——保留为演进，如实记在这里。
- **MCP 面是十三个一致性工具（v0.14 的五个 + v0.18 透明日志二工具 + v0.19 委派三工具 + v0.20 训练导出 + v0.21 经济学二工具）。** 即 `proof_status` / `proof_baseline` / `proof_verify` / `proof_claim` / `proof_bundle` / `proof_publish` / `proof_log_verify` / `proof_delegate` / `proof_delegate_submit` / `proof_task` / `proof_training_export` / `proof_economics` / `proof_sla_quote`。`proof_jury` / `proof_jury_submit` / `proof_endorse` / `proof_conjure` / `proof_conjure_run` 刻意不经 MCP 暴露——它们依赖宿主持有的 seam（人工审批提示、会话上下文、隔离的审议模型），开放服务器无法假设。想要证词与合成的客户端请在 DSH 内跑插件，审批 seam 在那里。
- **bundle 验证不替代本地审计（v0.14）。** 验证方从 bundle 自己的字节重导出一切——文件摘要、链链接、逐条自寻址、基线摘要——但检查点签名只在验证方持有（或被交给）点名密钥时可裁定，锚单调性只在锚文件可用时才检查；裁定的能力缺失如实记录，绝不四舍五入成伪造指控。没有锚的 bundle 保得住链与寻址保证，丢掉的是回滚覆盖。
- **检查点 count 自 v0.14 起是规范性的（H1）。** `count` 不是安全整数、或不等于走链实数记录数的检查点，无论谁签，一律进 `malformedCheckpoints`；锚比较只采信锚 keyId 匹配的检查点——伪造检查点（外来 keyId、虚报 count）不再能洗白截断。反面同样对称：一个诚实但数错了 count 的有 bug 生产方会被同样拒绝，没有豁免通道。
- **shell 命令字符串是所有宿主共有的溯源盲区（v0.15；守卫半边已于 v0.22 关闭）。** Bash/shell 类工具不携带结构化路径——`sed -i … src/a.ts` 这样的命令对**归因**什么都提取不出来，DSH、Claude Code、OpenCode 三个宿主同此洞，且是刻意为之（在命令行里挖「长得像路径的词」只会指纹出噪声）。shell 写出的文件没有指纹、没有触达归因；兜底是漂移检测——shell 改动先前观察过的文件仍会被抓到（字节与记录的指纹不再匹配）。逃逸的只有**全新** shell 建立的文件的归因——想要被记账与归因的改动，请用 Write/Edit。v0.22 补上的是守卫半边：**提及证据库或信任工件**（任何拼法、两种工作区身份）的 shell 命令在执行前即被拒绝——这个匹配能看见什么、看不见什么，见下一条。
- **OpenCode 没有回合结束 seam（v0.15）。** 没有 Stop 钩子、事件总线形状不稳，漂移与一次性 baseline/verify 提醒只能锚定在下一次工具调用上——外部改动后的第一个调用被持起并给出漂移叙事，且每个不同漂移集每个插件生命周期至多浮出一次（被无视的消息不能永远扣押后续调用）。`ask` 判定在这个宿主上也走不了用户审批往返：`ask` 与 `deny` 都持起调用，理由说明该改做什么。
- **超时如今是被观察的状态，不是推断（v0.16）。** 命令端口上报 `timedOut` 标志，真实超时的检查在两个平台上都记 `'timeout'`——此前生产端口报告不了这个死因，真实超时全被记成普通 `error`。边界仍在原处：信号死亡在能报告的平台上仍记 `error` 并注明信号（见 v0.8 条），Windows 上以普通退出码到达的击杀仍读作 `error`——插件只报告端口观察到的，绝不多说。
- **本会话用过 shell 后，`external` 降级为 `unknown`（v0.16）。** 「不在 touched 集」曾被读作外部改动的肯定证据——可会话一旦用过 shell（其路径任何宿主都提取不了，见 v0.15 条），这个缺失可能只是 agent 自己的 shell 工作没有被归因。归因如今对此说 `unknown`，不说自信但可能错指的 `external`，漂移叙事与外部嫌疑记账都读这个降级；`external` 只在本会话确实没有能产出该改动的手段时保留。
- **MCP `serverInfo.version` 就是包版本（v0.16）。** `initialize` 应答 `MCP_DEFAULT_VERSION`，随发布纪律与 `package.json` 保持同步，并被 `test/23-mcp` 的握手断言钉死——它是**实现版本**，不是协议能力声明；协议兼容性另行协商（`2025-06-18` 等）。
- **合成 deny-list 增补 process 系（v0.17）。** `process` / `node:process` 进入禁用清单，文本层能看见的拼写——反引号模板、`\u`/`\x` 转义、`node:` 前缀——先解转义归一再匹配，`import { env } from 'node:process'` 不再绕过 env 读取检查。增补对诚实脚本**按构造非破坏**：脚手架协议经全局取 process 状态（`process.exitCode`，无需 import），正当的合成测试分毫无损。清单看不见的仍是它从来看不见的——运行时计算的 specifier 与别名通道（见 v0.12 条）：文本不是沙箱；且清单是与引擎钉死的契约，增补是对宿主强制面的破坏性变更，不是随手编辑。
- **canonicalJson 对普通 JSON 单射，对非有限数刻意不单射（v0.17）。** bigint/symbol/function 与非普通对象（`Date`、`Map`、类实例……）抛 `TypeError`，不再静默折叠成别的值已占有的字节——两个 payload 不再可能铸出同一个 evidenceId。`NaN`/`±Infinity` 维持折叠为 `'null'` 的 legacy 行为，如今显式 pin 为决策而非事故：裁定读路径吃的是 `JSON.parse` 出来的数，伪造的 `"count": 1e999` 会 parse 成 `Infinity`——在那里 throw 会把审计当场崩掉，而不是把检查点裁定为 malformed；折叠已经产出正确裁定（验签失败，且走链的安全整数门点名这个谎）。改成 throw 被这些调用点的前置门挡着，是待办不是疏忽。
- **透明日志是单操作者日志（v0.18）。** v1 规范的就是一个操作者、一份文件日志。密码学保证的是日志自身历史不可被无感改写——改一字节根必动、截断树必缩，二者都过不了签名树头或一致性证明，回退防护再拒一层（缩树、同树换根、回拨时间戳的新头一律拒绝）。它抓不住的是**分叉视图（split-view）**：一个向不同验证者出示不同树的操作者，任何单一日志都无法识破——识破它需要多见证或审计者间 gossip（完整的 certificate transparency 答案），明确列为 future work，文档不声称它。
- **透明日志不验证工作区签名（v0.18）。** 日志按设计是哑公证——逐字托管检查点的 `{count, head, at, sig, keyId}`，从不裁定 `sig`。拿工作区公钥裁定工作区签名始终是审计者的独立工作；一条已发布的条目证明的是**发布**这一事实有序且未被回写，从不证明被发布的字节是诚实的。
- **引擎不能重跑子工作区的检查（v0.19）。** 子代理的检查跑在另一个工作区、对着另一份基线，引擎重演不了。`artifactVerified` 是 bundle 验证——结构、摘要、链——不是重新执行；`claimedGrade` 缺省因此刻意两值（验过且带基线 → `proven`，其余 → `no-baseline`），细等级（`unproven`/`stale`/`regressed`）全靠提交方**显式声明**。谎报的定价是伪造规则：声明了 artifact 撑不住的等级——尤其虚报 `proven`——一律记 `regressed`、豁免免疫；声明买不来字节撑不住的任何东西。
- **dsh 的 agent-team seam 未稳定（v0.19）。** dsh 已发布的插件类型没有 team 接口，实验桥（`agentTeamBridge`，默认 false，opt-in）因此对 4 个候选事件 seam 做运行时鸭子类型探测并优雅降级——每个事件从 `unknown` 收窄、每个订阅各自 try/catch、任何路径不向宿主抛异常。dsh 构建若不发出任何被探测的事件，桥就保持静默（至多一行 stderr）；显式驱动（MCP 或引擎的委派三工具）始终是第一等路径，与桥无关。
- **训练 reward 表是成文惯例，不是客观真理（v0.20）。** 标签底下的判定是机器验证的基线差分，但 1.0 / 0.5 / 0.0 的定价（`VERDICT_REWARD`）是声明的政策，逐 manifest 快照——不同意 `still-failing = 0.5` 的消费方必须自行重定价，而快照恰好告诉他重定价的对象是什么。flip 配对同样是相邻启发：「相邻」是导出日志决定性子序列里的相邻，不是「两次观测之间世上什么都没发生」的断言。
- **`private` 档去掉的是输出文本，不是上下文（v0.20）。** private 导出零输出字符，但仍携带工作区路径与输出 digest——路径本身可能敏感，digest 可以印证一个猜测。数据集消费方即使拿到 private 档也欠这份数据一份小心。
- **跨部署合并数据集的信任问题未解（v0.20）。** 把多个导出方的数据集并到一起，就要回答「这是谁的数据？被投过毒吗？」——本版不回答。把数据集来源锚进透明日志（防 data laundering）是未来方向，不是 v0.20 的属性。
- **经济账本的费率卡是注入的成本基础，不是真实账单（v0.21）。** `computePerMs` 与 `humanReviewPerItem` 是部署方对「一毫秒验证算力、一件人工评审值多少钱」的**声明**，账本只和卡一样诚实——包里没有任何东西知道你的验证算力实际花了多少钱。换卡重定价是特性（同一条链、不同成本基础、各自对账），但读数时请记住它计价的是声明价，不是发票。
- **`pUndetected` 是模型概率，不是精算理赔史（v0.21）。** `1 − confidence` 溯源自 v0.9 的断言后验，带着该模型全部已声明的失真（独立性假设为首——见 v0.9 条）；没有任何损失数据喂给它，也不带任何理赔历史的标定。把它当风险**排序与定价的模型基础**，不要当经验费率。
- **SLA premium 是示意性、基于模型的报价，不是金融产品（v0.21）。** `dsh-proof/SLA-1` 背后没有监管、没有准备金、没有理赔流程——它与训练 reward 表（v0.20）同一精神、同一限度：给残余风险定价的**成文惯例**。另外 `infoNats` 为负值的意思是这笔钱买到了**坏消息**（断言概率下降了）——那仍然是信息，账本按符号如实入账，计的是「学到了什么」，不是「舒不舒服」。
- **shell 守卫是保守子串匹配，不是解析器（v0.22）。** 守卫把两侧的大小写与分隔符折叠后，拒绝一切文本上**提及**证据库或信任工件的命令——这意味着**改写后避开全部受卫拼法**的命令（环境变量间接、折叠恰好漏掉的大小写变体、把写入交给一个脚本文件）仍可能溜过。选择是刻意的：解析器漏掉的会比抓住的多，所以守卫宁可误拦并点名理由；漏过归因的一切仍由漂移检测兜底。
- **V8 覆盖防御是隔离 + mtime 时间窗，不是密码学（v0.22）。** 每轮验证在各自的暂存目录收集，只采纳 mtime 落在本轮窗口内的 profile，窗口外一份即整轮降级 `basis: 'none'`。买到的是抬高的伪造成本——被检进程必须在与引擎时钟的赛跑中写进引擎本轮自己的暂存目录，而不是仅仅继承环境变量——**不是不可能**：能以窗口内 mtime 写进当前轮目录的进程仍然能击穿它。
- **PTL 操作者密钥只有在信任根已知时才与日志分离（v0.22）。** 设置了 `DSH_PROOF_TRUST_DIR` 时密钥落在 `<信任根>/ptl-operator-key`，在它公证的日志目录之外；未设置时可能解析到 `<ptlDir>/ptl-operator-key`——就在它签名的树旁边，正是审计点名的自指。显式传 `--operator-key`（或设 `DSH_PROOF_OPERATOR_KEY_DIR`）即可分离；密钥仍在 `<日志目录>/operator-key` 的 pre-0.22 旧日志，显式传该路径即可继续验证。
- **`proven` 允许存在预置红灯。** 一个本来就红的仓库不该让 Agent 无法工作。预置失败会在报告里显著列出，但不计入本次会话的责任。这是刻意设计，不是漏洞。
- **它不替代测试本身。** `dsh-proof` 编排并归因你已有的客观检查。v0.12 的证据合成也不改变这条边界：断言由 agent 起草，插件只冻结脚手架、筛检、执行，并把结果折价记账为弱于任何独立检查的证据。
- **DSH 是 v0.1/0.2 开发者预览版。** 插件契约会变。本插件已把依赖面最小化并钉死契约快照（`src/vendor/dsh-tools.ts`），但上游变更时仍需重新对齐。

---

## 十一、许可

MIT

## 鸣谢

插件契约、扩展点与打包模型来自 DeepSeek Harness 官方文档与源码（`deepseek-ai/deepseek-harness`，本文档对齐 `v0.2.1-alpha.1`）。
