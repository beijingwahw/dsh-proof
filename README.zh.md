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

---

## 四、面向模型的四个工具

| 工具 | 作用 |
|---|---|
| `proof_status` | 当前证明状态：基线、发现的检查、最新证据、证据链是否完好 |
| `proof_baseline` | 建立/刷新基线：跑全部客观检查并记录证据 |
| `proof_verify` | 增量验证：只跑变更集所影响的检查，对照基线给出评级与归因 |
| `proof_claim` | **声明 + 证明**：`proven: true` 才算数，否则 `blockers` 就是待办清单 |

所有工具都遵守 DSH 的硬契约：`execute` 只返回**规范 JSON 值**，人类可读文案在 `output.render`，UI 卡片通过 `presentCall` / `presentResult` / `presentationMeta` **纯投影**生成 —— session-log 回放时逐字节复现同一张卡片。

---

## 五、运行时强制（不只是提示词）

| 扩展点 | 机制 |
|---|---|
| `tools/pre-execute`（waterfall） | `requireBaseline: ask` 时，**没有基线就不许改工作区**，走用户审批 |
| `tools/pre-execute`（waterfall） | `evidenceStore: workspace` 时，**写入证据库的变更类工具一律转用户审批**——被审计者不能改审计记录 |
| `tools/result`（emit） | 观察每次工具结果，维护脏区与文件指纹 |
| `agent/turn-stopping` | 本轮改了东西但没做 `proof_claim` → 注入纠正性上下文；没有基线且 `requireBaseline: warn` → 注入基线提醒；检测到漂移 → 注入 stale 警告 |
| `ctx.systemPrompt.section()` | 发布 `proof:policy` 段落，让模型知道规则存在，不必靠失败去摸索 |

## 五·五、信任模型（v0.2）：对抗被审计者

证据日志的对手不是黑客，是**它要审计的智能体本身**——模型有文件写工具，可以把 `.proof/` 整个重写，并用本包导出的哈希函数重算所有自洽地址。v0.1 的 `audit()` 只能抓这种「天真篡改」。v0.2 用四层机制把「证明者」和「验证者」分开：

1. **哈希链**：每行携带 `prev = sha256(上一行)`，改动或删除任意一行都会断链。
2. **签名检查点**：检查点承诺 `{记录数, 链头}`，由**宿主持有、模型不可见**的 Ed25519 密钥签名（密钥在 `$DSH_HOME/proof/keys/`，永远不在工作区内）。智能体可以伪造整条链，但**造不出签名**。
3. **带外锚点**：历史最高检查点同时镜像到密钥旁边的锚点文件（工作区之外）。把日志截断或回滚到旧检查点之前 → `rewind` 检测。
4. **基线摘要入链**：`baseline.json` 是普通 JSON 文件，整体替换原本不可察觉——现在保存时其 sha256 作为 marker 落链并紧跟检查点，任何事后替换都会被 `audit()` 标记 `baselineTampered`。

配套的存储隔离：默认 `evidenceStore: host` 把日志放到 `$DSH_HOME/proof/workspaces/<工作区指纹>/`，**完全移出智能体沙箱可写范围**；选择 `workspace` 模式（放回项目内）时，写入 `.proof/` 的变更类工具会被转用户审批。

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

**引擎的诚实边界**。git 不可用时（WorkspacePort 新可选能力 `gitAvailable?()`），每条 git 查询各自失败返回空集——"什么都看不见"曾被吞成"什么都没变"，增量选择悄悄缩成空。现在变更集显式标记 `degraded`，引擎**强制全量跑**并在 `VerifyOutcome.degraded` 透出。中止的基线不再落盘——abort 的基线曾照常写盘，之后的回归判定对着半成品真值运行；现在已观测的证据仍全部入链、落 `baseline/aborted` 标记、检查点窗口照常闭合，返回值携带 `aborted` 标志，下一次 verify 诚实报告 `no-baseline`。signer 加载失败大声降级：链内 `trust/signer-unavailable` marker + verbose 日志——静默降级与诚实的 unsigned 部署从此可区分。`requireBaseline: 'warn'` 从"配置了但没接线"变成真通知：本轮动了工作区而没有基线时，回合结束经 `agent.inject` 注入纠正性提示。死配置 `driftNoticeMs` 删除（配置降至 22 项，v0.9 增至 24 项）。

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

---

## 六、架构：领域核心 + 薄适配层

对齐 DSH 自己的「接口 / 实现 / 消费者」三分法：

```
dsh-proof/
├── src/
│   ├── core/                 ← 纯领域层，零 @deepseek-ai/* 依赖（13 个模块）
│   │   ├── ports.ts          # 唯一的对外接口（Command/Fs/Clock/Workspace/Signer/Resolver）
│   │   ├── hash.ts           # 规范化 JSON + 内容寻址 + Merkle root + 输出归一
│   │   ├── checks.ts         # 客观检查发现（多语言 + monorepo 子包 cwd）
│   │   ├── evidence.ts       # 证据模型 + append-only 事实源 + 基线 + 判定知识格
│   │   ├── impact.ts         # 反向依赖闭包 + 变更影响选择
│   │   ├── bayes.ts          # 贝叶斯验证调度（先验/后验/信息增益排序，纯函数）
│   │   ├── changeset.ts      # 内容锚定变更集 + 来源归因
│   │   ├── regression.ts     # 回归判定与嫌疑文件归因
│   │   ├── runner.ts         # 增量验证调度（并发/超时/预算/可取消）
│   │   ├── report.ts         # 证明装配与五档评级
│   │   ├── excerpt.ts        # 智能摘录（balanced / head）
│   │   ├── trust.ts          # 哈希链 + 检查点签名 + 带外锚点
│   │   └── index.ts          # 领域导出
│   ├── engine.ts             # ProofEngine —— 宿主调用的命令式门面
│   ├── node-ports.ts         # Node 实现（spawn / fs / git / Ed25519）
│   ├── config.ts             # Schemastery 配置
│   ├── index.ts              # Cordis 插件入口
│   ├── dsh/                  ← 薄 Cordis 适配层
│   │   ├── tools.ts          # 四个模型可见工具
│   │   ├── observe.ts        # 脏区追踪 + 漂移检测
│   │   ├── prompt.ts         # proof:policy 段落
│   │   └── lsp-impact.ts     # 宿主 LSP → DefinitionResolverPort 适配
│   └── vendor/dsh-tools.ts   # 契约快照（pinned to dsh v0.2.1-alpha.1）
├── test/                     # 16 个测试文件（229 个测试）：真实 shell 集成、信任对抗、变更集溯源、LSP 影响融合、智能摘录、位置无关寻址、Node 适配层、runner 直测、贝叶斯调度核心
├── cordis.patch.yml          # bundle 层
└── examples/cordis.yml       # --patch 本地调试
```

**为什么领域核心不碰 `@deepseek-ai/*`：**

1. DSH 是开发者预览版，破坏性变更频繁。核心逻辑与 harness 版本解耦 → 升级不重写。
2. **可测性**：`test/` 用内存 Fs、假命令端口、假时钟就能覆盖全部判定逻辑；`test/07-integration.test.ts` 再用**真实 shell** 跑一遍，229 个测试全绿。
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
        verbose: false
```

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
npm test              # 229 个测试（node:test）
npm run build         # 产出 lib/
npm run bundle:check  # 打包契约自检
```

测试分层：

- `01`–`04` —— 纯核心：哈希、检查发现、影响分析、证据与判定
- `05` —— 引擎端到端（内存端口；v0.9 增补波式调度用例：提前认证、首败停、`set` 回归、确定性、预算降级）
- `06` —— 漂移检测
- `07` —— **真实 shell 集成**：真的 `npm run --silent test`，真的退出码，真的回归归因
- `08` —— 插件接线：四个工具、三个钩子、提示词段落、纯投影、配置校验
- `09` —— **信任对抗**：链断裂、全量重写（用本包自己的哈希函数）、回滚、基线替换、真实 Ed25519 密钥
- `10` —— **变更集溯源**：陈旧脏区豁免、还原即变更、未跟踪文件、外部回归不记账、引擎端到端
- `11` —— **LSP 影响融合**：goToDefinition 验证近似边、别名导入盲区发现、缓存与预算、降级不缩窄
- `12` —— **智能摘录**：显著失败行优先、整行尾窗、省略记账、（文本， 配置）纯函数确定性
- `13` —— **位置无关寻址**：跨机器 / 跨检出目录 / 跨用户名同址、`$HOME` 隐私、Windows 双斜杠形态
- `14` —— **Node 适配层**：`porcelain -z` 解析（rename/copy 双端、幻影路径）、git 能力探测、多字节 UTF-8 跨 chunk 捕获、Windows `.cmd` 垫片解析（真实 npm 模板、非标准垫片清晰报错）、`killedBySignal`、并发写唯一临时名 + rename 重试
- `15` —— **runner 直测**：并发 clamp、验证预算 skip、abort 传播、乱序完成重排、`killedBySignal` 判定（信号 ≠ 超时）、spawnError、excerpt 贯通
- `16` —— **贝叶斯调度核心**：公式阶梯逐档核对（ρ 平滑、s 的 1.0 / 1/(1+d) / 0.7 / 0.5、π 双侧 clamp、α clamp）、后验单调性与全概率恒等式（鞅）、VOI 非负且与独立转写的公式吻合、确定性 / 乱序不变、(π, α) 网格扫描

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
- **`proven` 允许存在预置红灯。** 一个本来就红的仓库不该让 Agent 无法工作。预置失败会在报告里显著列出，但不计入本次会话的责任。这是刻意设计，不是漏洞。
- **它不替代测试本身。** `dsh-proof` 编排并归因你已有的客观检查；它不生成测试用例。
- **DSH 是 v0.1/0.2 开发者预览版。** 插件契约会变。本插件已把依赖面最小化并钉死契约快照（`src/vendor/dsh-tools.ts`），但上游变更时仍需重新对齐。

---

## 十一、许可

MIT

## 鸣谢

插件契约、扩展点与打包模型来自 DeepSeek Harness 官方文档与源码（`deepseek-ai/deepseek-harness`，本文档对齐 `v0.2.1-alpha.1`）。
