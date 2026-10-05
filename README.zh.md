# dsh-proof

**证据驱动的完成证明与回归归因引擎** — DeepSeek Harness 插件

> 把「我做完了」从一句自我陈述，变成一条可复算的证据链。
> 把「改一处坏三处」从事后发现，变成事中归因。

```
$ proof_claim "修复了登录重定向 bug，并补了回归测试"
✓ PROVEN — 修复了登录重定向 bug，并补了回归测试
evidence root: 9f2c1ab47d0e
PROVEN — 3 check(s) passing, 0 regression(s), 1 pre-existing failure(s) left untouched.
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
| 无 | fail | `new-failure` | 无法区分，如实标注 |
| 无 | 未跑 | `not-run` | 证据过期 |

**这是本插件的头号差异点**：在一个本来就红的仓库里工作时，你不需要先修完所有历史遗留才能证明自己没做坏。这正是「大多数用户」的真实处境。

### 附加：工作区漂移检测

工具流之外的文件改动（IDE 编辑、构建产物、后台进程）会被指纹比对抓到，注入纠正性上下文：

```
⚠️ 你已经读过的文件在你的工具调用之外被改动了。你上下文里的副本已过期：
  · src/auth/redirect.ts
重新读取后再依赖它们，然后重新运行 proof_verify。
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
| `agent/turn-stopping` | 本轮改了东西但没做 `proof_claim` → 注入纠正性上下文；检测到漂移 → 注入 stale 警告 |
| `ctx.systemPrompt.section()` | 发布 `proof:policy` 段落，让模型知道规则存在，不必靠失败去摸索 |

## 五·五、信任模型（v0.2）：对抗被审计者

证据日志的对手不是黑客，是**它要审计的智能体本身**——模型有文件写工具，可以把 `.proof/` 整个重写，并用本包导出的哈希函数重算所有自洽地址。v0.1 的 `audit()` 只能抓这种「天真篡改」。v0.2 用四层机制把「证明者」和「验证者」分开：

1. **哈希链**：每行携带 `prev = sha256(上一行)`，改动或删除任意一行都会断链。
2. **签名检查点**：检查点承诺 `{记录数, 链头}`，由**宿主持有、模型不可见**的 Ed25519 密钥签名（密钥在 `$DSH_HOME/proof/keys/`，永远不在工作区内）。智能体可以伪造整条链，但**造不出签名**。
3. **带外锚点**：历史最高检查点同时镜像到密钥旁边的锚点文件（工作区之外）。把日志截断或回滚到旧检查点之前 → `rewind` 检测。
4. **基线摘要入链**：`baseline.json` 是普通 JSON 文件，整体替换原本不可察觉——现在保存时其 sha256 作为 marker 落链并紧跟检查点，任何事后替换都会被 `audit()` 标记 `baselineTampered`。

配套的存储隔离：默认 `evidenceStore: host` 把日志放到 `$DSH_HOME/proof/workspaces/<工作区指纹>/`，**完全移出智能体沙箱可写范围**；选择 `workspace` 模式（放回项目内）时，写入 `.proof/` 的变更类工具会被转用户审批。

`proof_status` 暴露全部信任遥测：`chainMode`（signed/unsigned/legacy）、`checkpoints`、`chainIntact`、`rewindDetected`、`baselineTampered`。`proven` 评级的可信度从此有了对抗性保证：**日志要么没被动过，要么动了就会被点名。**

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

---

## 六、架构：领域核心 + 薄适配层

对齐 DSH 自己的「接口 / 实现 / 消费者」三分法：

```
dsh-proof/
├── src/
│   ├── core/                 ← 纯领域层，零 @deepseek-ai/* 依赖
│   │   ├── ports.ts          # 唯一的对外接口（Command/Fs/Clock/Workspace）
│   │   ├── hash.ts           # 规范化 JSON + 内容寻址 + Merkle root
│   │   ├── checks.ts         # 客观检查发现（多语言）
│   │   ├── evidence.ts       # 证据模型 + append-only 事实源 + 基线
│   │   ├── impact.ts         # 反向依赖闭包 + 变更影响选择
│   │   ├── regression.ts     # 回归判定与嫌疑文件归因
│   │   ├── runner.ts         # 增量验证调度（并发/超时/预算/可取消）
│   │   └── report.ts         # 证明装配与五档评级
│   ├── engine.ts             # ProofEngine —— 宿主调用的命令式门面
│   ├── node-ports.ts         # Node 实现（spawn / fs / git）
│   ├── dsh/                  ← 薄 Cordis 适配层
│   │   ├── tools.ts          # 四个模型可见工具
│   │   ├── observe.ts        # 脏区追踪 + 漂移检测
│   │   └── prompt.ts         # proof:policy 段落
│   ├── vendor/dsh-tools.ts   # 契约快照（pinned to dsh v0.2.1-alpha.1）
│   ├── config.ts             # Schemastery 配置
│   └── index.ts              # Cordis 插件入口
├── test/                     # 95 个测试，含真实 shell 集成、信任对抗、变更集溯源、LSP 影响融合与智能摘录
├── cordis.patch.yml          # bundle 层
└── examples/cordis.yml       # --patch 本地调试
```

**为什么领域核心不碰 `@deepseek-ai/*`：**

1. DSH 是开发者预览版，破坏性变更频繁。核心逻辑与 harness 版本解耦 → 升级不重写。
2. **可测性**：`test/` 用内存 Fs、假命令端口、假时钟就能覆盖全部判定逻辑；`test/07-integration.test.ts` 再用**真实 shell** 跑一遍，95 个测试全绿。
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
        verbose: false
```

**`requireBaseline` 三档**

- `off` —— 不拦，只做记录与报告
- `warn` —— 默认。没有基线时给模型注入提醒
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
npm test              # 95 个测试（node:test）
npm run build         # 产出 lib/
npm run bundle:check  # 打包契约自检
```

测试分层：

- `01`–`04` —— 纯核心：哈希、检查发现、影响分析、证据与判定
- `05` —— 引擎端到端（内存端口）
- `06` —— 漂移检测
- `07` —— **真实 shell 集成**：真的 `npm run --silent test`，真的退出码，真的回归归因
- `08` —— 插件接线：四个工具、三个钩子、提示词段落、纯投影、配置校验
- `09` —— **信任对抗**：链断裂、全量重写（用本包自己的哈希函数）、回滚、基线替换、真实 Ed25519 密钥
- `10` —— **变更集溯源**：陈旧脏区豁免、还原即变更、未跟踪文件、外部回归不记账、引擎端到端

本地调试：

```sh
# 编辑 examples/cordis.yml 里的绝对路径后
pnpm dsh web --patch /absolute/path/to/dsh-proof/examples/cordis.yml
```

---

## 十、诚实边界

- **检查发现是启发式的。** 复杂 monorepo、自定义构建系统、Bazel/Nx/Turborepo 编排请用 `checks` 显式配置，并给出 `paths`，增量验证才会精确。
- **依赖图是近似的。** 动态 `import()`、反射、运行时字符串拼接的路径无法解析。近似**偏向过覆盖**（多跑一次，绝不漏判）。
- **检查点存在窗口期（v0.2）。** 最后一个签名检查点之后的记录受哈希链保护但不受检查点保护；窗口由 `checkpointEvery` 界定，且每次基线/验证/断言边界都会闭合它。删除锚点文件可以造成「回滚不可检测」——锚点因此放在智能体沙箱之外；若整台主机被攻陷，本插件的威胁模型不适用。
- **签名密钥的边界。** 密钥防的是「被审计的智能体」，不是「能读宿主文件的人」；主机被完全攻陷时一切本地信任机制都失效。
- **`proven` 允许存在预置红灯。** 一个本来就红的仓库不该让 Agent 无法工作。预置失败会在报告里显著列出，但不计入本次会话的责任。这是刻意设计，不是漏洞。
- **它不替代测试本身。** `dsh-proof` 编排并归因你已有的客观检查；它不生成测试用例。
- **DSH 是 v0.1/0.2 开发者预览版。** 插件契约会变。本插件已把依赖面最小化并钉死契约快照（`src/vendor/dsh-tools.ts`），但上游变更时仍需重新对齐。

---

## 十一、许可

MIT

## 鸣谢

插件契约、扩展点与打包模型来自 DeepSeek Harness 官方文档与源码（`deepseek-ai/deepseek-harness`，本文档对齐 `v0.2.1-alpha.1`）。
