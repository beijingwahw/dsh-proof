# FINDINGS-LEDGER — dsh-proof 七轮审计终局账本

> **范围**：v0.26.0（commit 767e45d，基线 1066/1066 绿）之前的全部审计轮次——v0.13 基线报告（`dsh-proof-deep-analysis-v0.13.md`，H1-H12/M1-M19）、v0.21 第一轮 27-agent 普查（`audit-v021/D2-consolidation.md`，H-01..H-34/M-01..M-85/L≈68）、v0.22 红队复核（`R1-redteam-closure.md`，N-1..N-8）、第三轮普查（`audit-v022/X2-consolidation.md`，X-H-01..19/X-M-01..64/L 家族）、第四轮普查（`audit-v023/VX-consolidation.md`，Y-H-01..17/Y-M-01..37/Y-L-01..40）、第七轮普查（`audit-v025/U1-U4`，U 系列）。v0.25（bdfc650）为无编号修复轮，其关闭动作记入对应条目。
>
> **契约**：`test/33-ledger.test.ts` 钉本账本的格式（四列、状态四值、CLOSED 类证据必须引用真实存在的测试文件与出现在该文件中的关键词「…」）、`residuals.json` 的字段完备性、README Honest limits 对每条 residual 的关键词覆盖、以及 H 级关闭计数 ≥ 各修复 commit 声称之和（42+19+17=78）。**契约是权威**：账本与登记册回改到契约绿为止。
>
> **状态**：`CLOSED`（已修 + 有测试钉）｜`CLOSED-WITH-NOTES`（已修 + 有钉，边界在行内一句声明）｜`RESIDUAL-DOCUMENTED`（留档未修/已修未钉——全部登记于 `residuals.json`）｜`SUPERSEDED`（被后续更大的修复动作覆盖，行内注明被谁）。
>
> **判定口径**：H 级逐条，最终状态取「最后一轮有效修复 + 存活钉」；M/L 级按家族合并行，**家族行状态 = 该族主导状态**，族内 RESIDUAL 成员在行内注明并全部登记于 residuals.json。M/L 关闭判定依据 = 修复 commit 声明（fdd06db "most security-relevant mediums"、后续各轮 wiring 清单）+ 测试钉存在性 + 后续轮次未再报；**未逐条重验**的以行内「未逐条重验」标注——这是本账本的核验边界，不是关闭声明。证据列格式：`test/NN-xx.test.ts「关键词」`（关键词真实出现在该文件中——契约 (a) 强制）。

---

## 第 0 轮 · v0.13 基线（H1-H12 / M1-M19）

### H 级（15 个判定点：H5 拆①②、H9 拆①②③）

| ID | 标题（短） | 状态 | 证据 |
|---|---|---|---|
| H1 | 伪造 checkpoint 洗白证据链（count=1e999 直通/外来 keyId/rewind 自报） | CLOSED-WITH-NOTES | test/09-trust.test.ts「H-08」+「H-09」（count 域+锚精确对应答+缴械形态拒绝，v0.17/v0.22）；PTL/bundle 面复发由 H-06/H-05 链关闭（test/28-ptl-cli.test.ts「H-06」）；边界：锚文件删除/整文件垃圾需信任根写权限（README『On machines without the signing key』条目） |
| H2 | 零观察 verify 可判 proven（runCheckIds 死字段/波折叠非决断） | CLOSED | test/05-engine.test.ts「decisive」（observedDecisive 消费 + 波折叠仅决断记录，双向钉）；库 API 面尾巴由 X-M-01/X-L-09 家族续管 |
| H3 | endorsementUnlock 解锁未完成的验证过程 | CLOSED | test/05-engine.test.ts「H4」（vanished/scriptDrifted/baselineTampered 门齐，v0.22 收口） |
| H4 | api-surface 漏报带类型注解的导出 | CLOSED | test/17-contract.test.ts「phantom」（注解不藏名、解构注解不产 phantom） |
| H5a | checkId 不含脚本内容——学习先验侵蚀 drift 折扣 | CLOSED-WITH-NOTES | test/16-bayes.test.ts「H-03」+ test/05-engine.test.ts「N-6」（时间切片→纪元感知→vouched floor 全链）；边界：篡改体可诚实重挣信任（by design）、重锚换体 swap 上链可见（N-6 钉） |
| H5b | 基线检查静默消失 | CLOSED | test/05-engine.test.ts「vanished」（detectVanishedChecks + stale 路径 + unlock 门） |
| H6 | git 查询失败吞成确定性空答案 | CLOSED-WITH-NOTES | test/10-changeset.test.ts「degraded」（requireGitOk + degraded→forceAll 四连）；边界：optional 能力与证据层入口的残留由 M-27/M-34 家族行跟踪（v0.22 域批） |
| H7 | 超时死因系统性错标 | CLOSED | test/14-node-ports.test.ts「timedOut」（timedOut 一等事实 + 三形态映射 + 真实进程超时） |
| H8 | Python import 三形态漏边 | CLOSED-WITH-NOTES | test/03-impact.test.ts「H-24」+「Y-H-07」（点语义/候选/名单/续行，v0.22-v0.24 全链）；边界：`from .import x`（点后无空格）整行丢边（Y-L-30，L 家族留档） |
| H9a | pathsIn 数组分支绕过键白名单 | CLOSED | test/06-observe.test.ts「H9a」（数组六连钉） |
| H9b | shell 路径 external 误归因（假陈述注入模型） | CLOSED-WITH-NOTES | test/06-observe.test.ts「shellUsed」（记账线 uncertainExternal→unknown）；叙事线随 M-29/X-M-53 家族收口（v0.25 移除 task 名单项）；边界：brand-new shell 文件归因仍盲（README v0.15 条目） |
| H9c | bash 命令字符串穿透证据守卫 | CLOSED-WITH-NOTES | test/24-adapters-shared.test.ts「N-1」（能力门控值扫：runner 名/argv/未知名）；边界：保守子串匹配，改写避拼法可溜过（README v0.22『Shell-command guarding』条目=注册残留 M11 同域） |
| H10 | Windows 大小写变体绕过证据守卫 | CLOSED-WITH-NOTES | test/24-adapters-shared.test.ts「H-25」（双侧折叠+尾点/空格+根级投影+设备前缀，v0.22-v0.24）；边界：8.3 短名未折（版本条件性，现代 NTFS 默认不生成——Y-L-10 留档） |
| H11 | Ed25519 私钥读失败静默轮换密钥 | CLOSED | test/14-node-ports.test.ts「H11」（非 ENOENT 拒绝轮换；原子公钥首写 M-83 同钉） |
| H12 | 半真基线落盘（skipped/timeout 不触发守卫） | CLOSED | test/05-engine.test.ts「aborted」（aborted∨skipped∨timeout∨error 全拒锚 + baseline/aborted marker——error 项 M-36 随 v0.22 域批补齐，代码核验） |

### M 级（家族行）

| ID | 标题（短） | 状态 | 证据 |
|---|---|---|---|
| M1..M19 | v0.13 中危 19 项 | CLOSED-WITH-NOTES | 16 CLOSED（M1-M4/M6/M8-M10/M12-M14/M18/M19；M5→M-70、M7→M-73、M15 组件族、M19d MCP 面均随 v0.22 批关闭——钉散布 test/01-31）；1 CW-N（M16 嵌套 glob 单层退化，checks.ts 文档声明）；2 RESIDUAL（M11 筛检≠沙箱、M17 非有限折叠——residuals.json）；代表钉 test/19-synthetic.test.ts「M11」 |

---

## 第一轮 · v0.21 普查（H-01..H-34 / M-01..M-85 / L≈68）

### H 级（34 条逐条）

| ID | 标题（短） | 状态 | 证据 |
|---|---|---|---|
| H-01 | 工具名分类器 camelCase 失明（MultiEdit 绕门/Read 误归因） | CLOSED-WITH-NOTES | test/06-observe.test.ts「H-01」（锚定名单+未知名默认变异，v0.22）+ test/24-adapters-shared.test.ts「X-H-13」（值扫消键名维度，v0.23）；边界：只读名单 `find` 投机面 + 保守匹配（README v0.22 条目） |
| H-02 | shell 命令字符串穿透证据守卫 | CLOSED-WITH-NOTES | test/06-observe.test.ts「H-02」+ test/25-cc.test.ts「H-02」（命令串子串扫，v0.22）→N-1/X-H-13/Y-H-10 链（值扫+双端窗）；边界：保守子串匹配（README v0.22 条目） |
| H-03 | 学习先验侵蚀 β 折扣（drifted 单次假 pass 即 proven） | CLOSED-WITH-NOTES | test/16-bayes.test.ts「H-03」（时间切片+β=0.5，v0.22）→ X-H-01/X-H-19（suspect 过滤+纪元，v0.23）→ Y-H-05/Y-M-14（priorsFor 地板+代内末见，v0.24）；边界：诚实重挣 by design、链上留痕（R1 变体注记） |
| H-04 | endorsementUnlock 缺 vanished 门（endorse 洗白删检查） | CLOSED | test/05-engine.test.ts「H4」（vanished/scriptDrifted/baselineTampered 全门，v0.22） |
| H-05 | delegation 提交无信任根（空/自洽伪造 bundle+自报 proven） | CLOSED-WITH-NOTES | test/05-engine.test.ts「H-05」（锚键签名 checkpoint 必需，v0.22）→X-H-02/03/04（真 signer+移植签名+尾记录，v0.23：test/22-bundle.test.ts「X-H-04」）→Y-H-08（不可裁定响亮封顶，v0.24）；边界：bundle 验证≠本地重执行（README v0.19 条目） |
| H-06 | PTL 发布栈零签名裁决（外来 keyId 借 operator 公证化） | CLOSED-WITH-NOTES | test/28-ptl-cli.test.ts「H-06」（CLI 锚键门控+无信任根响亮拒绝，v0.22）→X-H-11（两面统一，v0.23）→Y-H-01（head-liared 不入发布，v0.24）→U1-F2（主路身份核对，v0.26：test/05-engine.test.ts「laundering」）；边界：PTL 单操作者（README v0.18 条目） |
| H-07 | verify --bundle 不验 publishedHead.sig/logId；sth 缺席=通过 | CLOSED | test/28-ptl-cli.test.ts「operator」（六步全查、键缺席=fail，v0.22；Y-M-20 三面统一 v0.24） |
| H-08 | 无密钥主机：冒名锚键+膨胀 count 全量洗白 | CLOSED | test/09-trust.test.ts「H-08」（精确 (count,head) 对应答，keyless 同样适用，v0.22） |
| H-09 | 锚文件 4 行篡改永久缴械（sig:''/负 count） | CLOSED | test/09-trust.test.ts「H-09」（parseAnchorEx 三态 invalid→fail ok + preSign 拒签，v0.22） |
| H-10 | waiveDelegation 豁免授权完全未认证 | RESIDUAL-DOCUMENTED | 产品面已修（v0.22：by=issuedByWorkspace 或持锚键，waive 不上 MCP 面；钉 test/05-engine.test.ts「H-10」）；残留=库边界知识认证——residuals.json#H-10 |
| H-11 | taskVerdict ownGrade 未认证证词被当权威折入根判定 | CLOSED-WITH-NOTES | test/05-engine.test.ts「H11」（申报超派生→discrepancy，派生腿站稳，v0.22）+ X-H-07（未提交叶 compose unproven，v0.23：test/29-obligations.test.ts「X-H-07」）；边界：派生腿读地板下 protected marker（v0.25 K1） |
| H-12 | agent-team 桥把宿主 parentTaskId 直投 task-N 命名空间 | CLOSED-WITH-NOTES | test/08-plugin-wiring.test.ts「H-12」（hostId→engineId 映射翻译+lost-parent 响亮，v0.22）；边界：桥实验性、默认关（README v0.19 条目；U3-F7 映射读残留注册） |
| H-13 | training×engine 缝合断裂（causal-purity 结构性不可执行+时序错配） | CLOSED-WITH-NOTES | test/30-training.test.ts「H-13」（audit 闸门+基线切片，v0.22）→v0.24 训练切片止于 vouched checkpoint→v0.25 trainingAnchor 走 lastWellFormedCheckpoint（代码核验）→v0.26 latest() 地板（U2-F2）；边界：导出信任地板下已审的链 |
| H-14 | training 同态重跑灌水（无限 reward-1.0 正样本） | CLOSED | test/30-training.test.ts「H-14」（(checkId,status,outputDigest) 去重 + dedupedCount 上 manifest，v0.22） |
| H-15 | economics 域值缺口（Infinity 溢出/quoteId 折叠碰撞/非法 grade 直通） | CLOSED | test/31-economics.test.ts「H-15」（MONEY_CEILING+roundMoney throw+grade 双面校验，v0.22） |
| H-16 | proof_training_export path 零 confinement | CLOSED-WITH-NOTES | test/23-mcp.test.ts「H-16」+ test/05-engine.test.ts「N-2」（绝对/UNC/`..` 拒绝 + case/尾点折叠，v0.22）；边界：confinement 域=store 与信任根（X-M-13/Y-H-11 链收口） |
| H-17 | τ 覆盖门对被检代码可伪造（NODE_V8_COVERAGE 交给敌手） | RESIDUAL-DOCUMENTED | 防御在位并钉（每轮暂存+mtime 窗+窗外毒化+require 拒 synthetic 见证：test/05-engine.test.ts「H-17」、自删脚本记 error：test/05-engine.test.ts「X-H-05」）；残留=窗内自伪造不可判——residuals.json#H-17（README v0.22『V8 coverage defense』条目） |
| H-18 | 超时只杀直接子进程（进程树存活、verify 永挂） | CLOSED | test/14-node-ports.test.ts「H-18」（进程组负 pid+Job Object+settle 兜底定时器，v0.22） |
| H-19 | 适配器会话存储无认证（账本整体可伪造） | RESIDUAL-DOCUMENTED | 防御在位并钉（canonical digest+体不符址重置+stderr 广播+原子写+按 workspaceKey 隔离：test/24-adapters-shared.test.ts「H-19」）；残留=同用户进程可重算 digest 整体伪造（行为缓存非信任锚）——residuals.json#H-19 |
| H-20 | hasBaselineOnDisk 只查形状（伪造 20 字节解除基线门） | CLOSED | test/25-cc.test.ts「H-20」（自地址检查，v0.22）+ test/25-cc.test.ts「Y-H-13」（链绑定 chainDigest 七调用点，v0.24） |
| H-21 | 跨进程配置分叉（DSH_PROOF_EVIDENCE_DIR 三面不同义） | CLOSED | test/26-opencode.test.ts「H-21」（resolveAdapterEnv 单点解析三面共用 + EVIDENCE_STORE 拼写拒绝，v0.22） |
| H-22 | hook 接线 repo 可控，SessionStart 仍断言"强制在位" | CLOSED | test/25-cc.test.ts「H-22」（"DETECTED, not guaranteed"+可证伪自检，v0.22；自检路径具体化 X-M-45 随 v0.26 代码核验） |
| H-23 | baseline.json 无完整性校验（剥字段永久关防御） | CLOSED | test/04-evidence.test.ts「H-23」（canonical 自地址+链绑定 digest，v0.22）；跨会话吸收由 X-H-08（v0.23 preSign 作者规则）+v0.25 地板+v0.26 全 protected 名册（U1-F1）链关闭 |
| H-24 | Python import 三形态漏边（v0.13 H8 本轮重报） | CLOSED-WITH-NOTES | test/03-impact.test.ts「H-24」（点语义+候选+名单+裸导入+多站点，v0.22）→X-H-17（双向解析，v0.23）→Y-H-07（续行 off-by-one，v0.24）；边界：无空格 `from .import` 形（Y-L-30，L 家族留档） |
| H-25 | 守卫折叠不完整的 Win32 变体（UNC 根/8.3/尾点） | CLOSED-WITH-NOTES | test/24-adapters-shared.test.ts「H-25」（case+反斜杠+尾点/空格+根级投影，v0.22）+「X-H-12」（设备前缀/盘符相对，v0.23）+「Y-H-12」（index 面 lockstep，v0.24）；边界：8.3 短名未折（版本条件性） |
| H-26 | host 模式绝对路径直写真实 store 放行 | CLOSED-WITH-NOTES | test/24-adapters-shared.test.ts「H-26」（host 模式+trustRoot 武装 absoluteInside，v0.22）+ test/08-plugin-wiring.test.ts「X-H-16」（apply 面 v0.24）；边界："沙箱外"是 harness 契约（README 顶层声明） |
| H-27 | checkpointInternal 对物理尾盲签（系统给伪造链头补签） | CLOSED | test/09-trust.test.ts「H-27」（preSignAudit：走查/尾同步/同键伪签/锚态——任一命中拒签+SIG_REFUSED 上链，v0.22） |
| H-28 | normalizeOutput 占位符无转义（outputDigest 碰撞） | CLOSED-WITH-NOTES | test/01-hash.test.ts「H-28」（折叠前检测字面占位符+RAW_PLACEHOLDER_MARKER，v0.22）；边界：duration 折叠等价类 by-design（内容寻址等价类，R1 注记） |
| H-29 | budgetMs 非有限直通（perf 义务恒 met） | CLOSED | test/17-contract.test.ts「H-29」（工具面+契约面双门，v0.22）；天文有限值 1e308 由三面 1e12 上限封（Y-M-07 v0.24，U3-F12 核验 lockstep） |
| H-30 | 矛盾证词 reject@0.99 全链路存活并抬升置信度 | CLOSED | test/18-attest.test.ts「H-30」（verdict↔probability 方向一致 + reject 只记折扣不混合，v0.22；写侧镜像 X-M-56 核验 lockstep） |
| H-31 | synthetic 筛检黑名单缺全局 fetch/WebSocket/cluster/dns/tls | CLOSED-WITH-NOTES | test/19-synthetic.test.ts「H-31」（FORBIDDEN_GLOBALS 调用形态+能力扩列，v0.22；计算成员/别名/node:vm v0.23）；边界：静态筛检≠沙箱（README v0.12 条目=注册残留 M11） |
| H-32 | marker 通道无鉴权且 last-wins（尾部追加即注入背书/基线） | CLOSED | test/09-trust.test.ts「H-32」（位置取证 suspect 排除取代字段，v0.22）→one-door（v0.23）→vouched floor 新鲜追加只计数不采信（v0.25）；升级盲区 X-H-06 由代际回退关闭（test/05-engine.test.ts「X-H-06」） |
| H-33 | excerpt NaN budget（空文本+NaN 账目） | CLOSED | test/12-excerpt.test.ts「H-33」（非有限 budget throw TypeError，v0.22） |
| H-34 | LSP 查询无超时（服务器挂起→verify 永不返回） | CLOSED | test/11-lsp-impact.test.ts「H-34」（deadline 竞速+transient 不缓存，v0.22；累计墙钟 M-30/Y-M-30 v0.25 补：test/11-lsp-impact.test.ts「M-30」） |

### M 级（家族行，85 项）

| ID | 标题（短） | 状态 | 证据 |
|---|---|---|---|
| M-01..M-19 | 验证语义/合成检查/SLA/训练家族 | CLOSED-WITH-NOTES | v0.22-v0.26 批关闭：M-01 再执行重筛+缺脚本拒绝（v0.26 U1-F4：test/05-engine.test.ts「vanished」）、M-02 协议行有损读、M-03 SLA 锚定（v0.24）、M-04..M-06 报告契约面、M-07 POSIX 形态、M-08 飞行预算、M-09 TrustWeights 域（含 humanProbability，v0.24 代码核验）、M-10 证词 gen/appeal 取代、M-11..M-19 逐项随域批；代表钉 test/18-attest.test.ts「H-30」 |
| M-20..M-24 | 训练编码/经济域值家族 | CLOSED-WITH-NOTES | v0.22 H-13/H-14/H-15 同批（durationMs 过滤+域校验）；M-24 零断言除数语义改为 sunk-cost 可见展示（economics.ts decisiveCount 注释声明）；代表钉 test/31-economics.test.ts「H-15」 |
| M-25..M-31 | 运行时/路径/LSP/symlink 家族 | CLOSED-WITH-NOTES | M-25 excerpt 账目、M-26 `./` 死模式、M-27 optional git 降级、M-28 chunk 解码（v0.23）、M-29 输入背压（v0.24 V6-F5 代码核验）、M-30 累计墙钟（v0.25）、M-31 symlink 拒绝 append；代表钉 test/14-node-ports.test.ts「M-31」 |
| M-32..M-40 | 信任层快照/锚/键/基线门家族 | CLOSED-WITH-NOTES | M-32 单快照纪律（U2 核验 selectionSnapshot 单读）、M-33 拒签代际计费（v0.24：test/09-trust.test.ts「M-33」）、M-34/M-35 git 快照与 UNC、M-36 error 拒锚（代码核验）、M-37 可见化、M-38 删除墓碑→吸收嫌疑（v0.25：test/05-engine.test.ts「baselineAbsorptionSuspect」）、M-39 键归一+legacy 探测（v0.22）、M-40 gate 链绑定（v0.24：test/25-cc.test.ts「Y-H-13」）；代表钉 test/09-trust.test.ts「M-33」 |
| M-41..M-50 | 适配器接线/配置域/MCP 工具面家族 | CLOSED-WITH-NOTES | M-41 叙事消毒、M-42 surfacedDrift、M-43 Stop 持久化、M-44 环境旋钮、M-45 自检路径具体化（v0.26 代码核验）、M-46 数值域（Bayes 旋钮构造期 throw=claim 2；timeoutMs min(1)=v0.25；直构面 verifyBudgetMs/concurrency 透传随 Y-L-07 L 家族留档）、M-47 信任根收容告警（v0.24 代码核验）、M-48 折空守卫（代码核验退化分支）、M-49 entryPoints、M-50 MCP claim；代表钉 test/08-plugin-wiring.test.ts「M-49」 |
| M-51..M-60 | MCP 治理/PTL/bundle 家族 | CLOSED-WITH-NOTES | M-51..M-54 工具面批、M-55 manifest 封闭、M-56 transparency 裁决（v0.24）、M-57 锚跨字段、M-58 方言锁死→协议版本一致性 claim 5 缓解（老 bundle 需历史实现=已声明设计代价）、M-59 recorded 生产化、M-60 savePtlHead 验旧头（v0.23：test/27-transparency.test.ts「M-60」）；代表钉 test/27-transparency.test.ts「M-60」 |
| M-61..M-70 | PTL CLI/测试接线/MCP 边角家族 | CLOSED-WITH-NOTES | M-61 撕裂尾、M-62 并发 append、M-63 RangeError→裁决、M-64 生产分支 claim 化、M-65 evidenceLogPath、M-66 shellUsed 接线、M-67 指令面、M-68 exports 放行（package.json 核验）、M-69 工具清单如实（README 13 工具条目核验）、M-70 decision 门；代表钉 test/28-ptl-cli.test.ts「H-06」 |
| M-71..M-85 | 工具文案/替身/协议边角家族 | CLOSED-WITH-NOTES | M-71..M-82 逐项随批（M-77 last-line、M-80 capToolString、M-83 原子公钥：test/14-node-ports.test.ts「M-83」）；M-84 替身保真度（v0.25 FakeSigner 真密钥；残余 U3-F9/U4-L1/L2 注册）；M-85 协议边角（v0.23+背压/解码批）；代表钉 test/14-node-ports.test.ts「M-83」 |

### L 级（家族行）

| ID | 标题（短） | 状态 | 证据 |
|---|---|---|---|
| L-v021 家族 | v0.21 低危 ≈68 项（D2 §L 归并） | SUPERSEDED | 存活者以 X/Y/U 轮编号重新跟踪（X2 §6.3 衔接表列名映射：appendLine symlink→M-31、M-84→X-M-62 等）；其余随 v0.22 hardening 批关闭；未逐条重验 |

---

## 红队 · v0.22（N-1..N-8）

| ID | 标题（短） | 状态 | 证据 |
|---|---|---|---|
| N-1 | shell 扫描按名单门控（11 runner 名/argv/嵌套形态直通） | CLOSED | test/24-adapters-shared.test.ts「N-1」（能力门控：任何变异类+命令串入扫，v0.22 终版）；键名维度残余由 X-H-13 值扫关闭（v0.23） |
| N-2 | exportTrainingData 路径 confinement 缺 case/尾点折叠（`.PROOF` 截断日志） | CLOSED | test/05-engine.test.ts「N-2」（case 不是边界——折叠比对，v0.22 终版）；信任根入折叠域 X-M-13→v0.23 one-fold |
| N-3 | τ 覆盖门对"运行中自伪造"放行 | CLOSED-WITH-NOTES | require 档拒 synthetic 见证 + 自删脚本记 error（v0.22/v0.24：test/05-engine.test.ts「Y-H-17」钉 require+池身份机制；test/32 claim 9 行为钉）；边界：窗内自伪造见 residuals.json#H-17（README v0.22 条目） |
| N-4 | H-32 的 κ/delegation suspect 排除接在死通道上 | SUPERSEDED | 被 v0.23 one-door（全部消费走 createVerifiedView，test/32「claim 1b」前身）+ v0.25 vouched floor（信任决策只读地板下）覆盖——原「改两个消费点」的一行修法被更大架构动作取代 |
| N-5 | 引擎面 PTL 发布不验所选 checkpoint 自身签名 | SUPERSEDED | 被 X-H-11（v0.23 两面统一验签：test/28-ptl-cli.test.ts「X-H-11」）+ Y-H-01（v0.24 head-liared 发布谓词：test/32「claim 7」）覆盖 |
| N-6 | 重铸洗白：直调 proof_baseline 锚定篡改脚本→一发 proven | CLOSED-WITH-NOTES | test/05-engine.test.ts「N-6」（重锚把 script-body 突变 swap 上链，v0.22 终版）；纪元感知切断旧体史继承（v0.23/v0.24：test/05-engine.test.ts「Y-H-15b」）；边界：proof_baseline 直调无审批门=已声明边界（换体事实链上可见） |
| N-7 | proof/verified、delegation/* 不在保护名单 | CLOSED | test/32-claims.test.ts「claim 6」（受保护名单 superset 契约——覆盖一切被信任消费的标签，v0.24；代码核验前缀族） |
| N-8 | mcp-server 接受 `<ptlDir>/operator-key` 同目录自指键位 | RESIDUAL-DOCUMENTED | 同目录键位作为显式回退保留（README v0.22『PTL operator key』条目=v0.24 起启动告警 V4-M7 代码核验）；残留注册 residuals.json#N-8 |

---

## 第三轮 · v0.23 普查（X-H-01..19 / X-M-01..64 / L≈135）

### H 级（19 条逐条）

| ID | 标题（短） | 状态 | 证据 |
|---|---|---|---|
| X-H-01 | scriptDriftFirstSeen 不走 suspect 过滤（伪造 marker 回拨边界复活 H-03） | CLOSED | test/05-engine.test.ts「X-H-01」+「Y-H-15a」（读点走 markersWith suspect 过滤，v0.23；对抗形态钉 v0.24） |
| X-H-02 | submitDelegation 不传 anchorSigner——验签死代码 | CLOSED | test/22-bundle.test.ts「X-H-02」（signer 选项面+真锚定判定，v0.23） |
| X-H-03 | 签名 checkpoint 重放/移植（payload.head 从不与 walked 比对） | CLOSED | test/09-trust.test.ts「X-H-03」（replayed signatures invalid not verified，v0.23；Y-M-37 headLiars 契约对齐 v0.24） |
| X-H-04 | tailRecords 尾部搭载只报不罚 → proven | CLOSED | test/22-bundle.test.ts「X-H-04」（尾记录=problem，v0.23） |
| X-H-05 | 自删 synthetic 脚本绕过 require 排除（缺文件静默 continue） | CLOSED | test/05-engine.test.ts「X-H-05」（缺文件→error 上链+池身份 keyed 排除，v0.24/v0.26；test/32 claim 9） |
| X-H-06 | 旧链升级 suspect 全杀（DAG 蒸发/taskId 回卷） | CLOSED | test/04-evidence.test.ts「X-H-06」（代际回退 degraded 池 + taskId max+1，v0.23；读失败区分 v0.25 代码核验 catch{return[]} 移除） |
| X-H-07 | 未提交叶子组合出 proven 零 blocker | CLOSED | test/29-obligations.test.ts「X-H-07」（unsubmitted leaves compose unproven，v0.23） |
| X-H-08 | 跨会话尾部吸收（ensureTail 吸收+宿主补签公证） | CLOSED | test/09-trust.test.ts「X-H-08」（preSignAudit 拒签 foreign baseline/saved，v0.23）→v0.25 地板（追加只计数）→v0.26 全 protected 名册（U1-F1：test/09-trust.test.ts「U1-H1」） |
| X-H-09 | verdict 只消费 baselineTampered 不消费 audit.ok | CLOSED | test/05-engine.test.ts「X-H-09」（audit.ok 四路消费封顶，v0.23；Y-H-16 钉补 v0.24） |
| X-H-10 | savePtlHead 对已存头不验签（自指基线） | CLOSED | test/27-transparency.test.ts「X-H-10」（verifyExistingHead uncertain=refuse，v0.23；Y-H-06 不可解析头=拒绝 v0.24） |
| X-H-11 | 引擎面发布验签缺失集（无锚照发/锚定外来键两面都发） | CLOSED | test/28-ptl-cli.test.ts「X-H-11」（统一发布谓词，v0.23）+ test/05-engine.test.ts「laundering」（主路 workspace 身份，v0.26 U1-F2） |
| X-H-12 | `\\?\` 设备前缀与 `C:rel` 盘符相对绕过四层守卫 | CLOSED | test/24-adapters-shared.test.ts「X-H-12」（设备前缀剥除+盘符相对投影，v0.23；index 面 lockstep v0.24=claim 3c/3d） |
| X-H-13 | 命令串键名白名单+只读名单信任域 | CLOSED | test/24-adapters-shared.test.ts「X-H-13」（值扫描取代键名枚举，v0.23；界窗梯子 Y-H-10 v0.24=claims 3/4） |
| X-H-14 | PATH_KEYS 键名大小写敏感+常用拼写缺失 | CLOSED | test/24-adapters-shared.test.ts「X-H-14」（键名折叠+补全，v0.23；Y-M-23 全列落地代码核验 foldKey） |
| X-H-15 | 相对 DSH_PROOF_TRUST_DIR 把信任根落进工作区 | CLOSED | test/23-mcp.test.ts「X-H-15」（相对信任根=响亮启动失败，v0.23） |
| X-H-16 | apply 面（index.ts）默认 host 模式守卫整体缺失 | CLOSED | test/08-plugin-wiring.test.ts「X-H-16」（DSH 面守卫+键派生对齐，v0.24） |
| X-H-17 | Python 点号算术两处漏边（off-by-one+JS 点 specifier） | CLOSED | test/03-impact.test.ts「X-H-17」（双向解析+KAT，v0.23；Y-H-07 续行 v0.24） |
| X-H-18 | own-regressed 被缺失子洗成可豁免 stale（单调性倒挂） | CLOSED | test/29-obligations.test.ts「X-H-18」（forged/regressed 优先，waiver 买不断，v0.23） |
| X-H-19 | drift 边界无 baseline 纪元感知（重锚循环继承绿史） | CLOSED | test/05-engine.test.ts「X-H-19」+「Y-H-15b」（纪元感知+代内末见，v0.24） |

### M 级（家族行，64 项）

| ID | 标题（短） | 状态 | 证据 |
|---|---|---|---|
| X-M-01..X-M-19 | 贝叶斯旋钮/SLA 锚定/基线代际/发布治理家族 | CLOSED-WITH-NOTES | X-M-01 旋钮域（v0.24 claim 2：test/21-protocol.test.ts「Y-H-04」）、X-M-02 synthetic 三时刻、X-M-03 SLA confidence 锚、X-M-04/06 基线移除集与空基线、X-M-05 键探测、X-M-07/08 无签与冒名形态、X-M-09 label 覆盖、X-M-10 训练锚（v0.24 lastWellFormedCheckpoint 代码核验）、X-M-11 dirtDigest、X-M-12 unlock 可达性（v0.24 重写）、X-M-13 导出折叠域、X-M-14 结构面目标集、X-M-15 operator 键名（Y-H-11 v0.24）、X-M-16 observe 叙事、X-M-17 导出快照（v0.25 地板读）、X-M-18 读放大（单遍 view）、X-M-19 封顶记账；代表钉 test/21-protocol.test.ts「Y-H-04」 |
| X-M-20..X-M-38 | 委派图/桥/MCP 传输/PTL 运维家族 | CLOSED-WITH-NOTES | X-M-20 环递归（detectCycles 迭代化代码核验）、X-M-21 读失败铸造（verified view 化）、X-M-22/23 后写覆盖与末条胜出（fresh-append 名册+拒签）、X-M-24 映射回灌（v0.25）、X-M-25 关键路径 mark、X-M-26 桥幂等（v0.25）、X-M-27 响亮参数、X-M-28 chunk 解码（v0.23）、X-M-29 输入背压（v0.24 代码核验）、X-M-30 LSP 墙钟（v0.25）、X-M-31 叶身份核对（v0.26）、X-M-32 半发布预检（v0.24）、X-M-33 倒序回扫（v0.25）、X-M-34 uncertain=fail（v0.24）、X-M-35 badLines、X-M-36 读失败区分、X-M-37 零记录日志、X-M-38 PTL_DIR 收容（v0.24 代码核验）；代表钉 test/04-evidence.test.ts「X-H-06」 |
| X-M-39..X-M-64 | gate 域/路径旋钮/文档/测试强度家族 | CLOSED-WITH-NOTES | X-M-40 链绑定（v0.24）、X-M-41 会话迁移、X-M-42 syntheticDir pattern、X-M-43 叙事消毒、X-M-44 OpenCode ask 死锁（v0.23 proof_* 豁免）、X-M-45 自检路径（v0.26 代码核验）、X-M-46 形状漂移、X-M-47 布线名单 RESIDUAL（residuals.json）、X-M-48 消失分支守卫（代码核验）、X-M-49 裸文件名归因、X-M-50 字符串上界（残留并入 U3-F11 注册）、X-M-51 天文预算（三面 1e12 代码核验）、X-M-52 墙钟（v0.25）、X-M-53 task 名单（v0.25 移除）、X-M-54 标记行检测集、X-M-55 漏边族、X-M-56 jury 镜像（lockstep 代码核验）、X-M-57 筛检变体（边界=M11 注册）、X-M-58 内联 type export、X-M-59 磨曲线档位、X-M-60 launder 计桶、X-M-61 数字失实（v0.24）、X-M-62 替身族（v0.25）、X-M-63 对抗路径测试批（v0.24-26）、X-M-64 折空守卫（代码核验）；代表钉 test/24-adapters-shared.test.ts「X-H-12」 |

### L 级（家族行）

| ID | 标题（短） | 状态 | 证据 |
|---|---|---|---|
| X-L-1..X-L-14 家族 | v0.23 普查低危（≈135 项归并 14 家族） | SUPERSEDED | 存活者以 Y-L/U 编号续跟踪（VX 衔接：W8/W9/W11/W12/W13/W14 系列映射）；其余随 v0.23-v0.25 批关闭；未逐条重验 |

---

## 第四轮 · v0.24 普查（Y-H-01..17 / Y-M-01..37 / Y-L-01..40）

### H 级（17 条逐条）

| ID | 标题（短） | 状态 | 证据 |
|---|---|---|---|
| Y-H-01 | headLiared 不进发布选点（移植 checkpoint 公证进 PTL） | CLOSED | test/28-ptl-cli.test.ts「Y-H-01」（发布谓词完整，v0.24；test/32 claim 7 双面钉） |
| Y-H-02 | 拒签无赦免 × audit 封顶 = 永久 stale | CLOSED | test/09-trust.test.ts「Y-H-02」（代际计费+重锚赦免，v0.24；test/32 claim 8） |
| Y-H-03 | createVerifiedView 零生产调用（one door 主张落空） | CLOSED | test/05-engine.test.ts「Y-H-03」（引擎全消费 verified，v0.24）+ test/32-claims.test.ts「claim 1b」（门契约化，v0.26 收紧到 readChainMarkers 进口集） |
| Y-H-04 | validateBayesKnobs 死代码（旋钮零校验三处假话） | CLOSED | test/21-protocol.test.ts「Y-H-04」（构造期/报告面双门 throw，v0.24；test/32 claim 2） |
| Y-H-05 | priorsFor 吃未覆盖尾部伪造 evidence 行 | CLOSED | test/05-engine.test.ts「Y-H-05」（记录切片止于 vouched checkpoint，v0.24/v0.25） |
| Y-H-06 | 不可解析 sth.json = 冷启动（种植头跳过一切检查） | CLOSED | test/27-transparency.test.ts「Y-H-06」（不可解析=拒绝非冷启动，v0.24） |
| Y-H-07 | 括号续行路径复活点尾 off-by-one | CLOSED | test/03-impact.test.ts「Y-H-07」（续行条件拼接+KAT，v0.24） |
| Y-H-08 | submitDelegation 无锚/signer 失败回退 keyId 存在性判定 | CLOSED | test/05-engine.test.ts「Y-H-08」（不可裁定响亮封顶+signer 失败不静默，v0.24） |
| Y-H-09 | 吸收检测是事后拒签非阻止（判决先铸） | CLOSED-WITH-NOTES | test/05-engine.test.ts「Y-H-09」（地板使追加不可信+拒签名册，v0.24-v0.26）；边界：未签名链无地板整链可读（README v0.25『vouched floor』条目） |
| Y-H-10 | 值扫描三界窗梯子+两面 sweep 分叉 | CLOSED | test/24-adapters-shared.test.ts「Y-H-10」（双端窗+单实现，v0.24；test/32 claims 3/4 call-form 断言 v0.26） |
| Y-H-11 | adapter 扫串目标集缺签名密钥文件名 | CLOSED | test/24-adapters-shared.test.ts「Y-H-11」（密钥名+密钥目录入目标集，v0.24 代码核验） |
| Y-H-12 | index.ts workspace 分支用旧折叠（lockstep 违约） | CLOSED | test/24-adapters-shared.test.ts「Y-H-12」（one fold 消费，v0.24；claim 3c/3d） |
| Y-H-13 | hasBaselineOnDisk chainDigest 参数发货即死 | CLOSED | test/25-cc.test.ts「Y-H-13」（七调用点接线，v0.24） |
| Y-H-14 | index.ts 铸 LEGACY workspaceKey 与 mcp-entry 分家 | CLOSED | test/08-plugin-wiring.test.ts「Y-H-14」（DSH 面统一派生，v0.24） |
| Y-H-15 | 纪元化 drift 边界对抗形态全仓零钉 | CLOSED | test/05-engine.test.ts「Y-H-15a」（带外早 at marker 不动边界）+「Y-H-15b」（换体循环双形，v0.24） |
| Y-H-16 | audit.ok 四路消费仅 1/4 有钉 | CLOSED | test/05-engine.test.ts「Y-H-16」（三路封顶钉，v0.24） |
| Y-H-17 | 自删脚本与 require 池身份零钉 | CLOSED | test/05-engine.test.ts「Y-H-17」（conjure 自删+require 三断言，v0.24；test/32 claim 9） |

### M 级（家族行，37 项）

| ID | 标题（短） | 状态 | 证据 |
|---|---|---|---|
| Y-M-01..Y-M-12 | 尾部追加/代际回退/发布树家族 | CLOSED-WITH-NOTES | Y-M-01 模式五（v0.25 地板：K1a 钉 test/05-engine.test.ts「H-17」邻域）、Y-M-02 空行（claim 10）、Y-M-03 回退泛化（v0.25）、Y-M-04 降级池界窗（U2-F1 v0.26）、Y-M-05 半发布预检、Y-M-06 拒签 marker、Y-M-07 三面 1e12（代码核验）、Y-M-08 值引用形态（边界=M11）、Y-M-09 humanProbability（代码核验）、Y-M-10 ghost 赦免、Y-M-11 名单 superset（代码核验+claim 6）、Y-M-12 叶身份（v0.26）；代表钉 test/32-claims.test.ts「claim 6」 |
| Y-M-13..Y-M-37 | 基线移除集/工具面/测试强度家族 | CLOSED-WITH-NOTES | Y-M-13 移除集、Y-M-14 代内末见（v0.24）、Y-M-15 读失败铸造、Y-M-16 lastWellFormed（代码核验）、Y-M-17 孪生锚、Y-M-18 waive 知识认证（并入 residuals.json#H-10）、Y-M-19 倒序回扫（v0.25）、Y-M-20 uncertain 三面、Y-M-21 PTL_DIR 收容（代码核验）、Y-M-22 裸目录目标集、Y-M-23 PATH_KEYS 全列（代码核验）、Y-M-24 evidenceDir 盘符、Y-M-25 juryConfidenceCap、Y-M-26 UNC 臂、Y-M-27 折叠唯一（claim 3）、Y-M-28 文案、Y-M-29 背压（v0.24）、Y-M-30 墙钟（v0.25）、Y-M-31 endorsementBlockers、Y-M-32 迭代化（代码核验）、Y-M-33 域一致、Y-M-34 版本（claim 5）、Y-M-35 max+1、Y-M-36 FakeSigner 真密钥（v0.25：test/28-ptl-cli.test.ts「Y-M-36」）、Y-M-37 headLiars 契约；代表钉 test/28-ptl-cli.test.ts「Y-M-36」 |

### L 级（家族行）

| ID | 标题（短） | 状态 | 证据 |
|---|---|---|---|
| Y-L-01..Y-L-40 | v0.24 普查低危 40 项 | SUPERSEDED | 存活者以 U 轮编号续跟踪（Y-L-10 8.3、Y-L-36 替身族等）；其余随 v0.24-v0.26 批关闭；未逐条重验 |

---

## 第七轮 · v0.26 普查（U1-U4，审计对象 v0.25.0/bdfc650）

### H 级（7 条逐条：U1-F1、U2-F1/F2、U4-H1..H4）

| ID | 标题（短） | 状态 | 证据 |
|---|---|---|---|
| U1-F1 | 地板在下一检查点洗白尾部伪造（pre-sign 名册仅 baseline） | CLOSED | test/09-trust.test.ts「U1-H1」（名册=全 protected 列表，会话缝注入拒公证，v0.26） |
| U2-F1 | verifiedEpochBound 把移植检查点当担保（世代界窗抬高） | CLOSED | test/04-evidence.test.ts「epoch」（界窗排除 liar/malformed，v0.26 代码核验） |
| U2-F2 | latest() 无担保前缀形态喂进 evaluateContract 回退 | CLOSED | test/05-engine.test.ts「U2-H2」（latest-by-check 地板化，v0.26） |
| U4-H1 | claim 1b 下划线改名即绕过（4 生产读点走裸门） | CLOSED | test/32-claims.test.ts「claim 1b」（裸门出口除名+readChainMarkers 进口集契约，v0.26） |
| U4-H2 | claim 11 三千字符窗口子串断言（注释伪造+helper 误伤） | CLOSED | test/32-claims.test.ts「U4-H2」（注释剥离+方法签名族匹配，v0.26） |
| U4-H3 | claim 12 mark-后-checkpoint 字符串存在性 | CLOSED | test/32-claims.test.ts「U4-H3」（行为半边：真实 jury 流程+宣誓字节落于签名检查点下，v0.26） |
| U4-H4 | claims 3/4 死 import+改名孪生双绿灯 | CLOSED | test/32-claims.test.ts「U4-H4」（call-form 断言+改名孪生族负例，v0.26） |

### M 级

| ID | 标题（短） | 状态 | 证据 |
|---|---|---|---|
| U1-F2..U1-F5 | 引擎面 M 级四项（主路身份/吸收地板/缺脚本拒绝/地板身份过滤） | CLOSED | test/05-engine.test.ts「laundering」（主路 workspace 身份 v0.26）+「baselineAbsorptionSuspect」（吸收用 vouchedFloor，代码核验 U1-M3 注释）+「vanished」（缺脚本=非检查，v0.26）+「workspaceKey」（地板滤外来身份，代码核验） |
| U3-F1 | jury 请求读回不过地板（pattern-5 在工具面存活） | CLOSED | test/08-plugin-wiring.test.ts「attest/jury-requested」（读走 engine.vouchedMarkers 公共门，v0.26） |
| U3-F2 | MCP 面吞 drift/vanished 警告 | RESIDUAL-DOCUMENTED | 修复在位（mcp-server.ts 三处转发，U3-M2 v0.25.1 注释，代码核验）但无测试钉——residuals.json#U3-F2（已修未钉） |
| U4-M1, U4-M4, U4-M6 | 契约强度 M 级三项 | CLOSED | test/32-claims.test.ts「claim 7」（诚实必发断言）+「U4-M4」（claim 2b 闭区间上边）+「U4-M6」（claim 1a OR 备选删除） |
| U4-M2, U4-M3, U4-M5 | 契约强度 M 级三项（叶子身份锚/差分绝对锚/赦免两轮） | RESIDUAL-DOCUMENTED | residuals.json#U4-M2 / #U4-M3 / #U4-M5（测试强度残留；实际防线由 test/09-trust.test.ts「Y-H-02」与 test/05 V4-M6 段承担） |

### L 级

| ID | 标题（短） | 状态 | 证据 |
|---|---|---|---|
| U1-F6, U1-F8, U1-F9, U1-F10, U1-F11 | 引擎 L 级五项（default 身份/ skipped 过述/verbose 门/地板重算/死参） | RESIDUAL-DOCUMENTED | residuals.json#U1-F6 / #U1-F8 / #U1-F9 / #U1-F10 / #U1-F11（U1-F5/F7 已修：身份过滤与 CLI 措辞对齐代码核验，test/05-engine.test.ts「workspaceKey」） |
| U2-F3, U2-F4 | 证据层 M 级两项（窗话语义/混代蒸发） | RESIDUAL-DOCUMENTED | residuals.json#U2-F3 / #U2-F4（后者为已声明 accepted 的代际规则） |
| U2-F5, U2-F6, U2-F7 | 证据层 L 级三项（发布核心未消费/拒签候选留池/锚应答移植） | RESIDUAL-DOCUMENTED | residuals.json#U2-F5 / #U2-F6 / #U2-F7 |
| U3-F3, U3-F4, U3-F6 | 可见性/接缝 L 级三项（扣留证词不可见/墙钟接缝/失败路径未钉） | RESIDUAL-DOCUMENTED | residuals.json#U3-F3 / #U3-F4 / #U3-F6 |
| U3-F7, U3-F9, U3-F11 | 适配器/替身/上界 L 级三项 | RESIDUAL-DOCUMENTED | residuals.json#U3-F7 / #U3-F9 / #U3-F11（U3-F10 已修：退化分支守卫代码核验，test/24-adapters-shared.test.ts「M-48」） |
| U4-L1, U4-L2, U4-L3 | 契约卫生 L 级三项 | RESIDUAL-DOCUMENTED | residuals.json#U4-L1 / #U4-L2 / #U4-L3 |

---

## 总账统计

| 轮次 | 级别（条目数） | CLOSED | CLOSED-WITH-NOTES | RESIDUAL-DOCUMENTED | SUPERSEDED |
|---|---|---|---|---|---|
| v0.13 基线 | H（15 判定点） | 8 | 7 | 0 | 0 |
| v0.13 基线 | M（19，1 家族行） | — | 1 家族行（16 CLOSED/1 CW-N/2 RESIDUAL 成员） | 2（M11/M17） | 0 |
| v0.21 第一轮 | H（34） | 17 | 14 | 3（H-10/H-17/H-19） | 0 |
| v0.21 第一轮 | M（85，7 家族行）+ L（1 家族行） | — | 7 家族行 | 0（族内成员并入 X/Y/U 编号或家族注记） | 1（L 家族行） |
| v0.22 红队 | N（8） | 3 | 2 | 1（N-8） | 2（N-4/N-5） |
| v0.23 第三轮 | X-H（19） | 19 | 0 | 0 | 0 |
| v0.23 第三轮 | X-M（64，3 家族行）+ L（1） | — | 3 家族行（X-M-47/X-M-50 成员 RESIDUAL） | 2（并入成员） | 1（L 家族行） |
| v0.24 第四轮 | Y-H（17） | 16 | 1（Y-H-09） | 0 | 0 |
| v0.24 第四轮 | Y-M（37，2 家族行）+ L（1） | — | 2 家族行（Y-M-18 并入 H-10 注册） | 0 | 1（L 家族行） |
| v0.26 第七轮 | U H（7） | 7 | 0 | 0 | 0 |
| v0.26 第七轮 | U M/L（16，8 行） | 3 行 | 1 行 | 6 行（16 项全部登记） | 0 |
| **H 级合计（100 判定行）** | | **70** | **24** | **4** | **2** |

- H 级关闭族（CLOSED + CLOSED-WITH-NOTES）= 94 ≥ 修复 commit 声称之和 78（fdd06db 34+8、15a42bc 19、86f4778 17）——契约 (d) 钉死。
- RESIDUAL-DOCUMENTED 登记 30 条（residuals.json），其中 H 级 4 条（H-10/H-17/H-19/N-8）、v0.13 M 级 2 条（M11/M17）、X-M 级 1 条（X-M-47）、U 轮 23 条（含 2 条「已修未钉」：U3-F2/U3-F6）。
- 每条 residual 的关键词均被 README.md「Honest limits」节覆盖——契约 (c) 钉死（v0.24-v0.26 边界条目为本账本补写，双语同步）。
