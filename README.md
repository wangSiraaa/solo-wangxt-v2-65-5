# 路由策略离线推演工作台 (Routing Policy Rehearsal Workbench)

在**发布前**离线看清前缀策略会放行/拒绝哪些前缀。完全本地，**不连接任何生产设备**。

* **React**：前缀树 + 命中链可视化、规则编辑、遮蔽检查、语义差异（最小见证前缀集）、有序回放、**RIB 快照导入与实际影响分析**、FRR 交叉验证
* **FastAPI**：REST API，判定核心用 Python 标准库 **`ipaddress`**
* **PostgreSQL**：邻居、有序规则、不可变配置快照、场景、验证运行、**冻结 RIB 快照与绑定输入的影响分析任务**（也可用 SQLite 免依赖运行）
* **FRRouting 容器**（router-a / router-b，隔离 bridge）：用 FRR 自己的 prefix-list 匹配器做交叉验证

---

## 1. 语义模型（模拟器）

每条规则 `(seq, prefix, action, ge, le)`，规则按 **seq 升序，首条匹配即终止**：

1. **包含关系**：候选前缀必须是规则基址的子网（`candidate subnet-of base`）；
2. **掩码长度窗口**：`effective_min = ge ?? base_len`，`effective_max = le ?? (ge ?? base_len) : base_len`，即
   * 无 ge/le：精确匹配基址长度；
   * 仅 `le`：窗口 `[base_len, le]`；
   * 仅 `ge`：窗口 `[ge, 32|128]`（Cisco 语义）；
3. 第一个同时满足包含与窗口的规则决定 permit/deny；
4. 都不命中 → 策略的**隐式默认动作**（可配，通常 deny）；
5. **IPv4 与 IPv6 严格隔离**：混合规则在构造/分类时直接报错。

`IPv4Network/IPv6Network` 完成全部地址与掩码计算；引擎与 FRR 的 ge/le 边界一致（见下“FRR 一致性”）。

## 2. 不是文本 diff：最小行为见证集

用户改完规则后，系统计算两个**不可变快照**之间的语义差异，输出**行为发生变化的最小前缀集合**，而不是规则文本差异：

* 前缀空间被精确切分为单元（规则基址边界 + ge/le 长度边界），**全枚举、非采样**；
* 同状态单元用并查集合并成“最大等价区域”（同深度地址相邻 + 跨深度包含且获胜规则/窗口一致），区域被更粗的获胜规则切断时不会跨越；
* 每个发生动作变化的区域给出**一个最浅代表前缀**作为探针，并标注旧/新命中 seq；
* `deny→deny` 只是命中规则换了、转发结果没变，**不会**出现；纯文本改写（如改备注）得到空集。

同时提供**遮蔽分析**：完全遮蔽（永不可达，给出被截获的代表前缀）与部分重叠。

### 三个内置示例（`backend/app/seed.py`，含 before/after 快照与有序探针，可回放）

| 场景 | 说明 | 关键见证 |
|---|---|---|
| **over-permit** 更具体路由误放行 | `192.168.0.0/16 le 24` 过宽，把本应拒绝的 DC /24（如 `192.168.100.0/24`）放了进来；收紧到 `le 23` 并加显式 guard | `192.168.0.0/24`、`192.168.100.0/24` 等 `permit→deny` |
| **reorder** 规则换序 | 宽 `172.16/12 le32 permit` 从 seq 20 换到 seq 5，压过窄 `172.31/16 deny`（后者变完全遮蔽） | `172.31.0.0/16 deny→permit` |
| **default-flip** 默认动作变化 | 删掉 `0/0 permit` 风格兜底、默认从 permit 翻成 deny | `0.0.0.0/0 permit→deny`（最宽代表） |

另含 IPv6 示例 **over-permit-v6**（`2001:db8::/32 le 48` 过宽）。

## 3. 回放：输入与生效次序

* 每次“发布候选”都生成**不可变快照**（含有序规则、默认动作、族、渲染好的 FRR 配置）；
* 场景保存**有序探针列表**，`/api/scenarios/{id}/replay` 以相同顺序对 before/after 两个快照确定性回放，返回每条命中链与差异；
* 快照 payload 自包含，后续再编辑规则不影响历史回放——满足“可回放输入及生效次序”。

## 3b. RIB 快照导入与实际影响分析

策略审查不能只看规则全集：还需要知道某份**离线路由清单实际会把哪些可达前缀交给该策略**。本工作台支持离线 RIB 快照导入（**全程不连接路由器**，RIB 以粘贴表文本或结构化行传入）：

* 快照记录 **邻居、地址族、前缀、下一跳、采集时间、来源/来源版本**；
* **严格校验**：每行经 `ipaddress` 解析，host 位、非法掩码、v4/v6 混族、下一跳族不符都直接报错；
* **去重**：批内 `(prefix, nexthop)` 去重；整个规范路由集 + 邻居/来源做内容哈希，相同内容重复导入返回同一冻结快照，**绝不重复路由**；
* **原子冻结**：先把整批全部解析校验，再在一个事务里写入并置 `frozen`；任何非法行导致**整批失败**、不留下部分快照；
* **迟到的旧 RIB 只是历史版本**：采集时间早于同邻居/同族最新快照的导入被标记 `stale`，只作为历史保存，不会覆盖任何版本。

**影响分析任务**把**两个不可变策略快照 + 一个冻结 RIB 快照**绑定为完整输入（id + 三者内容的 `input_digest`），对 RIB 中**每一条真实可达前缀**（全枚举，非采样）分别用两个策略判定，输出：

* 每条路由在旧/新两侧的**完整命中链**（逐规则包含/窗口判定 + 隐式默认）；
* 实际**被放行 / 被拒绝 / 无匹配（走隐式默认）**集合；
* **行为变化**集合：动作翻转（permit↔deny，区分新放行/新拒绝）与命中规则变化（动作相同但获胜 seq 或 rule↔default 改变）；
* 同一策略对两个不同 RIB 得到不同的实际影响（不同的放行/拒绝/无匹配计数与具体前缀集合）。

**全空间最小见证分析原样保留**：影响结果里同时返回独立于 RIB 的全空间语义证明；RIB 只限定“真实被交给策略的前缀”，**不能用采样清单替代语义证明**。

**输入绑定 / 版本不串**：执行前重新校验三个冻结输入的摘要；分析期间编辑在线策略、打新快照或导入新 RIB 都不会改写已完成或进行中的结果。任务状态机 `pending → running → succeeded / failed`，失败保留错误且**可重试**；重试从同一冻结输入重算，得到同一结果。结果文本可一键导出（含 input_digest、来源版本、逐路由决策）。FRR 有限样本交叉验证证据单独入 `impact_evidences`，重启后仍可回放。

## 4. FRR 容器交叉验证

两个 FRR 8.4 节点在隔离的 internal bridge（`172.30.10.0/24`，无外部连通）上。验证流程（`backend/app/validate.py`）：

1. 把快照渲染成 `ip/ipv6 prefix-list NAME seq N permit/deny PREFIX [ge X] [le Y]` 下发到容器；
2. 对每个探针执行 FRR 原生命令
   `vtysh -c "debug ip prefix-list NAME match PREFIX"`
   —— 输出由 **FRR 自己的匹配代码**给出 `PERMIT/DENY` 与 `matching entry #seq`；
3. 与 `ipaddress` 模拟器逐条比对动作与 seq，结果写入 `runs` 表；
4. 结束后删除该 prefix-list。

FRR 语义已对照其源码 `lib/plist.c` 核对（包含关系、无 ge/le 精确匹配、窗口、首条最小 seq、未命中 DENY）。注意 FRR 对**空** prefix-list 返回 PERMIT，因此空策略会被报为 lab setup error 而非静默一致。

传输默认 `docker exec`（`RLAB_FRR_TRANSPORT=docker`），也可切到 SSH（`RLAB_FRR_TRANSPORT=ssh`，见 `backend/app/config.py`），或切到本机原生 vtysh（`RLAB_FRR_TRANSPORT=local`，配合 `FRR_LOCAL_VTYSH/FRR_LOCAL_VTY_SOCKET/FRR_LOCAL_CONFIG_DIR/FRR_LOCAL_DAEMON`，便于无 Docker 时直接用本地安装/解包的 FRR）。容器不在线时相关测试自动 skip，UI 显示离线徽标。

## 5. 快速开始

### 免容器 / 免 Postgres（SQLite，最快体验）

```bash
cd backend
python -m pip install -r requirements.txt
python -m app.seed                       # 建表 + 写入示例（数据在 backend/data/）
python -m uvicorn app.main:app --port 8765
# API 文档 http://127.0.0.1:8765/docs

cd ../frontend
npm install && npm run dev               # http://localhost:5173 （已配 /api 代理）
```

### 完整本地栈（PostgreSQL + FRR）

```bash
docker compose up -d postgres router-a router-b
cd backend
DATABASE_URL=postgresql+psycopg://rlab:rlab@127.0.0.1:5432/rlab \
  python -m app.seed
RLAB_FRR_TRANSPORT=docker python -m uvicorn app.main:app --port 8765
```

在 UI “④ 回放 / FRR 交叉验证”页选快照与节点（router-a / router-b），点“推送 FRR 并比对”，或：

```bash
curl -s localhost:8765/api/frr/status
curl -s -XPOST localhost:8765/api/snapshots/<id>/cross-validate \
  -H 'content-type: application/json' \
  -d '{"probes":["192.168.100.0/24","10.1.2.3/32"],"node":"a"}'
```

## 6. 测试

```bash
pip install pytest httpx
python -m pytest tests/ -q
```

* `test_engine.py`：精确匹配、ge/le 窗口、首条匹配、默认拒绝、v4/v6 隔离、三个示例决策；
* `test_properties.py`：在完整枚举的 /0../6（v4）与 /32../34（v6）格子上，对数百个随机策略用暴力预言机验证**遮蔽判定**与**最小见证集**逐区域一致（非采样）；
* `test_api.py`：编辑→快照→差异→回放的端到端 REST；
* `test_rib_impact.py`：RIB 导入去重/原子失败/族隔离/迟到历史版、同一策略对两个 RIB 的不同实际影响、分析期间更新不改写结果、失败重试与重启回放、全空间见证保留、逐路由命中链，以及 FRR 有限样本证据（检测到本地/容器 FRR 时对真实 FRR 运行，否则 skip）；
* `test_frr_consistency.py`：FRR 输出解析、随机 400 例与 FRR `prefix_list_apply` 移植模型逐条一致；`test_live_frr_consistency` 在检测到容器时自动对真实 FRR 运行。

## 7. 主要 API

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/policies` | 策略列表（含规则与渲染的 FRR 配置） |
| PUT | `/api/policies/{id}/rules` | 整表有序替换规则（经 ipaddress 校验、族隔离、ge/le 校验） |
| GET | `/api/policies/{id}/analyze` | 完全/部分遮蔽分析 |
| POST | `/api/policies/{id}/classify` | 单条命中链（含 trie_path、每条规则包含/窗口判定与原因） |
| POST | `/api/policies/{id}/classify/batch` | 批量有序推演（坏输入逐条隔离报错） |
| GET | `/api/policies/{id}/trie` | 前缀树视图 |
| POST | `/api/policies/{id}/snapshots` | 创建不可变快照 |
| POST | `/api/snapshots/diff` | 两个快照的最小见证集差异 |
| POST | `/api/snapshots/{id}/replay` | 有序探针确定性回放 |
| POST | `/api/snapshots/{id}/cross-validate` | 推送 FRR 容器并逐条比对 |
| GET/POST | `/api/scenarios`、`/api/scenarios/{id}/replay` | 场景（输入+两个快照+结果） |
| GET/POST | `/api/neighbors` | 本地实验室邻居 |
| GET/POST | `/api/ribs`、`/api/ribs/{id}` | 离线 RIB 快照列表/导入（整批校验、去重、原子冻结）、详情（含路由） |
| POST | `/api/impact/tasks` | 创建并运行影响分析（绑定两个策略快照+一个 RIB，内容摘要固定） |
| GET | `/api/impact/tasks`、`/api/impact/tasks/{id}` | 任务列表/详情（含逐路由命中链与集合） |
| POST | `/api/impact/tasks/{id}/retry` | 失败任务重试（同输入同结果） |
| GET | `/api/impact/tasks/{id}/export` | 可回放文本导出 |
| POST | `/api/impact/tasks/{id}/cross-validate` | 本地 FRR 对 RIB 有限样本的证据（旁证，非证明） |
| GET | `/api/frr/status`、`/api/runs` | 容器在线状态、历史验证运行 |

## 目录

```
backend/app/   engine.py(匹配/遮蔽) trie.py(精确单元+最小见证) service.py db.py(含迁移)
               validate.py frr_bridge.py treeview.py routers/api.py seed.py
               rib.py(离线 RIB 导入/冻结) impact.py(影响分析任务+FRR 样本证据)
frontend/src/  App.jsx + components/(PolicyEditor/TrieView/DiffView/ImpactLab/
               RibImport/ImpactSummary/ReplayLab/Neighbors)
frr/           两个节点的 daemons/vtysh/frr.conf 与独立 docker-compose
tests/         引擎/属性/API/RIB+影响/FRR 一致性
docker-compose.yml   postgres + backend + router-a/b
```

### RIB/影响相关数据库迁移

`init_db()` 对新表（`rib_snapshots`/`rib_routes`/`impact_tasks`/`impact_evidences`）幂等建表，并通过版本化的 `schema_migrations` 运行增量 DDL（SQLite/PostgreSQL 通用）；对本特性之前初始化的库重启即自动升级。
