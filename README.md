# 路由策略离线推演工作台 (Routing Policy Rehearsal Workbench)

在**发布前**离线看清前缀策略会放行/拒绝哪些前缀。完全本地，**不连接任何生产设备**。

* **React**：前缀树 + 命中链可视化、规则编辑、遮蔽检查、语义差异（最小见证前缀集）、有序回放、RIB 影响分析、FRR 交叉验证
* **FastAPI**：REST API，判定核心用 Python 标准库 **`ipaddress`**
* **PostgreSQL**：邻居、有序规则、不可变配置快照、场景、验证运行、RIB 快照、影响分析任务（也可用 SQLite 免依赖运行）
* **FRRouting 容器**（router-a / router-b，隔离 bridge）：用 FRR 自己的 prefix-list 匹配器做交叉验证

---

## 0. RIB 快照与影响分析（不连接路由器）

策略审查不能只看规则全集——还需要知道**某份离线路由清单实际会把哪些可达前缀交给该策略**。系统支持导入离线 RIB 快照（如 `show ip bgp` 采集的文本），并回答“这次策略改动对**这批真实路由**到底有什么影响”。

### RIB 快照导入

* 每条路由记录 **邻居、地址族、前缀、下一跳**；快照整体记录 **采集时间（collected_at）与来源版本（source_version，如 `frr-8.4.1/show-ip-bgp#20260925`）**；
* **原子冻结**：整批一个事务，任何一条非法行（坏前缀、host bits、坏下一跳、跨族混入）→ **整批失败，什么都不落库**；冻结后没有任何修改/删除入口；
* **去重**：批内相同 `(前缀, 下一跳)` 只保留首条（保留原始行号 ordinal）；同一 `(邻居, 族, 采集时间, 来源版本)` 的重复导入**幂等**——返回已存在快照，不重复路由；同身份不同内容 → 409 冲突；
* **迟到的旧 RIB 只能作为历史版本**：按 `(邻居, 族)` 以采集时间判定 `is_latest`，旧采集导入后只作历史，绝不顶替较新的快照；
* 每个快照带路由集 sha256（`content_hash`），可导出为可再导入的 JSON。

### 影响分析任务（绑定完整输入，结果不串版）

对**任意两个策略快照** × **选定 RIB** 创建分析任务：

* 逐路由分类，给出 **实际命中 / 被放行 / 被拒绝 / 无匹配（落到默认）/ 行为变化** 五个集合（汇总计数 + 逐路由明细，含新旧两条完整命中链）；
* **同时保留全空间最小见证分析**（精确单元枚举的语义证明）——RIB 只是真实样本，**绝不用采样清单替代语义证明**，两者在同一个结果里并列呈现；
* 任务在创建时绑定完整输入并计算 `input_fingerprint`（RIB content_hash + 两个策略快照 payload 哈希）；运行前重新校验指纹，不符则失败而**不是**写入串版结果；
* 状态机 `pending → running → done|failed`：**失败可重试**（输入不可变，重试结果确定一致）；`done` 为终态，结果**永不被改写**——之后改策略、导入更新 RIB 都不影响已完成任务；
* 服务重启时，遗留在 `running` 的任务被标记为 `failed`（可重试），结果、来源与容器证据全部持久化可回放；
* 数据库变更通过**版本化迁移**（`schema_migrations` 表）应用，老库自动升级。

### FRR 有限样本交叉验证

对已完成任务，把**新策略快照**下发到本地 FRR 容器，抽取 RIB 的**有限样本**（行为变化的路由优先，可设上限）逐条比对；比对运行写入 `runs` 表并关联任务 id，作为可回放的容器证据。

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

## 4. FRR 容器交叉验证

两个 FRR 8.4 节点在隔离的 internal bridge（`172.30.10.0/24`，无外部连通）上。验证流程（`backend/app/validate.py`）：

1. 把快照渲染成 `ip/ipv6 prefix-list NAME seq N permit/deny PREFIX [ge X] [le Y]` 下发到容器；
2. 对每个探针执行 FRR 原生命令
   `vtysh -c "debug ip prefix-list NAME match PREFIX"`
   —— 输出由 **FRR 自己的匹配代码**给出 `PERMIT/DENY` 与 `matching entry #seq`；
3. 与 `ipaddress` 模拟器逐条比对动作与 seq，结果写入 `runs` 表；
4. 结束后删除该 prefix-list。

FRR 语义已对照其源码 `lib/plist.c` 核对（包含关系、无 ge/le 精确匹配、窗口、首条最小 seq、未命中 DENY）。注意 FRR 对**空** prefix-list 返回 PERMIT，因此空策略会被报为 lab setup error 而非静默一致。

传输默认 `docker exec`（`RLAB_FRR_TRANSPORT=docker`），也可切到 SSH（`RLAB_FRR_TRANSPORT=ssh`，见 `backend/app/config.py`）。容器不在线时相关测试自动 skip，UI 显示离线徽标。

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
* `test_rib_impact.py`：RIB/影响分析验收——同一策略对两个 RIB 不同实际影响、重复导入不重复路由、v4/v6 严格隔离、分析后策略/RIB 更新不改写结果、非法行整批失败、失败重试与重启恢复后结果/来源/容器证据可回放、迟到旧 RIB 仅作历史版本；
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
| POST | `/api/ribs/import` | 导入并原子冻结 RIB 快照（去重、幂等、非法行整批失败、迟到为历史版本） |
| GET | `/api/ribs`、`/api/ribs/{id}`、`/api/ribs/{id}/export` | RIB 快照列表/详情/可再导入导出 |
| POST | `/api/impact/tasks` | 创建并运行影响分析（RIB × 两个策略快照；同输入幂等返回） |
| GET | `/api/impact/tasks`、`/api/impact/tasks/{id}` | 任务列表/详情（含逐路由结果与语义证明） |
| POST | `/api/impact/tasks/{id}/retry` | 重试失败/被中断任务（done 返回 409） |
| POST | `/api/impact/tasks/{id}/cross-validate` | FRR 有限样本（变化优先）交叉验证，证据入 `runs` |
| GET | `/api/impact/tasks/{id}/runs`、`/api/impact/tasks/{id}/export?format=json\|csv` | 容器证据、自包含导出 |
| GET | `/api/frr/status`、`/api/runs` | 容器在线状态、历史验证运行 |

## 目录

```
backend/app/   engine.py(匹配/遮蔽) trie.py(精确单元+最小见证) service.py db.py(模型+版本化迁移)
               rib.py(RIB解析/去重/影响计算) impact.py(导入冻结/任务状态机/导出)
               validate.py frr_bridge.py treeview.py routers/api.py seed.py
frontend/src/  App.jsx + components/(PolicyEditor/TrieView/DiffView/ReplayLab/RibImpact/Neighbors)
frr/           两个节点的 daemons/vtysh/frr.conf 与独立 docker-compose
tests/         引擎/属性/API/RIB影响分析/FRR 一致性
docker-compose.yml   postgres + backend + router-a/b
```
