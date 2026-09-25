import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../api.js'

/**
 * RIB 快照导入 + 策略影响分析。
 *
 * 左栏：离线 RIB 导入（邻居/地址族/采集时间/来源版本 + 路由行），
 *       去重、原子冻结、迟到旧版本只作历史。
 * 右栏：选定 RIB × 两个策略快照 → 实际影响任务（命中/放行/拒绝/无匹配/
 *       行为变化），逐路由命中链，FRR 有限样本交叉验证，导出。
 */
export default function RibImpact({ policy }) {
  const [neighbors, setNeighbors] = useState([])
  const [ribs, setRibs] = useState([])
  const [snaps, setSnaps] = useState([])
  const [tasks, setTasks] = useState([])
  const [sel, setSel] = useState(null)          // 选中的任务（含 result）
  const [err, setErr] = useState('')
  const [notice, setNotice] = useState('')

  // ---- 导入表单 ----
  const [form, setForm] = useState({
    neighbor: '', family: policy.family,
    collected_at: new Date().toISOString().slice(0, 16),
    source_version: '', label: '',
    routes: policy.family === 4
      ? '192.168.100.0/24 10.255.0.1\n10.1.0.0/16 10.255.0.1'
      : '2001:db8:1::/48 2001:db8:ffff::1',
  })
  // ---- 分析表单 ----
  const [ribId, setRibId] = useState('')
  const [oldId, setOldId] = useState('')
  const [newId, setNewId] = useState('')
  // ---- FRR 抽样 ----
  const [cvNode, setCvNode] = useState('a')
  const [cvLimit, setCvLimit] = useState(20)
  const [cv, setCv] = useState(null)
  // ---- 结果视图 ----
  const [filter, setFilter] = useState('all')
  const [openRow, setOpenRow] = useState(null)

  async function refresh() {
    const [nbs, rs, ts, ss] = await Promise.all([
      api.neighbors(), api.ribs(), api.impactTasks(), api.snapshots(policy.id),
    ])
    setNeighbors(nbs); setRibs(rs); setTasks(ts); setSnaps(ss)
    if (!form.neighbor && nbs.length) setForm((f) => ({ ...f, neighbor: nbs[0].name }))
    const famRibs = rs.filter((r) => r.family === policy.family)
    setRibId((cur) => cur || famRibs[0]?.id || '')
    const ordered = [...ss].sort((a, b) => a.version - b.version)
    if (ordered.length >= 2) {
      setOldId((c) => c || ordered[ordered.length - 2].id)
      setNewId((c) => c || ordered[ordered.length - 1].id)
    } else if (ordered.length === 1) {
      setOldId((c) => c || ordered[0].id); setNewId((c) => c || ordered[0].id)
    }
  }
  useEffect(() => { refresh().catch((e) => setErr(e.message)) }, [policy.id])

  const famRibs = useMemo(
    () => ribs.filter((r) => r.family === policy.family), [ribs, policy.family])

  async function doImport() {
    setErr(''); setNotice('')
    const routes = form.routes.split('\n').map((s) => s.trim()).filter(Boolean)
    try {
      const r = await api.importRib({
        neighbor: form.neighbor, family: Number(form.family),
        collected_at: form.collected_at, source_version: form.source_version,
        label: form.label, routes,
      })
      setNotice(
        (r.deduplicated
          ? `重复导入：已存在快照 #${r.id}，未新增路由（幂等去重）。`
          : `已冻结快照 #${r.id}：${r.route_count} 条路由` +
            (r.duplicates_collapsed ? `（批内去重 ${r.duplicates_collapsed} 条）` : '') + '。')
        + (r.warning ? ` ⚠ ${r.warning}` : ''))
      await refresh()
    } catch (e) { setErr(e.message) }
  }

  async function doAnalyze() {
    setErr(''); setNotice(''); setCv(null)
    try {
      const t = await api.runImpact({
        rib_snapshot_id: Number(ribId),
        old_snapshot_id: Number(oldId), new_snapshot_id: Number(newId),
      })
      setSel(t)
      setNotice(t.status === 'done'
        ? `任务 #${t.id} 完成：${t.result.summary.total} 条路由，行为变化 ${t.result.summary.changed} 条。`
        : `任务 #${t.id} 失败：${t.error}`)
      await refresh()
    } catch (e) { setErr(e.message) }
  }

  async function openTask(id) {
    setErr(''); setCv(null); setOpenRow(null)
    try { setSel(await api.impactTask(id)) } catch (e) { setErr(e.message) }
  }

  async function doRetry(id) {
    setErr('')
    try { setSel(await api.retryImpact(id)); await refresh() }
    catch (e) { setErr(e.message) }
  }

  async function doCV() {
    setErr(''); setCv(null)
    try { setCv(await api.impactCV(sel.id, cvNode, Number(cvLimit))) }
    catch (e) { setErr(e.message) }
  }

  const rows = sel?.result?.rows ?? []
  const filtered = rows.filter((r) =>
    filter === 'all' ? true
    : filter === 'changed' ? r.changed
    : filter === 'permit' ? r.new.action === 'permit'
    : filter === 'deny' ? r.new.action === 'deny'
    : r.new.terminal === 'default')
  const sum = sel?.result?.summary
  const proof = sel?.result?.semantic_proof

  return (
    <div className="ribimpact">
      <div className="cols">
        {/* ------------------------------------------------ 导入 + 列表 */}
        <div>
          <h4>① 离线 RIB 快照导入（不连接路由器）</h4>
          <div className="formgrid">
            <label>邻居</label>
            <select value={form.neighbor}
              onChange={(e) => setForm({ ...form, neighbor: e.target.value })}>
              {neighbors.map((n) => (
                <option key={n.id} value={n.name}>{n.name} ({n.ip})</option>))}
            </select>
            <label>地址族</label>
            <select value={form.family}
              onChange={(e) => setForm({ ...form, family: Number(e.target.value) })}>
              <option value={4}>IPv4</option><option value={6}>IPv6</option>
            </select>
            <label>采集时间</label>
            <input type="datetime-local" value={form.collected_at}
              onChange={(e) => setForm({ ...form, collected_at: e.target.value })} />
            <label>来源版本</label>
            <input type="text" placeholder="如 frr-8.4.1/show-ip-bgp#20260925"
              value={form.source_version}
              onChange={(e) => setForm({ ...form, source_version: e.target.value })} />
            <label>标签</label>
            <input type="text" value={form.label}
              onChange={(e) => setForm({ ...form, label: e.target.value })} />
          </div>
          <textarea rows={6} value={form.routes}
            onChange={(e) => setForm({ ...form, routes: e.target.value })}
            placeholder="每行一条：前缀 下一跳（重复行自动去重；任何非法行整批失败）" />
          <div className="bar">
            <button className="primary" onClick={doImport}
              disabled={!form.neighbor || !form.source_version}>导入并原子冻结</button>
            {err && <span className="error">{err}</span>}
            {notice && <span className="ok">{notice}</span>}
          </div>

          <h4>RIB 快照（冻结，不可改）</h4>
          <table className="cv">
            <thead><tr>
              <th>id</th><th>邻居</th><th>族</th><th>采集时间</th>
              <th>来源版本</th><th>路由数</th><th>内容哈希</th><th>版本</th><th></th>
            </tr></thead>
            <tbody>
              {ribs.map((r) => (
                <tr key={r.id}>
                  <td>{r.id}</td><td>{r.neighbor}</td><td>IPv{r.family}</td>
                  <td>{r.collected_at}</td>
                  <td><code>{r.source_version}</code></td>
                  <td>{r.route_count}</td>
                  <td><code>{r.content_hash.slice(0, 12)}…</code></td>
                  <td>{r.is_latest
                    ? <span className="badge up">最新</span>
                    : <span className="badge down">历史</span>}</td>
                  <td><a className="mini" href={`/api/ribs/${r.id}/export`}>导出</a></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* ------------------------------------------------ 分析 + 结果 */}
        <div>
          <h4>② 影响分析（当前策略：{policy.name}，IPv{policy.family}）</h4>
          <div className="bar">
            <select value={ribId} onChange={(e) => setRibId(e.target.value)}>
              <option value="" disabled>选 RIB…</option>
              {famRibs.map((r) => (
                <option key={r.id} value={r.id}>
                  #{r.id} {r.neighbor} @{r.collected_at}（{r.route_count} 条{r.is_latest ? '，最新' : '，历史'}）
                </option>))}
            </select>
            <select value={oldId} onChange={(e) => setOldId(e.target.value)}>
              <option value="" disabled>旧快照…</option>
              {snaps.map((s) => <option key={s.id} value={s.id}>v{s.version} {s.label}</option>)}
            </select>
            <span className="arrow">⟶</span>
            <select value={newId} onChange={(e) => setNewId(e.target.value)}>
              <option value="" disabled>新快照…</option>
              {snaps.map((s) => <option key={s.id} value={s.id}>v{s.version} {s.label}</option>)}
            </select>
            <button className="primary" onClick={doAnalyze}
              disabled={!ribId || !oldId || !newId}>创建并分析</button>
          </div>

          <h4>分析任务（绑定完整输入；done 结果不可改写）</h4>
          <table className="cv">
            <thead><tr>
              <th>id</th><th>RIB</th><th>旧→新</th><th>状态</th>
              <th>尝试</th><th>时间</th><th></th>
            </tr></thead>
            <tbody>
              {tasks.map((t) => (
                <tr key={t.id} className={sel?.id === t.id ? 'okrow' : ''}>
                  <td>{t.id}</td>
                  <td>#{t.rib_snapshot_id} {t.inputs?.rib?.neighbor}</td>
                  <td>{t.inputs?.old_snapshot?.label} ⟶ {t.inputs?.new_snapshot?.label}</td>
                  <td>
                    <span className={`tag ${t.status === 'done' ? '' : t.status === 'failed' ? 'bad' : 'warn'}`}>
                      {t.status}
                    </span>
                    {t.error && <div className="error" style={{ fontSize: 11 }}>{t.error}</div>}
                  </td>
                  <td>{t.attempts}</td>
                  <td className="muted">{t.finished_at || t.created_at}</td>
                  <td>
                    <button className="small" onClick={() => openTask(t.id)}>查看</button>
                    {t.status === 'failed' &&
                      <button className="small" onClick={() => doRetry(t.id)}>重试</button>}
                    <a className="mini" href={`/api/impact/tasks/${t.id}/export`}>JSON</a>
                    <a className="mini" href={`/api/impact/tasks/${t.id}/export?format=csv`}>CSV</a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {sel?.status === 'done' && sum && (
            <>
              <h4>③ 实际影响汇总（任务 #{sel.id}）</h4>
              <div className="summary">
                <span>路由总数 <b>{sum.total}</b></span>
                <span>旧：放行 <b className="permit">{sum.old.permit}</b> 拒绝 <b className="deny">{sum.old.deny}</b> 命中 {sum.old.matched} 无匹配 {sum.old.unmatched}</span>
                <span>新：放行 <b className="permit">{sum.new.permit}</b> 拒绝 <b className="deny">{sum.new.deny}</b> 命中 {sum.new.matched} 无匹配 {sum.new.unmatched}</span>
                <span className="deny2">行为变化 <b>{sum.changed}</b></span>
                <span className="permit2">新增放行 {sum.newly_permitted}</span>
                <span className="deny2">新增拒绝 {sum.newly_denied}</span>
              </div>
              <p className="muted">
                语义证明保留：全空间最小见证 <b>{proof.witness_count}</b> 个区域
                （精确枚举，非 RIB 采样）；RIB 仅回答“这批真实路由里谁受影响”。
                输入指纹 <code>{sel.input_fingerprint.slice(0, 16)}…</code>，
                来源 <code>{sel.inputs?.rib?.source_version}</code>。
              </p>

              <div className="bar">
                <span>逐路由结果</span>
                <select value={filter} onChange={(e) => setFilter(e.target.value)}>
                  <option value="all">全部（{rows.length}）</option>
                  <option value="changed">仅行为变化（{sum.changed}）</option>
                  <option value="permit">新放行（{sum.new.permit}）</option>
                  <option value="deny">新拒绝（{sum.new.deny}）</option>
                  <option value="unmatched">无匹配（{sum.new.unmatched}）</option>
                </select>
                <span className="muted">点击行展开新旧命中链</span>
              </div>
              <table className="cv">
                <thead><tr>
                  <th>#</th><th>前缀</th><th>下一跳</th>
                  <th>旧结果</th><th>新结果</th><th>变化</th>
                </tr></thead>
                <tbody>
                  {filtered.map((r) => (
                    <RouteRow key={r.ordinal} r={r}
                      open={openRow === r.ordinal}
                      onToggle={() => setOpenRow(openRow === r.ordinal ? null : r.ordinal)} />
                  ))}
                </tbody>
              </table>

              <div className="bar">
                <span>FRR 有限样本交叉验证（变化优先）</span>
                <select value={cvNode} onChange={(e) => setCvNode(e.target.value)}>
                  <option value="a">router-a</option>
                  <option value="b">router-b</option>
                </select>
                <input type="text" style={{ width: 70 }} value={cvLimit}
                  onChange={(e) => setCvLimit(e.target.value)} title="样本上限" />
                <button onClick={doCV}>推送 FRR 抽样比对</button>
              </div>
              {cv && (
                <div className={`cvbox ${cv.status}`}>
                  {cv.status === 'match'
                    ? <div className="ok">✓ {cv.rows.length} 个样本与 FRR 全部一致（run #{cv.run_id}，证据已持久化）</div>
                    : <div className="error">✗ {cv.mismatch_count} 处不一致（run #{cv.run_id}）</div>}
                  <table className="cv">
                    <thead><tr>
                      <th>前缀</th><th>模拟器</th><th>FRR</th><th>一致</th>
                    </tr></thead>
                    <tbody>
                      {cv.rows.map((r) => (
                        <tr key={r.order}
                          className={r.action_match && r.seq_match ? 'okrow' : 'badrow'}>
                          <td><code>{r.prefix}</code></td>
                          <td className={r.sim_action}>{r.sim_action} #{r.sim_seq ?? '默认'}</td>
                          <td className={r.frr_action}>{r.frr_action} #{r.frr_seq ?? '默认'}</td>
                          <td>{r.action_match && r.seq_match ? '✓' : '✗'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
          {sel && sel.status !== 'done' && (
            <div className="analysis">
              任务 #{sel.id} 状态 <b>{sel.status}</b>
              {sel.error && <span className="error">：{sel.error}</span>}
              {sel.status === 'failed' &&
                <button className="small" onClick={() => doRetry(sel.id)}>重试</button>}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function RouteRow({ r, open, onToggle }) {
  return (
    <>
      <tr onClick={onToggle} style={{ cursor: 'pointer' }}
        className={r.changed ? 'badrow' : ''}>
        <td>{r.ordinal + 1}</td>
        <td><code>{r.prefix}</code></td>
        <td><code>{r.next_hop}</code></td>
        <td className={r.old.action}>{r.old.action}{r.old.seq == null ? '（默认）' : ` #${r.old.seq}`}</td>
        <td className={r.new.action}>{r.new.action}{r.new.seq == null ? '（默认）' : ` #${r.new.seq}`}</td>
        <td>{r.changed ? '⚠ 行为变化' : '—'} {open ? '▾' : '▸'}</td>
      </tr>
      {open && (
        <tr>
          <td colSpan={6}>
            <div className="cols">
              <Chain title="旧快照命中链" chain={r.old_chain} />
              <Chain title="新快照命中链" chain={r.new_chain} />
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

function Chain({ title, chain }) {
  return (
    <div>
      <h5>{title}</h5>
      <table className="chain">
        <thead><tr>
          <th>seq</th><th>规则前缀</th><th>动作</th><th>包含?</th><th>窗口?</th><th>结果</th>
        </tr></thead>
        <tbody>
          {chain.map((c, i) => (
            <tr key={i} className={c.matched ? 'matched'
              : c.contained ? 'contained' : c.seq == null ? 'defaultrow' : ''}>
              <td>{c.seq ?? '默认'}</td>
              <td><code>{c.prefix}</code>{c.ge != null && <em> ge {c.ge}</em>}
                {c.le != null && <em> le {c.le}</em>}</td>
              <td className={c.action}>{c.action}</td>
              <td>{c.seq == null ? '—' : c.contained ? '✓' : '✗'}</td>
              <td>{c.seq == null ? '—' : c.length_ok ? '✓' : '✗'}</td>
              <td>{c.matched ? '🎯 命中' : c.seq == null ? '⬛ 默认' : '继续'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
