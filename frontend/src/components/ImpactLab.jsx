import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../api.js'
import RibImport from './RibImport.jsx'
import ImpactSummary from './ImpactSummary.jsx'

export default function ImpactLab({ policy, policies }) {
  const [snaps, setSnaps] = useState([])
  const [ribs, setRibs] = useState([])
  const [tasks, setTasks] = useState([])
  const [oldId, setOldId] = useState('')
  const [newId, setNewId] = useState('')
  const [ribId, setRibId] = useState('')
  const [task, setTask] = useState(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function refresh() {
    const [s, r, t] = await Promise.all([
      api.snapshots(policy.id), api.ribs(policy.family), api.impactTasks()])
    setSnaps(s); setRibs(r); setTasks(t)
    if (!oldId) {
      const byVer = [...s].sort((a, b) => a.version - b.version)
      setOldId(byVer[0]?.id ?? '')
      setNewId(byVer[byVer.length - 1]?.id ?? '')
    }
    if (!ribId && r.length) setRibId(r[0].id)
  }

  useEffect(() => { refresh().catch((e) => setErr(e.message)) }, [policy.id])

  async function loadTask(id) {
    setErr('')
    try { setTask(await api.impactTask(id)) } catch (e) { setErr(e.message) }
  }

  async function runAnalysis() {
    setBusy(true); setErr(''); setTask(null)
    try {
      const t = await api.createImpact({
        old_snapshot_id: Number(oldId), new_snapshot_id: Number(newId),
        rib_snapshot_id: Number(ribId), run: true })
      setTask(t)
      setTasks(await api.impactTasks())
    } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }

  async function retryTask(id) {
    setBusy(true); setErr('')
    try { setTask(await api.retryImpact(id)) }
    catch (e) { setErr(e.message) } finally { setBusy(false) }
  }

  const myTasks = useMemo(() => tasks.filter(
    (t) => t.old_snapshot_id === Number(oldId) &&
           t.new_snapshot_id === Number(newId)),
    [tasks, oldId, newId])

  return (
    <div className="impact">
      <RibImport family={policy.family} onImported={refresh} />

      <div className="bar">
        <strong>基于选定 RIB 计算实际影响</strong>
        <label>旧快照
          <select value={oldId} onChange={(e) => setOldId(e.target.value)}>
            {snaps.map((s) => <option key={s.id} value={s.id}>
              v{s.version} {s.label}</option>)}
          </select>
        </label>
        <label>新快照
          <select value={newId} onChange={(e) => setNewId(e.target.value)}>
            {snaps.map((s) => <option key={s.id} value={s.id}>
              v{s.version} {s.label}</option>)}
          </select>
        </label>
        <label>RIB 快照
          <select value={ribId} onChange={(e) => setRibId(e.target.value)}>
            {ribs.map((r) => <option key={r.id} value={r.id}>
              #{r.id} {r.name}（{r.route_count} 条
              {r.stale ? '，历史版本' : ''}）
            </option>)}
          </select>
        </label>
        <button className="primary" disabled={!oldId || !newId || !ribId || busy}
          onClick={runAnalysis}>
          {busy ? '分析中…' : '计算实际命中 / 放行 / 拒绝 / 变化'}
        </button>
        {err && <span className="error">{err}</span>}
      </div>

      <p className="muted" style={{ marginTop: -4 }}>
        分析任务绑定完整输入（两个策略快照 id + RIB id + 三者内容摘要）。
        分析期间编辑策略或导入新 RIB 都不会改写本任务结果；失败可重试，结果不串版。
        实际影响只统计该 RIB 中<b>真实可达</b>的前缀；全空间最小见证证明仍独立保留，
        不能用采样清单替代。
      </p>

      {myTasks.length > 0 && (
        <div className="analysis">
          <h4>该输入组合的任务历史</h4>
          <table>
            <thead><tr><th>#</th><th>RIB</th><th>状态</th><th>尝试</th>
              <th>摘要</th><th></th></tr></thead>
            <tbody>
              {myTasks.map((t) => (
                <tr key={t.id}>
                  <td>{t.id}</td>
                  <td>#{t.rib_snapshot_id}</td>
                  <td><StatusTag status={t.status} /></td>
                  <td>{t.attempts}</td>
                  <td className="muted">
                    {t.result ? `${t.result.summary.route_count} 条路由，` +
                      `动作变化 ${t.result.summary.action_changed}，` +
                      `全空间见证 ${t.result.summary.full_space_witnesses}`
                      : (t.error || '—')}</td>
                  <td>
                    <button className="mini" onClick={() => loadTask(t.id)}>查看</button>
                    {t.status === 'failed' &&
                      <button className="mini primary" onClick={() => retryTask(t.id)}>
                        重试</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {task && <ImpactSummary task={task} onEvidence={loadTask} />}
    </div>
  )
}

function StatusTag({ status }) {
  const cls = status === 'succeeded' ? 'tag ok'
    : status === 'failed' ? 'tag bad' : 'tag warn'
  const label = { succeeded: '✓ 成功', failed: '✗ 失败', running: '… 运行中',
    pending: '待执行' }[status] || status
  return <span className={cls}>{label}</span>
}
