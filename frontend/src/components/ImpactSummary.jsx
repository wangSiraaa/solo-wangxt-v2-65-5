import React, { useState } from 'react'
import { api } from '../api.js'

const SETS = [
  { key: 'newly_denied', label: '新拒绝', cls: 'deny' },
  { key: 'newly_permitted', label: '新放行', cls: 'permit' },
  { key: 'decision_changed', label: '命中规则变化', cls: 'warn' },
  { key: 'unmatched_new', label: '新策略无匹配（走默认）', cls: 'muted' },
  { key: 'stable', label: '行为不变', cls: 'muted' },
]

function Stat({ n, label, cls }) {
  return <div className={`stat ${cls || ''}`}>
    <div className="num">{n}</div><div className="lab">{label}</div></div>
}

export default function ImpactSummary({ task, onEvidence }) {
  const [setKey, setSetKey] = useState('newly_denied')
  const [openPrefix, setOpenPrefix] = useState(null)
  const [node, setNode] = useState('a')
  const [sampleN, setSampleN] = useState(20)
  const [ev, setEv] = useState(null)
  const [err, setErr] = useState('')

  if (task.status !== 'succeeded') {
    return <div className="analysis">
      <h4>任务 #{task.id}：{task.status}</h4>
      {task.error && <pre className="error">{task.error}</pre>}
    </div>
  }

  const r = task.result
  const s = r.summary
  const prefixes = new Set(r.sets[setKey] || [])
  const rows = r.routes.filter((x) => prefixes.has(x.prefix))

  async function runEvidence() {
    setErr(''); setEv(null)
    try {
      const e = await api.impactEvidence(task.id, node, sampleN)
      setEv(e)
      onEvidence && onEvidence(task.id)
    } catch (e2) { setErr(e2.message) }
  }

  function downloadExport() {
    const token = '/api'
    fetch(`${token}/impact/tasks/${task.id}/export`).then(async (resp) => {
      const blob = new Blob([await resp.text()], { type: 'text/plain' })
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = `impact-task-${task.id}.txt`
      a.click()
    })
  }

  return (
    <div className="impact-result">
      <div className="analysis">
        <h4>实际影响汇总（任务 #{task.id} · IPv{s.family} · RIB #{r.inputs.rib_snapshot_id}）</h4>
        <div className="stats">
          <Stat n={s.route_count} label="RIB 可达前缀" />
          <Stat n={s.permitted_old} label="旧：放行" cls="permit" />
          <Stat n={s.denied_old} label="旧：拒绝" cls="deny" />
          <Stat n={s.unmatched_old} label="旧：无匹配" />
          <Stat n={s.permitted_new} label="新：放行" cls="permit" />
          <Stat n={s.denied_new} label="新：拒绝" cls="deny" />
          <Stat n={s.unmatched_new} label="新：无匹配" />
          <Stat n={s.action_changed} label="动作翻转" cls="deny" />
          <Stat n={s.decision_changed} label="命中变化" cls="warn" />
          <Stat n={s.stable} label="不变" />
        </div>
        <p className="muted">
          输入摘要 <code>{task.input_digest.slice(0, 16)}…</code>；
          RIB 采集于 {r.inputs.rib_collected_at}，来源
          <b>{r.inputs.rib_source}</b> / {r.inputs.rib_source_version}，
          hash <code>{r.inputs.rib_content_hash.slice(0, 10)}…</code>。
          全空间最小见证（语义证明，非采样）：<b>{s.full_space_witnesses}</b> 个，
          见下方独立小节。
        </p>
        <div className="bar" style={{ margin: 0 }}>
          <button className="mini" onClick={downloadExport}>导出可回放文本</button>
          <select value={node} onChange={(e) => setNode(e.target.value)}>
            <option value="a">router-a</option><option value="b">router-b</option>
          </select>
          <label className="muted">样本数
            <input type="number" min={1} max={200} value={sampleN}
              style={{ width: 70, marginLeft: 6 }}
              onChange={(e) => setSampleN(Number(e.target.value))} /></label>
          <button className="mini primary" onClick={runEvidence}>
            FRR 容器有限样本交叉验证</button>
          {err && <span className="error">{err}</span>}
        </div>
        {(ev || task.evidence?.length > 0) && <EvidenceBox ev={ev || task.evidence[0]} />}
      </div>

      <div className="analysis">
        <div className="settabs">
          {SETS.map((x) => (
            <button key={x.key}
              className={`mini ${setKey === x.key ? 'active' : ''} ${x.cls}`}
              onClick={() => setSetKey(x.key)}>
              {x.label}（{(r.sets[x.key] || []).length}）
            </button>
          ))}
        </div>
        <table className="routetable">
          <thead><tr><th></th><th>可达前缀</th><th>下一跳</th>
            <th>旧决策</th><th>新决策</th><th>变化</th></tr></thead>
          <tbody>
            {rows.map((row) => (
              <RouteRow key={row.prefix} row={row}
                open={openPrefix === row.prefix}
                onToggle={() => setOpenPrefix(
                  openPrefix === row.prefix ? null : row.prefix)} />
            ))}
          </tbody>
        </table>
        {rows.length === 0 && <p className="muted">该集合为空。</p>}
      </div>

      <div className="analysis">
        <h4>全空间最小行为见证（保留的语义证明）</h4>
        <p className="muted">
          精确单元划分、全枚举得到；不依赖 RIB，RIB 影响分析只是补充而非替代。
        </p>
        <table>
          <thead><tr><th>见证前缀</th><th>旧动作</th><th>新动作</th>
            <th>旧 seq</th><th>新 seq</th><th>变化</th></tr></thead>
          <tbody>
            {r.witnesses.map((w) => (
              <tr key={w.prefix} className={w.change === 'permit->deny'
                ? 'badrow' : 'okrow'}>
                <td><code>{w.prefix}</code></td>
                <td className={w.old_action}>{w.old_action}</td>
                <td className={w.new_action}>{w.new_action}</td>
                <td>{w.old_seq ?? '默认'}</td><td>{w.new_seq ?? '默认'}</td>
                <td>{w.change}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function RouteRow({ row, open, onToggle }) {
  const o = row.old, n = row.new
  return <>
    <tr className={row.action_changed ? 'badrow'
      : row.decision_changed ? 'warnrow' : ''}>
      <td><button className="mini twist" onClick={onToggle}>
        {open ? '▼' : '▶'}</button></td>
      <td><code>{row.prefix}</code></td>
      <td className="muted">{row.nexthop}</td>
      <td className={o.action}>{o.action} #{o.seq ?? '默认'}</td>
      <td className={n.action}>{n.action} #{n.seq ?? '默认'}</td>
      <td>{row.action_changed ? <span className="tag bad">动作翻转</span>
        : row.decision_changed ? <span className="tag warn">命中变化</span>
          : <span className="muted">不变</span>}</td>
    </tr>
    {open && (
      <tr><td colSpan={6}>
        <div className="chainwrap">
          <Chain title="旧策略命中链" chain={o.chain} action={o.action} />
          <Chain title="新策略命中链" chain={n.chain} action={n.action} />
        </div>
      </td></tr>
    )}
  </>
}

function Chain({ title, chain, action }) {
  return <div className={`hitbox ${action}`}>
    <div className="hit-head muted">{title}</div>
    <table className="chain">
      <thead><tr><th>seq</th><th>规则前缀</th><th>包含</th>
        <th>掩码窗口</th><th>判定</th></tr></thead>
      <tbody>
        {chain.map((e, i) => (
          <tr key={i} className={e.matched ? 'matched'
            : e.contained ? 'contained' : e.seq === null ? 'defaultrow' : ''}>
            <td>{e.seq ?? '默认'}</td><td><code>{e.prefix}</code></td>
            <td>{e.contained ? '✓' : '—'}</td>
            <td>{e.length_ok ? '✓' : '—'}</td>
            <td className="muted">{e.reason}</td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
}

function EvidenceBox({ ev }) {
  const ok = ev.status === 'match'
  return <div className={`cvbox ${ok ? 'match' : 'mismatch'}`} style={{ marginTop: 8 }}>
    <strong>FRR {ev.node?.toUpperCase()} 有限样本证据：</strong>
    {ok ? <span className="ok"> ✓ {ev.sample_size} 个样本与模拟器一致（双侧）</span>
      : <span className="error"> ✗ 存在不一致（详见任务证据）</span>}
    <p className="muted" style={{ margin: '4px 0' }}>
      样本（{ev.detail?.sample?.join(', ')}）仅作旁证；完整结论仍是对 RIB
      全量前缀的枚举。
    </p>
  </div>
}
