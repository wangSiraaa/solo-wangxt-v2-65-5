import React, { useEffect, useState } from 'react'
import { api } from '../api.js'

const PLACEHOLDER = {
  4: '# 每行一条：前缀 下一跳\n192.168.100.0/24 10.0.0.1\n192.168.200.0/23 10.0.0.1',
  6: '# 每行一条：前缀 下一跳\n2001:db8:2::/48 2001:db8:ffff::1',
}

export default function RibImport({ family, onImported }) {
  const [ribs, setRibs] = useState([])
  const [name, setName] = useState('')
  const [neighbor, setNeighbor] = useState('')
  const [collectedAt, setCollectedAt] = useState('')
  const [source, setSource] = useState('show ip bgp export')
  const [sourceVersion, setSourceVersion] = useState('FRR 8.4.1')
  const [text, setText] = useState('')
  const [err, setErr] = useState('')
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState(false)
  const [showAll, setShowAll] = useState(false)

  async function refresh() { setRibs(await api.ribs(family)) }
  useEffect(() => { refresh() }, [family])

  async function submit() {
    setErr(''); setMsg(''); setBusy(true)
    try {
      const routes = text.split('\n').map((l) => l.trim())
        .filter((l) => l && !l.startsWith('#') && !l.startsWith('!'))
        .map((l) => {
          const [prefix, nexthop] = l.split(/\s+/)
          return { prefix, nexthop }
        })
      const res = await api.importRib({
        name, neighbor, family, collected_at: collectedAt,
        source, source_version: sourceVersion,
        routes: routes.length ? routes : null,
        raw_text: routes.length ? null : text || null,
      })
      setMsg(`已原子冻结 RIB #${res.id}：${res.route_count} 条去重路由 ` +
        `（hash ${res.content_hash.slice(0, 10)}…` +
        `${res.stale ? '，标记为历史版本' : ''}）`)
      setName(''); setText('')
      await refresh(); onImported && onImported()
    } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }

  const shown = showAll ? ribs : ribs.slice(0, 5)

  return (
    <details className="analysis">
      <summary><b>导入离线 RIB 快照</b>（不连接路由器；整批校验、去重、原子冻结）</summary>
      <div style={{ marginTop: 8 }} className="bar">
        <input placeholder="快照名称" value={name}
          onChange={(e) => setName(e.target.value)} />
        <input placeholder="邻居" value={neighbor} style={{ width: 130 }}
          onChange={(e) => setNeighbor(e.target.value)} />
        <input type="datetime-local" value={collectedAt}
          onChange={(e) => setCollectedAt(e.target.value
            ? new Date(e.target.value).toISOString() : '')} />
        <input placeholder="来源" value={source} style={{ width: 170 }}
          onChange={(e) => setSource(e.target.value)} />
        <input placeholder="来源版本" value={sourceVersion} style={{ width: 130 }}
          onChange={(e) => setSourceVersion(e.target.value)} />
        <button className="primary" disabled={busy || !name || !collectedAt || !text.trim()}
          onClick={submit}>{busy ? '导入中…' : '导入并冻结（IPv' + family + '）'}</button>
      </div>
      {err && <p className="error">✗ {err}（整批失败，无任何部分写入）</p>}
      {msg && <p className="ok">✓ {msg}</p>}
      <textarea rows={6} placeholder={PLACEHOLDER[family]}
        value={text} onChange={(e) => setText(e.target.value)} />
      <p className="muted">
        每行 <code>前缀 下一跳</code>（也接受含 AS 路径等噪声的 BGP 表文本）；
        host 位、非法掩码、v4/v6 混族、下一跳族不符都会让<b>整批</b>失败。
        相同内容重复导入返回同一冻结快照，不产生重复路由。
      </p>

      <h4>已冻结的 IPv{family} RIB（{ribs.length}）</h4>
      <table>
        <thead><tr><th>#</th><th>名称</th><th>邻居</th><th>采集时间</th>
          <th>来源/版本</th><th>路由</th><th>状态</th><th>内容 hash</th></tr></thead>
        <tbody>
          {shown.map((r) => (
            <tr key={r.id}>
              <td>{r.id}</td><td>{r.name}</td><td>{r.neighbor}</td>
              <td>{r.collected_at}</td>
              <td className="muted">{r.source} / {r.source_version}</td>
              <td>{r.route_count}</td>
              <td>{r.stale
                ? <span className="tag warn">历史版本</span>
                : <span className="tag ok">当前</span>}
                {!r.frozen && <span className="tag bad">未冻结</span>}</td>
              <td><code>{r.content_hash.slice(0, 10)}…</code></td>
            </tr>
          ))}
        </tbody>
      </table>
      {ribs.length > 5 && (
        <button className="mini" onClick={() => setShowAll(!showAll)}>
          {showAll ? '收起' : `展开全部 ${ribs.length} 条`}</button>)}
    </details>
  )
}
