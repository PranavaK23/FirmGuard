import { useEffect, useState } from 'react';
import safeSample from '../../samples/safe_config.txt?raw';
import unsafeSample from '../../samples/unsafe_config.txt?raw';
import firmwareV1 from '../../samples/firmware_v1.zip?url';
import firmwareV2 from '../../samples/firmware_v2.tar.gz?url';

async function api(url, options) {
  const response = await fetch(url, options);
  if (response.status === 204) return null;
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new Error(typeof body?.detail === 'string' ? body.detail : `Request failed (${response.status}).`);
  return body;
}
const bytes = value => value >= 1048576 ? `${(value / 1048576).toFixed(1)} MiB` : `${value.toLocaleString()} bytes`;
const title = value => value.replaceAll('_', ' ');
const date = value => new Date(value).toLocaleString();

function DataTable({ columns, rows, empty = 'No entries.' }) {
  const [page, setPage] = useState(0);
  const size = 30;
  useEffect(() => setPage(0), [rows.length]);
  const current = Math.min(page, Math.max(0, Math.ceil(rows.length / size) - 1));
  if (!rows.length) return <p className="muted">{empty}</p>;
  return <><div className="table-wrap"><table><thead><tr>{columns.map(c => <th key={c}>{c}</th>)}</tr></thead>
    <tbody>{rows.slice(current * size, (current + 1) * size).map((row, index) => <tr key={index}>{row.map((cell, i) => <td key={i}>{cell}</td>)}</tr>)}</tbody></table></div>
    {rows.length > size && <div className="pager"><button disabled={!current} onClick={() => setPage(current-1)}>Previous</button><span>Page {current+1} of {Math.ceil(rows.length/size)} · {rows.length} entries</span><button disabled={(current+1)*size >= rows.length} onClick={() => setPage(current+1)}>Next</button></div>}</>;
}

function Findings({ findings }) {
  const [severity, setSeverity] = useState('All');
  const filtered = severity === 'All' ? findings : findings.filter(f => f.severity === severity);
  return <><label className="inline">Severity <select value={severity} onChange={e => setSeverity(e.target.value)}>{['All','High','Medium','Low','Info'].map(s => <option key={s}>{s}</option>)}</select></label>
    <DataTable columns={['Finding', 'File / location', 'Severity', 'Explanation and action']} rows={filtered.map(f => [
      <><strong>{f.type}</strong><small>{f.rule_id}</small>{f.key && <code>{f.key}=********</code>}</>,
      <><span className="path">{f.filename}</span><small>{f.line ? `Line ${f.line}` : f.offset !== undefined ? `Byte offset ${f.offset}` : 'Metadata'}</small></>,
      <span className={`severity ${f.severity.toLowerCase()}`}>{f.severity}</span>,
      <>{f.explanation}<small><strong>Action:</strong> {f.remediation}</small>{f.reference && <a href={f.reference} target="_blank" rel="noreferrer">Advisory reference</a>}</>,
    ])} empty="No findings match this filter. An empty result does not prove security." /></>;
}

function Result({ scan }) {
  const [tab, setTab] = useState('Findings');
  const result = scan.result;
  if (!result.manifest) return <p>This record was created by an older analyser. Submit the original file again to use the current checks.</p>;
  return <section className="panel" aria-label="Scan results"><div className="section-head"><div><h2>Results: {scan.device} / {scan.version}</h2><p>Scan #{scan.id}, revision {scan.revision} · {date(scan.created_at)}</p></div>
    <div className="buttons"><a className="button" href={`/api/scans/${scan.id}/report.pdf`}>Download PDF</a><a className="button" href={`/api/scans/${scan.id}/export`}>Download JSON</a></div></div>
    <dl className="summary"><div><dt>Input</dt><dd>{result.filename}<small>{bytes(result.size_bytes)}</small></dd></div><div><dt>Files analysed</dt><dd>{result.files_scanned}<small>{result.text_files} text, {result.binary_files} binary</small></dd></div><div><dt>Findings</dt><dd>{result.finding_count}<small>{Object.entries(result.severity_counts).map(([k,v]) => `${v} ${k.toLowerCase()}`).join(', ') || 'No patterns detected'}</small></dd></div><div><dt>Coverage</dt><dd>{result.coverage}<small>{result.extraction.method} · {result.extraction.scope}</small></dd></div></dl>
    <div className="note"><strong>How to read this report</strong><p>{result.notice}</p>{result.warnings.map((w,i) => <p key={i}>{w}</p>)}</div>
    <details className="integrity"><summary>File integrity: {title(result.integrity.status)}</summary><p>SHA-256 of the exact uploaded bytes:</p><code>{result.integrity.sha256}</code>
      {result.integrity.expected_sha256 && <p>Expected: <code>{result.integrity.expected_sha256}</code></p>}<p>A matching digest shows byte equality with the reference you supplied. It does not verify the author or establish safety.</p></details>
    <div className="tabs" role="tablist" aria-label="Result sections">{['Findings','Software','ELF files','File manifest'].map(t => <button key={t} role="tab" aria-selected={t === tab} onClick={() => setTab(t)}>{t}</button>)}</div>
    {tab === 'Findings' && <Findings key={scan.id} findings={result.findings} />}
    {tab === 'Software' && <><p>Recognized version evidence, checked against {result.advisory_revision}. “No curated match” does not mean current or secure. Vendor suffixes may prevent an upstream version check.</p>
      <DataTable columns={['Component','Version','File / evidence','Advisory check']} rows={result.components.map(c => [c.product,c.version,<>{c.filename}<small>{c.source} · {c.confidence}</small></>,<>{title(c.check_status)}<small>{c.advisory_ids.join(', ')}</small></>])} empty="No supported software version evidence was detected." /></>}
    {tab === 'ELF files' && <><p>NX, PIE and RELRO come from ELF metadata. Canary and FORTIFY checks look for symbols; missing symbols do not prove that protection is absent.</p>
      <DataTable columns={['File / architecture','NX','PIE','RELRO','Canary / FORTIFY']} rows={result.elf.map(b => [<>{b.filename}<small>{b.status === 'analysed' ? `${b.class}-bit ${b.endian}, ${b.machine}, ${b.type}` : b.notice}</small></>,b.nx || 'unknown',b.pie || 'unknown',b.relro || 'unknown',`${b.stack_canary || 'unknown'} / ${b.fortify || 'unknown'}`])} empty="No ELF files were found." /></>}
    {tab === 'File manifest' && <DataTable columns={['Path','Size / permissions','SHA-256 / checks']} rows={result.manifest.map(f => [f.path,<>{bytes(f.size_bytes)}<small>{f.mode}</small></>,<><code>{f.sha256}</code><small>{f.coverage.join('; ')}</small></>])} />}
    <details><summary>Analysis stages and rule versions</summary><p>{result.scanner_version} · {result.advisory_revision}</p><ol>{scan.events.map((e,i) => <li key={i}>{e.stage} ({e.progress}%)</li>)}</ol></details>
  </section>;
}

function History({ openScan, refresh, onError }) {
  const [data, setData] = useState({items:[],total:0});
  const [device, setDevice] = useState('');
  const [offset, setOffset] = useState(0);
  const [tick, setTick] = useState(0);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    let cancelled = false; setLoading(true);
    api(`/api/scans?limit=20&offset=${offset}&device=${encodeURIComponent(device)}`).then(value => { if (!cancelled) setData(value); }).catch(e => { if (!cancelled) onError(e.message); }).finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [offset,device,tick,refresh]);
  async function remove(scan) {
    if (!window.confirm(`Delete saved scan #${scan.id}? This removes its results and report from local history.`)) return;
    try { await api(`/api/scans/${scan.id}`, {method:'DELETE'}); setTick(tick+1); } catch(e) { onError(e.message); }
  }
  return <section className="panel"><div className="section-head"><div><h1>Scan history</h1><p>Each upload creates a saved revision. Existing analyses are never overwritten.</p></div><button onClick={() => setTick(tick+1)}>Refresh</button></div>
    <label className="inline">Exact device label <input value={device} maxLength={80} placeholder="All devices" onChange={e => { setDevice(e.target.value); setOffset(0); }} /></label>
    {loading && <p role="status">Loading history…</p>}
    <DataTable columns={['Device / version','Input / created','Status','Actions']} rows={data.items.map(s => [<><strong>{s.device}</strong><small>{s.version} · revision {s.revision} · #{s.id}</small></>,<>{s.filename}<small>{date(s.created_at)}</small></>,<>{s.status}<small>{s.stage}{s.finding_count !== null ? ` · ${s.finding_count} findings` : ''}</small></>,<div className="buttons"><button onClick={() => openScan(s.id)}>Open</button><button className="danger" disabled={['queued','running'].includes(s.status)} onClick={() => remove(s)}>Delete</button></div>])} empty="No saved scans. Upload a file to begin." />
    <div className="pager"><button disabled={offset === 0} onClick={() => setOffset(Math.max(0,offset-20))}>Newer</button><span>{data.total} records · showing {data.items.length ? offset+1 : 0}–{offset+data.items.length}</span><button disabled={offset+20 >= data.total} onClick={() => setOffset(offset+20)}>Older</button></div>
  </section>;
}

function Compare({ onError }) {
  const [device, setDevice] = useState('');
  const [scans, setScans] = useState([]);
  const [baseline, setBaseline] = useState('');
  const [candidate, setCandidate] = useState('');
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let cancelled = false;
    api(`/api/scans?limit=100&device=${encodeURIComponent(device)}`).then(d => { if (!cancelled) { setScans(d.items.filter(s => s.status === 'completed')); setResult(null); setBaseline(''); setCandidate(''); } }).catch(e => { if (!cancelled) onError(e.message); });
    return () => { cancelled = true; };
  }, [device]);
  async function compare(event) {
    event.preventDefault(); setBusy(true); setResult(null);
    try { setResult(await api(`/api/compare?baseline=${baseline}&candidate=${candidate}`)); } catch(e) { onError(e.message); } finally { setBusy(false); }
  }
  return <section className="panel"><h1>Compare firmware versions</h1><p>Choose completed scans of the same device, with matching rules, input scope and extraction method.</p>
    <label className="inline">Exact device label <input value={device} maxLength={80} onChange={e => setDevice(e.target.value)} placeholder="All devices" /></label>
    <form onSubmit={compare}><div className="form-row">{[['Baseline',baseline,setBaseline],['Candidate',candidate,setCandidate]].map(([name,value,update]) => <label key={name}>{name}<select required value={value} onChange={e => { update(e.target.value); setResult(null); }}><option value="">Select a scan</option>{scans.map(s => <option key={s.id} value={s.id}>#{s.id} · {s.device} · {s.version} (r{s.revision})</option>)}</select></label>)}</div>
      <p className="muted">The latest 100 records are listed. Filter by device to find older versions, or enter scan IDs below.</p>
      <div className="form-row"><label>Baseline scan ID<input type="number" min="1" value={baseline} onChange={e => {setBaseline(e.target.value);setResult(null);}} /></label><label>Candidate scan ID<input type="number" min="1" value={candidate} onChange={e => {setCandidate(e.target.value);setResult(null);}} /></label></div>
      <button className="primary" disabled={busy || !baseline || !candidate || baseline === candidate}>{busy ? 'Comparing…' : 'Compare scans'}</button></form>
    {result && <div className="comparison"><div className="section-head"><h2>{result.baseline_version} → {result.candidate_version}</h2><a className="button" href={`/api/compare/report.pdf?baseline=${result.baseline_id}&candidate=${result.candidate_id}`}>Download comparison PDF</a></div>
      <p>{result.identical_upload ? 'The uploaded files have identical SHA-256 hashes.' : 'The uploaded files have different SHA-256 hashes.'}</p><p className="note">{result.notice}</p>
      <h3>File changes</h3><p>{Object.entries(result.file_counts).map(([k,v]) => `${v} ${title(k)}`).join(' · ')}</p>
      <DataTable columns={['Change','Path']} rows={['added','removed','changed'].flatMap(k => result.files[k].map(f => [k,typeof f === 'string' ? f : <>{f.path}<small>Mode: {f.baseline_mode} → {f.candidate_mode}</small></>]))} empty="No file or permission changes." />
      <h3>Software version changes</h3><DataTable columns={['Product','Baseline versions','Candidate versions']} rows={result.software_changes.map(c => [c.product,c.baseline_versions.join(', ') || 'absent',c.candidate_versions.join(', ') || 'absent'])} />
      {['new','still_present','no_longer_detected'].map(k => <details key={k}><summary>{title(k)} ({result.counts[k]})</summary><Findings findings={result[k]} /></details>)}
    </div>}
  </section>;
}

function Help({ health }) {
  return <section className="panel help"><h1>About FirmGuard</h1><p>FirmGuard analyses firmware files locally without running the uploaded code. Use it to review files, explain findings, and compare releases.</p>
    <h2>What the checks cover</h2><ul><li>ZIP, TAR, gzip, bzip2 and XZ archives, including nested archives.</li><li>Credential assignments, private-key headers and explicit insecure configuration directives.</li><li>ELF architecture, NX, PIE, RELRO, stack-check and FORTIFY symbols.</li><li>Version banners and recognized dpkg/opkg package entries for eight software families.</li><li>Two curated upstream advisory ranges: OpenSSL CVE-2014-0160 and dnsmasq CVE-2017-14491.</li><li>SHA-256 integrity, file manifests, immutable saved revisions, firmware comparisons, JSON and PDF exports.</li></ul>
    <h2>Embedded filesystems</h2><p>Vendor images and filesystems such as SquashFS need the optional Binwalk v3 Docker setup described in docs/BINWALK.md. Native archive extraction works without Docker. A raw image scanned without extraction receives partial coverage.</p><p>Binwalk configuration: {health?.binwalk?.configured ? 'image configured' : 'no image configured'}; Docker command: {health?.binwalk?.docker_cli ? 'found' : 'not found'}. Configuration does not guarantee that the Docker engine or image is ready. Run scripts/doctor.py to check.</p>
    <h2>Limits and interpretation</h2><p>Uploads: 64 MiB. Expanded content: 256 MiB across at most 4096 entries and four archive layers. Each file: 64 MiB. Text and ASCII-string checks: first 8 MiB per file. At most two scans run at once; each has a 180-second timeout. Binwalk has a 120-second timeout.</p><p>Native extraction rejects links, special files, sparse files, unsafe names and encrypted archives. Binwalk exports only regular files and excludes links. Encrypted and proprietary firmware may remain unreadable.</p><p>Checks are heuristics. A version string may not describe the active code. Vendor backports, stripped ELF files, generated settings, encoded secrets and unsupported components need manual review. Findings are not a certification or a complete CVE assessment.</p>
    <h2>Local storage</h2><p>SQLite stores labels, timestamps, hashes, manifests and masked findings. Temporary uploaded bytes are deleted after each job; abrupt shutdown may leave temporary folders. Paths and labels can still contain sensitive information. History survives restart; interrupted work must be submitted again. Use Delete in history to remove saved results.</p><p>The app has no login. Keep it on 127.0.0.1, with one backend process. No uploaded data is sent to an online advisory service. The optional Docker engine must be local.</p><p>Application version: {health?.version || 'unavailable'}</p>
  </section>;
}

export default function App() {
  const [page,setPage] = useState('Scan');
  const [health,setHealth] = useState(null);
  const [error,setError] = useState('');
  const [file,setFile] = useState(null);
  const [device,setDevice] = useState('Lab router');
  const [version,setVersion] = useState('v1.0');
  const [hash,setHash] = useState('');
  const [binwalk,setBinwalk] = useState(false);
  const [uploading,setUploading] = useState(false);
  const [activeId,setActiveId] = useState(null);
  const [scan,setScan] = useState(null);
  const [refresh,setRefresh] = useState(0);
  useEffect(() => { api('/api/health').then(setHealth).catch(() => setError('Cannot reach FirmGuard. Start it with the supplied start script, then reload.')); }, []);
  useEffect(() => {
    if (!activeId) return;
    const controller = new AbortController(); let timer;
    async function poll() {
      try {
        const current = await api(`/api/scans/${activeId}`,{signal:controller.signal});
        setScan(current);
        if (['queued','running'].includes(current.status)) timer = setTimeout(poll,700);
        else { setRefresh(v => v+1); if (current.status !== 'completed') setError(current.error || 'The scan did not finish.'); }
      } catch(e) { if (!controller.signal.aborted) setError(`${e.message} Open this scan again from History to retry status polling.`); }
    }
    poll(); return () => { controller.abort(); clearTimeout(timer); };
  }, [activeId]);
  const busy = uploading || (scan && ['queued','running'].includes(scan.status));
  function navigate(next) {setPage(next);setError('');}
  function choose(selected) { if (!selected) return; setFile(selected); setError(selected.size > 64*1048576 ? 'Choose a file of at most 64 MiB.' : selected.size === 0 ? 'Choose a non-empty file.' : ''); }
  async function loadSample(which) {
    try {
      if (which === 'safe' || which === 'unsafe') choose(new File([which === 'safe' ? safeSample : unsafeSample], `${which}_config.txt`, {type:'text/plain'}));
      else {
        const response = await fetch(which === 'v1' ? firmwareV1 : firmwareV2);
        if (!response.ok) throw new Error('The sample could not be loaded.');
        choose(new File([await response.blob()],which === 'v1' ? 'firmware_v1.zip' : 'firmware_v2.tar.gz'));
        setDevice('Sample router');setVersion(which === 'v1' ? '1.0' : '2.0');
      }
      setBinwalk(false);
    } catch(e) { setError(e.message); }
  }
  async function start(event) {
    event.preventDefault();setError('');setUploading(true);setActiveId(null);setScan(null);
    try {
      const body = new FormData();body.append('file',file);body.append('device',device.trim());body.append('version',version.trim());body.append('expected_sha256',hash.trim());body.append('use_binwalk',String(binwalk));
      const accepted = await api('/api/scans',{method:'POST',body});
      setScan({id:accepted.id,status:'queued',progress:0,stage:'Queued'});setActiveId(accepted.id);
    } catch(e) {setError(e.message);} finally {setUploading(false);}
  }
  function openScan(id) {setScan(null);setActiveId(null);setError('');setPage('Scan');setTimeout(() => setActiveId(id),0);window.scrollTo({top:0});}
  return <><header><div className="header-inner"><a className="brand" href="#" onClick={e => {e.preventDefault();navigate('Scan');}}>FirmGuard</a><span className="tagline">Static firmware security analysis</span><nav aria-label="Main navigation">{['Scan','History','Compare','Help'].map(p => <button key={p} aria-current={p === page ? 'page' : undefined} onClick={() => navigate(p)}>{p}</button>)}</nav></div></header>
    <main>{error && <div className="error" role="alert">{error}<button aria-label="Dismiss error" onClick={() => setError('')}>Dismiss</button></div>}
      {page === 'Scan' && <><section className="panel"><h1>Scan a firmware file</h1><p>Upload a configuration, archive, ELF executable or firmware image. Review the results and save each device release for comparison.</p>
        <form onSubmit={start}><div className="form-row"><label>Device label<input required maxLength={80} value={device} onChange={e => setDevice(e.target.value)} disabled={busy} /></label><label>Version label<input required maxLength={40} value={version} onChange={e => setVersion(e.target.value)} disabled={busy} /></label></div>
          <label>Firmware or configuration file<input type="file" required={!file} disabled={busy} onChange={e => choose(e.target.files?.[0])} /></label>{file && <p className="selected"><strong>{file.name}</strong> · {bytes(file.size)}</p>}
          <label>Expected SHA-256 (optional)<input className="hash-input" value={hash} maxLength={64} pattern="[a-fA-F0-9]{64}" onChange={e => setHash(e.target.value)} disabled={busy} placeholder="64 hexadecimal characters from a trusted reference" /></label>
          <label className="checkbox"><input type="checkbox" checked={binwalk} onChange={e => setBinwalk(e.target.checked)} disabled={busy || !health?.binwalk?.configured || !health?.binwalk?.docker_cli} />Use configured Binwalk container for a raw firmware/filesystem image</label>
          <p className="muted">Common archives unpack automatically. Maximum upload 64 MiB. Device and version labels are entered by you.</p>
          <button className="primary" disabled={busy || !file || file.size === 0 || file.size > 64*1048576}>{uploading ? 'Uploading…' : busy ? 'Analysing…' : 'Run analysis'}</button>
        </form><details><summary>Try the supplied samples</summary><p>The firmware samples are synthetic filesystem archives with configuration files, version banners and ELF fixtures. They contain dummy credentials.</p><div className="buttons">{[['unsafe','Unsafe configuration'],['safe','Safe configuration'],['v1','Firmware sample 1.0'],['v2','Firmware sample 2.0']].map(([id,name]) => <button key={id} disabled={busy} onClick={() => loadSample(id)}>{name}</button>)}</div></details>
      </section>
      {scan && scan.status !== 'completed' && <section className="panel" aria-live="polite"><h2>Scan #{scan.id}: {scan.status}</h2><p>{scan.stage}</p><progress max="100" value={scan.progress} aria-label="Analysis progress" />{scan.error && <p>{scan.error}</p>}<p className="muted">You can return to this record from History.</p></section>}
      {scan?.status === 'completed' && <Result key={scan.id} scan={scan} />}</>}
      {page === 'History' && <History openScan={openScan} refresh={refresh} onError={setError} />}
      {page === 'Compare' && <Compare onError={setError} />}
      {page === 'Help' && <Help health={health} />}
    </main><footer>FirmGuard · Local analysis · Review findings in their device context.</footer></>;
}
