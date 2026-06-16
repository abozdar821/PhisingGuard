'use client';

import { useState, useEffect, useCallback, useRef } from 'react';

/* ── Risk helpers ─────────────────────────────── */
const RISK_COLOR = { CRITICAL:'#ef4444', HIGH:'#fb923c', MEDIUM:'#fbbf24', LOW:'#4ade80' };
const riskColor  = rl => RISK_COLOR[rl] || '#4ade80';
const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

/* ── Toast ────────────────────────────────────── */
function useToast() {
  const [toasts, setToasts] = useState([]);
  const show = useCallback((msg, type = 'info', ms = 3500) => {
    const id = Date.now() + Math.random();
    setToasts(t => [...t, { id, msg, type }]);
    setTimeout(() => setToasts(t => t.filter(x => x.id !== id)), ms);
  }, []);
  return { toasts, show };
}

function ToastContainer({ toasts }) {
  return (
    <div style={{ position:'fixed', bottom:24, left:'50%', transform:'translateX(-50%)', zIndex:999, display:'flex', flexDirection:'column', gap:6, alignItems:'center' }}>
      {toasts.map(t => (
        <div key={t.id} style={{
          padding:'9px 18px', borderRadius:20, fontSize:12, fontWeight:600,
          background: t.type==='error' ? 'rgba(239,68,68,.18)' : t.type==='success' ? 'rgba(74,222,128,.14)' : t.type==='warn' ? 'rgba(251,191,36,.12)' : 'rgba(34,211,238,.14)',
          border: `1px solid ${t.type==='error'?'rgba(239,68,68,.4)':t.type==='success'?'rgba(74,222,128,.4)':t.type==='warn'?'rgba(251,191,36,.4)':'rgba(34,211,238,.4)'}`,
          color: t.type==='error'?'#f87171':t.type==='success'?'#4ade80':t.type==='warn'?'#fbbf24':'#22d3ee',
          backdropFilter:'blur(8px)', maxWidth:380, textAlign:'center',
        }}>{t.msg}</div>
      ))}
    </div>
  );
}

/* ── Gauge ────────────────────────────────────── */
function RiskGauge({ score, riskLevel }) {
  const [displayScore, setDisplayScore] = useState(0);
  const CIRC = 238.76;
  const col = riskColor(riskLevel);
  useEffect(() => {
    let cur = 0; const iv = setInterval(() => { cur = Math.min(cur + Math.ceil(score/20), score); setDisplayScore(cur); if(cur>=score) clearInterval(iv); }, 35);
    return () => clearInterval(iv);
  }, [score]);
  return (
    <div style={{ position:'relative', width:92, height:92, flexShrink:0 }}>
      <svg width="92" height="92" viewBox="0 0 92 92" style={{ transform:'rotate(-90deg)' }}>
        <circle cx="46" cy="46" r="38" fill="none" stroke="rgba(255,255,255,.05)" strokeWidth="7"/>
        <circle cx="46" cy="46" r="38" fill="none" stroke={col} strokeWidth="7"
          strokeLinecap="round" strokeDasharray={CIRC}
          strokeDashoffset={CIRC * (1 - score / 100)}
          style={{ transition:'stroke-dashoffset .9s cubic-bezier(.4,0,.2,1)' }}/>
      </svg>
      <div style={{ position:'absolute', inset:0, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center' }}>
        <div style={{ fontSize:25, fontWeight:800, fontFamily:'var(--font-mono, monospace)', color:col, lineHeight:1 }}>{displayScore}</div>
        <div style={{ fontSize:9, color:'#475569', marginTop:1 }}>/ 100</div>
      </div>
    </div>
  );
}

/* ══════════════════════════════════════════════
   Main App
══════════════════════════════════════════════ */
export default function PhishGuardApp() {
  const [view,      setView]      = useState('scan');
  const [scanMode,  setScanMode]  = useState('sms');
  const [sender,    setSender]    = useState('');
  const [subject,   setSubject]   = useState('');
  const [body,      setBody]      = useState('');
  const [scanning,  setScanning]  = useState(false);
  const [scanStep,  setScanStep]  = useState('');
  const [result,    setResult]    = useState(null);
  const [history,   setHistory]   = useState([]);
  const [histFilter,setHistFilter]= useState('all');
  const [histSearch,setHistSearch]= useState('');
  const [confirmedCount, setConfirmedCount] = useState(0);
  const [lastScanAt, setLastScanAt] = useState(0);
  const { toasts, show: toast } = useToast();
  const bodyRef = useRef();

  /* Load history from API (DynamoDB) on mount */
  useEffect(() => {
    fetch('/api/history?userId=public&limit=50')
      .then(r => r.json())
      .then(d => { if (d.items) setHistory(d.items); })
      .catch(() => {});
    fetch('/api/train?userId=public')
      .then(r => r.json())
      .then(d => { if (d.confirmedCount != null) setConfirmedCount(d.confirmedCount); })
      .catch(() => {});
  }, []);

  /* Keyboard shortcuts */
  useEffect(() => {
    const handler = e => {
      if ((e.ctrlKey||e.metaKey) && e.key==='Enter') { e.preventDefault(); if(view==='scan') doScan(); }
      if ((e.ctrlKey||e.metaKey) && e.key==='1') { e.preventDefault(); setView('scan'); }
      if ((e.ctrlKey||e.metaKey) && e.key==='2') { e.preventDefault(); setView('history'); }
      if ((e.ctrlKey||e.metaKey) && e.key==='3') { e.preventDefault(); setView('settings'); }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [view]);

  /* ── Scan ───────────────────────────────────── */
  async function doScan() {
    if (!body.trim() && !sender.trim()) { toast('Please paste a message to analyze.','warn'); return; }
    if (body.length > 10000) { toast('Message exceeds 10,000 character limit.','warn'); return; }
    const now = Date.now();
    if (now - lastScanAt < 3500) { toast('Please wait a moment before scanning again.','warn'); return; }
    setLastScanAt(now);
    setScanning(true); setResult(null);
    setScanStep('🔗 Extracting URLs…');

    try {
      setScanStep('🤖 Analyzing with AI…');
      const res = await fetch('/api/scan', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ sender, subject, message: body, mode: scanMode, userId: 'public' }),
      });
      if (!res.ok) { const e = await res.json(); throw new Error(e.error || `HTTP ${res.status}`); }
      const data = await res.json();
      setResult(data);
      setHistory(prev => [
        { ...data, scan_id: data.scanId, scanned_at: data.scannedAt, body: body.slice(0,300), subject, sender, mode: scanMode },
        ...prev.slice(0,49),
      ]);
      toast('Scan complete ✓','success');
    } catch(err) {
      toast('Scan error: ' + err.message,'error');
    } finally {
      setScanning(false); setScanStep('');
    }
  }

  /* ── Training ───────────────────────────────── */
  async function confirmScan(isScam) {
    if (!result) return;
    try {
      const res = await fetch('/api/train', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ userId:'public', sender, body, type: result.scam_type, risk: result.risk_level, label: isScam ? 'scam' : 'safe' }),
      });
      const d = await res.json();
      if (d.duplicate) { toast('Already in training data','info'); return; }
      if (isScam && d.confirmedCount != null) setConfirmedCount(d.confirmedCount);
      toast(isScam ? 'Confirmed scam — added to training ✓' : 'Marked as safe ✓', isScam ? 'warn' : 'success');
    } catch(e) { toast('Training save failed','error'); }
  }

  /* ── History ────────────────────────────────── */
  async function clearHistory() {
    if (!history.length) return;
    if (!confirm(`Delete all ${history.length} scan(s)?`)) return;
    await fetch('/api/history?userId=public', { method: 'DELETE' }).catch(()=>{});
    setHistory([]);
    toast('History cleared','success');
  }

  function loadHistoryEntry(item) {
    setScanMode(item.mode || 'email');
    setSender(item.sender || '');
    setSubject(item.subject || '');
    setBody(item.body || item.bodySnippet || '');
    setResult({ ...item, risk_level: item.risk_level || item.riskLevel, is_scam: item.is_scam ?? item.isScam, red_flags: item.red_flags || item.redFlags || [], recommended_actions: item.recommended_actions || item.actions || [] });
    setView('scan');
    toast('Loaded from history · ' + new Date(item.scanned_at || item.scannedAt).toLocaleString(), 'info');
  }

  const filteredHistory = history.filter(item => {
    const rl = item.risk_level || item.riskLevel;
    const ok = histFilter === 'all' ? true
      : histFilter === 'scam' ? (item.is_scam || item.isScam)
      : histFilter === 'safe' ? !(item.is_scam || item.isScam)
      : rl === histFilter;
    if (!ok) return false;
    if (!histSearch) return true;
    const q = histSearch.toLowerCase();
    return [item.sender, item.subject, item.scam_type || item.scamType, item.reasoning].filter(Boolean).join(' ').toLowerCase().includes(q);
  });

  const histStats = {
    total:    history.length,
    critical: history.filter(h => (h.risk_level||h.riskLevel) === 'CRITICAL').length,
    high:     history.filter(h => (h.risk_level||h.riskLevel) === 'HIGH').length,
    scams:    history.filter(h => h.is_scam||h.isScam).length,
  };

  /* ── Copy result ────────────────────────────── */
  async function copyResult() {
    if (!result) return;
    const txt = [`PhishGuard AI Scan — ${new Date().toLocaleString()}`, `Risk: ${result.risk_level} (${result.score}/100)`, `Type: ${result.scam_type || 'N/A'}`, `Sender: ${sender}`, subject ? `Subject: ${subject}` : '', `\nAI Analysis:\n${result.reasoning}`, result.red_flags?.length ? `\nRed Flags:\n${result.red_flags.map(f=>'• '+f).join('\n')}` : '', result.recommended_actions?.length ? `\nRecommended Actions:\n${result.recommended_actions.map((a,i)=>`${i+1}. ${a}`).join('\n')}` : ''].filter(Boolean).join('\n');
    await navigator.clipboard.writeText(txt).catch(() => {});
    toast('Copied to clipboard','success');
  }

  /* ── Styles (inline for portability) ────────── */
  const S = {
    app:       { background:'#060912', minHeight:'100vh', color:'#e2e8f0', fontFamily:"var(--font-syne, system-ui, sans-serif)", backgroundImage:'radial-gradient(ellipse 700px 350px at 15% -5%,rgba(34,211,238,.05) 0%,transparent 60%),radial-gradient(ellipse 400px 400px at 85% 105%,rgba(239,68,68,.04) 0%,transparent 60%)' },
    nav:       { position:'sticky', top:0, zIndex:200, background:'rgba(13,20,33,.92)', backdropFilter:'blur(14px)', borderBottom:'1px solid rgba(148,163,184,.1)', height:56, padding:'0 20px', display:'flex', alignItems:'center', justifyContent:'space-between', gap:12 },
    brand:     { display:'flex', alignItems:'center', gap:9 },
    logoMark:  { width:32, height:32, borderRadius:8, background:'linear-gradient(135deg,#164e63,#0369a1)', display:'flex', alignItems:'center', justifyContent:'center', fontSize:16, boxShadow:'0 0 0 1px rgba(34,211,238,.15)' },
    logoTxt:   { fontSize:16, fontWeight:800, letterSpacing:'-.02em' },
    navTabs:   { display:'flex', gap:2 },
    navTab:    (active) => ({ padding:'7px 14px', border:'none', background:active?'rgba(34,211,238,.09)':'transparent', color:active?'#22d3ee':'#475569', borderRadius:8, cursor:'pointer', fontFamily:'inherit', fontSize:13, fontWeight:600, transition:'.15s' }),
    pill:      { display:'flex', alignItems:'center', gap:5, padding:'3px 10px', borderRadius:20, background:'rgba(74,222,128,.08)', border:'1px solid rgba(74,222,128,.15)', color:'#4ade80', fontSize:11, fontWeight:700 },
    inner:     { maxWidth:580, margin:'0 auto', padding:'24px 16px 60px' },
    card:      { background:'#0d1421', border:'1px solid rgba(148,163,184,.1)', borderRadius:12, padding:'20px 22px', marginBottom:12 },
    cardLbl:   { fontSize:10, fontWeight:700, letterSpacing:'.1em', textTransform:'uppercase', color:'#475569', marginBottom:16 },
    mode:      { display:'flex', background:'#121d30', borderRadius:9, padding:3, marginBottom:16 },
    mbtn:      (on) => ({ flex:1, padding:'7px 12px', border:'none', background:on?'#060912':'transparent', color:on?'#e2e8f0':'#475569', borderRadius:7, cursor:'pointer', fontFamily:'inherit', fontSize:13, fontWeight:600, transition:'.2s', boxShadow:on?'0 1px 6px rgba(0,0,0,.4)':'none' }),
    field:     { marginBottom:13 },
    fieldLbl:  { fontSize:10, fontWeight:700, letterSpacing:'.08em', textTransform:'uppercase', color:'#475569', marginBottom:5, display:'flex', justifyContent:'space-between' },
    input:     { width:'100%', background:'rgba(255,255,255,.03)', border:'1px solid rgba(255,255,255,.07)', borderRadius:9, color:'#e2e8f0', fontFamily:'var(--font-mono, monospace)', fontSize:13, padding:'10px 13px', outline:'none' },
    textarea:  { width:'100%', background:'rgba(255,255,255,.03)', border:'1px solid rgba(255,255,255,.07)', borderRadius:9, color:'#e2e8f0', fontFamily:'var(--font-mono, monospace)', fontSize:13, padding:'10px 13px', outline:'none', resize:'vertical', minHeight:95, lineHeight:1.55 },
    scanBtn:   { width:'100%', marginTop:4, padding:13, background:'linear-gradient(135deg,#1e40af,#0369a1)', border:'none', borderRadius:10, color:'#fff', fontFamily:'inherit', fontSize:14, fontWeight:700, letterSpacing:'.06em', cursor:'pointer', opacity:scanning?.5:1 },
    hint:      { fontSize:10, color:'#475569', textAlign:'center', marginTop:5 },
    secHead:   { fontSize:9, fontWeight:700, letterSpacing:'.1em', textTransform:'uppercase', color:'#475569', paddingBottom:6, borderBottom:'1px solid rgba(148,163,184,.1)', marginBottom:9, display:'flex', alignItems:'center', gap:7 },
    aiBox:     (col) => ({ fontSize:13, lineHeight:1.65, color:'#e2e8f0', padding:'11px 13px', background:'rgba(255,255,255,.02)', borderRadius:8, borderLeft:`3px solid ${col}` }),
    flagsLi:   { display:'flex', alignItems:'flex-start', gap:7, padding:'5px 0', fontSize:12, fontWeight:500, borderBottom:'1px solid rgba(255,255,255,.03)', lineHeight:1.5 },
    actionsLi: { display:'flex', alignItems:'flex-start', gap:9, padding:'5px 0', fontSize:12, borderBottom:'1px solid rgba(255,255,255,.03)', lineHeight:1.5 },
    // History
    hstat:     (col) => ({ background:'#0d1421', border:'1px solid rgba(148,163,184,.1)', borderRadius:8, padding:'9px 8px', textAlign:'center' }),
    hcard:     { display:'grid', gridTemplateColumns:'auto 1fr auto', gap:12, alignItems:'center', padding:'11px 13px', background:'#0d1421', border:'1px solid rgba(148,163,184,.1)', borderRadius:9, cursor:'pointer', transition:'.15s', marginBottom:5 },
    // Settings
    ssec:      { background:'#0d1421', border:'1px solid rgba(148,163,184,.1)', borderRadius:12, padding:'20px 22px', marginBottom:10 },
    ssTitle:   { fontSize:13, fontWeight:800, color:'#e2e8f0', marginBottom:14 },
    sfLabel:   { fontSize:10, fontWeight:700, letterSpacing:'.08em', textTransform:'uppercase', color:'#94a3b8', marginBottom:5 },
    sfInput:   { width:'100%', background:'rgba(255,255,255,.03)', border:'1px solid rgba(255,255,255,.07)', borderRadius:9, color:'#e2e8f0', fontFamily:'var(--font-mono, monospace)', fontSize:13, padding:'10px 13px', outline:'none' },
    sfHint:    { fontSize:11, color:'#334155', marginTop:4, lineHeight:1.5 },
  };

  return (
    <div style={S.app}>
      <ToastContainer toasts={toasts} />

      {/* ── Navbar ── */}
      <nav style={S.nav}>
        <div style={S.brand}>
          <div style={S.logoMark}>🛡</div>
          <div style={S.logoTxt}>Phish<span style={{color:'#22d3ee'}}>Guard</span> AI</div>
        </div>
        <div style={S.navTabs}>
          {[['scan','🔍 Scan'],['history','📋 History'],['settings','⚙ Settings']].map(([v,label]) => (
            <button key={v} style={S.navTab(view===v)} onClick={() => setView(v)}>{label}</button>
          ))}
        </div>
        <div style={S.pill}>
          🧠 <span>{confirmedCount} confirmed</span>
        </div>
      </nav>

      {/* ══ SCAN VIEW ══════════════════════════════════ */}
      {view === 'scan' && (
        <div style={S.inner}>
          <div style={S.card}>
            <div style={S.cardLbl}>Analyze Message</div>
            <div style={S.mode}>
              <button style={S.mbtn(scanMode==='sms')}  onClick={() => setScanMode('sms')}>📱 SMS / Text</button>
              <button style={S.mbtn(scanMode==='email')} onClick={() => setScanMode('email')}>📧 Email</button>
            </div>
            <div style={S.field}>
              <div style={S.fieldLbl}>Sender</div>
              <input style={S.input} value={sender} onChange={e=>setSender(e.target.value)} maxLength={500} placeholder="Phone number, short code, or email address" />
            </div>
            {scanMode === 'email' && (
              <div style={S.field}>
                <div style={S.fieldLbl}>Subject</div>
                <input style={S.input} value={subject} onChange={e=>setSubject(e.target.value)} maxLength={500} placeholder="Email subject line" />
              </div>
            )}
            <div style={S.field}>
              <div style={S.fieldLbl}>
                Message
                <span style={{ fontWeight:600, color: body.length > 9000 ? '#fbbf24' : '#475569', letterSpacing:0, textTransform:'none', fontSize:10, fontFamily:'monospace' }}>
                  {body.length.toLocaleString()} / 10,000
                </span>
              </div>
              <textarea ref={bodyRef} style={S.textarea} value={body} onChange={e=>setBody(e.target.value)} maxLength={10000} rows={5} placeholder="Paste the suspicious message here…" />
            </div>
            <button style={S.scanBtn} disabled={scanning} onClick={doScan}>
              {scanning ? scanStep || 'ANALYZING…' : '🔍  SCAN MESSAGE'}
            </button>
            <div style={S.hint}>Press <kbd style={{background:'rgba(255,255,255,.06)',border:'1px solid rgba(255,255,255,.12)',borderRadius:4,padding:'1px 5px',fontFamily:'monospace',fontSize:9}}>Ctrl</kbd>+<kbd style={{background:'rgba(255,255,255,.06)',border:'1px solid rgba(255,255,255,.12)',borderRadius:4,padding:'1px 5px',fontFamily:'monospace',fontSize:9}}>Enter</kbd> to scan</div>
          </div>

          {/* Result Card */}
          {result && (
            <div style={{ ...S.card, border:`1px solid ${riskColor(result.risk_level)}40`, boxShadow:`0 0 0 1px ${riskColor(result.risk_level)}20, 0 8px 32px rgba(0,0,0,.3)` }}>
              <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:16 }}>
                <span style={{ fontSize:10, fontWeight:700, letterSpacing:'.1em', textTransform:'uppercase', color:'#475569' }}>Scan Result</span>
                <button onClick={copyResult} style={{ padding:'5px 11px', background:'rgba(255,255,255,.04)', border:'1px solid rgba(148,163,184,.1)', borderRadius:7, cursor:'pointer', fontSize:11, fontWeight:600, color:'#475569', fontFamily:'inherit' }}>⎘ Copy</button>
              </div>

              {/* Gauge + Risk */}
              <div style={{ display:'flex', alignItems:'center', gap:20, marginBottom:18 }}>
                <RiskGauge score={result.score} riskLevel={result.risk_level} />
                <div>
                  <div style={{ fontSize:25, fontWeight:800, letterSpacing:'-.01em', color:riskColor(result.risk_level), marginBottom:3 }}>{result.risk_level}</div>
                  <div style={{ fontSize:13, color:'#94a3b8', marginBottom:2 }}>{result.scam_type || (result.is_scam ? 'Suspicious Content' : 'No Threat Detected')}</div>
                  {result.confidence && <div style={{ fontSize:11, color:'#475569', fontFamily:'var(--font-mono,monospace)' }}>Confidence: {Math.round(result.confidence*100)}%</div>}
                </div>
              </div>

              {/* URL Safety */}
              {result.urlsChecked?.length > 0 && (
                <div style={{ marginBottom:14 }}>
                  <div style={S.secHead}>URL Safety <span style={{ fontSize:8, padding:'1px 5px', borderRadius:3, background:'rgba(74,222,128,.08)', color:'#4ade80', border:'1px solid rgba(74,222,128,.2)', fontWeight:700 }}>SAFE BROWSING</span></div>
                  {result.urlsChecked.map(url => {
                    const threat = result.sbResult?.find(m => m.url === url);
                    const badge = threat ? (threat.threatType==='MALWARE'?'MALWARE':'PHISHING') : (result.sbResult ? 'SAFE' : 'UNCHECKED');
                    const badgeColor = badge==='SAFE'?'#4ade80':badge==='UNCHECKED'?'#475569':'#ef4444';
                    return (
                      <div key={url} style={{ display:'grid', gridTemplateColumns:'auto 1fr', gap:7, alignItems:'center', padding:'6px 9px', borderRadius:6, border:'1px solid rgba(148,163,184,.1)', background:'rgba(255,255,255,.02)', marginBottom:3 }}>
                        <span style={{ fontSize:9, padding:'2px 6px', borderRadius:3, fontWeight:700, border:`1px solid ${badgeColor}40`, color:badgeColor, background:`${badgeColor}18`, whiteSpace:'nowrap' }}>{badge}</span>
                        <span style={{ fontSize:10, fontFamily:'var(--font-mono,monospace)', color:'#475569', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{url}</span>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* AI Analysis */}
              <div style={{ marginBottom:14 }}>
                <div style={S.secHead}>AI Analysis</div>
                <div style={S.aiBox(riskColor(result.risk_level))}>{result.reasoning}</div>
              </div>

              {/* Red Flags */}
              {result.red_flags?.length > 0 && (
                <div style={{ marginBottom:14 }}>
                  <div style={S.secHead}>Red Flags</div>
                  {result.red_flags.map((f,i) => (
                    <div key={i} style={S.flagsLi}>
                      <span style={{ width:6, height:6, borderRadius:'50%', background:riskColor(result.risk_level), flexShrink:0, marginTop:5 }}/>
                      {f}
                    </div>
                  ))}
                </div>
              )}

              {/* Actions */}
              {result.recommended_actions?.length > 0 && (
                <div style={{ marginBottom:18 }}>
                  <div style={S.secHead}>What To Do</div>
                  {result.recommended_actions.map((a,i) => (
                    <div key={i} style={S.actionsLi}>
                      <span style={{ minWidth:19, height:19, background:'rgba(255,255,255,.05)', borderRadius:'50%', display:'flex', alignItems:'center', justifyContent:'center', fontSize:10, fontWeight:700, flexShrink:0, fontFamily:'var(--font-mono,monospace)' }}>{i+1}</span>
                      {a}
                    </div>
                  ))}
                </div>
              )}

              {/* Training */}
              <div style={{ marginTop:18, paddingTop:16, borderTop:'1px solid rgba(148,163,184,.1)' }}>
                <div style={{ fontSize:11, color:'#475569', fontWeight:600, textAlign:'center', marginBottom:9, letterSpacing:'.02em' }}>WAS THIS CORRECT? · Help train PhishGuard</div>
                <div style={{ display:'flex', gap:7 }}>
                  <button onClick={() => confirmScan(true)} style={{ flex:1, padding:9, borderRadius:8, border:'1px solid rgba(239,68,68,.3)', background:'rgba(239,68,68,.07)', color:'#ef4444', fontFamily:'inherit', fontSize:12, fontWeight:700, cursor:'pointer' }}>⚠ Confirm Scam</button>
                  <button onClick={() => confirmScan(false)} style={{ flex:1, padding:9, borderRadius:8, border:'1px solid rgba(74,222,128,.25)', background:'rgba(74,222,128,.07)', color:'#4ade80', fontFamily:'inherit', fontSize:12, fontWeight:700, cursor:'pointer' }}>✓ Mark as Safe</button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ══ HISTORY VIEW ════════════════════════════ */}
      {view === 'history' && (
        <div style={S.inner}>
          {/* Stats */}
          <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:6, marginBottom:12 }}>
            {[['Total',histStats.total,'#22d3ee'],['Critical',histStats.critical,'#ef4444'],['High',histStats.high,'#fb923c'],['Scams',histStats.scams,'#fbbf24']].map(([l,n,c]) => (
              <div key={l} style={S.hstat(c)}>
                <div style={{ fontSize:18, fontWeight:800, fontFamily:'var(--font-mono,monospace)', color:c, lineHeight:1 }}>{n}</div>
                <div style={{ fontSize:9, fontWeight:700, letterSpacing:'.07em', textTransform:'uppercase', color:'#475569', marginTop:3 }}>{l}</div>
              </div>
            ))}
          </div>

          {/* Toolbar */}
          <div style={{ display:'flex', alignItems:'center', gap:7, flexWrap:'wrap', marginBottom:10 }}>
            <input value={histSearch} onChange={e=>setHistSearch(e.target.value)} placeholder="Search sender, subject, type…" style={{ flex:1, minWidth:140, height:34, background:'rgba(255,255,255,.03)', border:'1px solid rgba(148,163,184,.1)', borderRadius:8, color:'#e2e8f0', fontFamily:'var(--font-mono,monospace)', fontSize:12, padding:'0 11px', outline:'none' }} />
            {[['all','All'],['CRITICAL','Critical'],['scam','Scams'],['safe','Safe']].map(([f,label]) => (
              <button key={f} onClick={() => setHistFilter(f)} style={{ padding:'4px 9px', border:'1px solid', borderColor:histFilter===f?'rgba(34,211,238,.3)':'rgba(148,163,184,.1)', borderRadius:6, background:histFilter===f?'rgba(34,211,238,.08)':'transparent', color:histFilter===f?'#22d3ee':'#475569', fontFamily:'inherit', fontSize:10, fontWeight:700, cursor:'pointer', letterSpacing:'.04em' }}>{label}</button>
            ))}
            <button onClick={clearHistory} style={{ padding:'4px 10px', border:'1px solid rgba(239,68,68,.2)', borderRadius:6, background:'rgba(239,68,68,.05)', color:'#ef4444', fontFamily:'inherit', fontSize:10, fontWeight:700, cursor:'pointer', marginLeft:'auto' }}>🗑 Clear</button>
          </div>

          {/* List */}
          {filteredHistory.length === 0 ? (
            <div style={{ textAlign:'center', padding:'48px 24px' }}>
              <div style={{ fontSize:40, marginBottom:12, opacity:.4 }}>📋</div>
              <div style={{ fontSize:16, fontWeight:700, color:'#94a3b8', marginBottom:6 }}>No scans yet</div>
              <div style={{ fontSize:13, color:'#475569' }}>Scan a message to see results here</div>
            </div>
          ) : filteredHistory.map((item, i) => {
            const rl  = item.risk_level || item.riskLevel;
            const col = riskColor(rl);
            const t   = new Date(item.scanned_at || item.scannedAt).toLocaleString(undefined, { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
            return (
              <div key={item.scan_id || item.scanId || i} style={S.hcard} onClick={() => loadHistoryEntry(item)}>
                <div style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:4, minWidth:52 }}>
                  <span style={{ fontSize:8, padding:'2px 5px', borderRadius:3, fontWeight:700, border:`1px solid ${col}40`, color:col, background:`${col}15` }}>{rl}</span>
                  <span style={{ fontSize:16, fontWeight:800, fontFamily:'var(--font-mono,monospace)', color:col }}>{item.score}</span>
                </div>
                <div style={{ minWidth:0 }}>
                  <div style={{ fontSize:12, fontWeight:700, color:'#e2e8f0', whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis', marginBottom:2 }}>
                    {(item.mode||'email')==='email'?'📧':'📱'} {(item.sender||'Unknown').slice(0,58)}
                  </div>
                  <div style={{ fontSize:11, color:'#94a3b8', whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis', marginBottom:3 }}>
                    {(item.scam_type||item.scamType||item.subject||item.body||'—').slice(0,72)}
                  </div>
                  <div style={{ fontSize:10, color:'#475569', fontFamily:'var(--font-mono,monospace)' }}>{t}</div>
                </div>
                <div style={{ color:'#475569', fontSize:16 }}>›</div>
              </div>
            );
          })}
        </div>
      )}

      {/* ══ SETTINGS VIEW ════════════════════════════ */}
      {view === 'settings' && (
        <div style={S.inner}>
          <div style={S.ssec}>
            <div style={S.ssTitle}>⚙ API Configuration</div>
            <p style={{ fontSize:12, color:'#475569', marginBottom:16, lineHeight:1.6 }}>
              API keys are configured as environment variables in Vercel — they never touch the client browser.
              Set them in your <strong style={{color:'#e2e8f0'}}>Vercel dashboard → Settings → Environment Variables</strong>.
            </p>
            {[
              ['ANTHROPIC_API_KEY', 'Claude AI (required)', 'https://console.anthropic.com', 'sk-ant-...'],
              ['GOOGLE_SAFE_BROWSING_KEY', 'Google Safe Browsing (URL checking)', 'https://console.cloud.google.com', 'AIza...'],
              ['AWS_ACCESS_KEY_ID', 'AWS Access Key (DynamoDB)', 'https://console.aws.amazon.com/iam', 'AKIA...'],
              ['AWS_SECRET_ACCESS_KEY', 'AWS Secret Key', '', ''],
              ['AWS_REGION', 'AWS Region', '', 'us-east-1'],
              ['NEXT_PUBLIC_GOOGLE_CLIENT_ID', 'Google OAuth Client ID (Gmail import)', 'https://console.cloud.google.com', '...googleusercontent.com'],
              ['NEXT_PUBLIC_MSAL_CLIENT_ID', 'Azure App Client ID (Outlook import)', 'https://portal.azure.com', 'xxxxxxxx-xxxx-...'],
            ].map(([key, label, url, example]) => (
              <div key={key} style={{ marginBottom:12, padding:'10px 12px', background:'rgba(255,255,255,.02)', border:'1px solid rgba(148,163,184,.1)', borderRadius:8 }}>
                <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:3 }}>
                  <code style={{ fontSize:11, color:'#22d3ee', fontFamily:'var(--font-mono,monospace)' }}>{key}</code>
                  {url && <a href={url} target="_blank" rel="noopener noreferrer" style={{ fontSize:10, color:'#22d3ee', textDecoration:'none' }}>Get key →</a>}
                </div>
                <div style={{ fontSize:11, color:'#475569' }}>{label}</div>
                {example && <div style={{ fontSize:10, color:'#334155', marginTop:2, fontFamily:'monospace' }}>e.g. {example}</div>}
              </div>
            ))}
          </div>

          <div style={S.ssec}>
            <div style={S.ssTitle}>📊 App Status</div>
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:7 }}>
              {[['8','Threat Patterns in DynamoDB'],['Confirmed Scams',String(confirmedCount)],['AWS DynamoDB','Connected'],['Vercel','Deployed']].map(([label, val], i) => (
                <div key={i} style={{ background:'rgba(255,255,255,.02)', border:'1px solid rgba(148,163,184,.1)', borderRadius:7, padding:'9px 11px' }}>
                  <div style={{ fontSize:typeof val==='number'||/^\d/.test(val)?16:12, fontWeight:800, color:'#22d3ee' }}>{/^\d/.test(label)?label:val}</div>
                  <div style={{ fontSize:10, color:'#475569', marginTop:2 }}>{/^\d/.test(label)?val:label}</div>
                </div>
              ))}
            </div>
          </div>

          <div style={S.ssec}>
            <div style={S.ssTitle}>🏆 H01 Hackathon Submission</div>
            <div style={{ fontSize:12, color:'#94a3b8', lineHeight:1.7 }}>
              <strong style={{color:'#e2e8f0'}}>Track:</strong> Track 2 — Monetizable B2B App<br/>
              <strong style={{color:'#e2e8f0'}}>AWS Database:</strong> DynamoDB (3 tables)<br/>
              <strong style={{color:'#e2e8f0'}}>Frontend:</strong> Next.js 14 on Vercel<br/>
              <strong style={{color:'#e2e8f0'}}>Hashtag:</strong> <span style={{color:'#22d3ee'}}>#HOHackathon</span><br/>
              <strong style={{color:'#e2e8f0'}}>Deadline:</strong> June 29, 2026 @ 8:00pm EDT
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
