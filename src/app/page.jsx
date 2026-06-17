'use client';

import { useState, useEffect, useCallback, useRef } from 'react';

/* ── Risk helpers ─────────────────────────────────────────────────────── */
const RISK_COLOR = {
  CRITICAL: '#DC2626',
  HIGH:     '#EA580C',
  MEDIUM:   '#D97706',
  LOW:      '#059669',
};
const RISK_BG = {
  CRITICAL: '#FEF2F2',
  HIGH:     '#FFF7ED',
  MEDIUM:   '#FFFBEB',
  LOW:      '#ECFDF5',
};
const riskColor = rl => RISK_COLOR[rl] || '#059669';
const riskBg    = rl => RISK_BG[rl]    || '#ECFDF5';

/* ── Toast ────────────────────────────────────────────────────────────── */
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
  const colors = {
    error:   { bg:'#FEF2F2', border:'#FECACA', text:'#B91C1C' },
    success: { bg:'#ECFDF5', border:'#A7F3D0', text:'#065F46' },
    warn:    { bg:'#FFFBEB', border:'#FDE68A', text:'#92400E' },
    info:    { bg:'#EFF6FF', border:'#BFDBFE', text:'#1E40AF' },
  };
  return (
    <div style={{ position:'fixed', bottom:24, left:'50%', transform:'translateX(-50%)', zIndex:9999, display:'flex', flexDirection:'column', gap:8, alignItems:'center', pointerEvents:'none' }}>
      {toasts.map(t => {
        const c = colors[t.type] || colors.info;
        return (
          <div key={t.id} style={{ padding:'10px 20px', borderRadius:12, fontSize:13, fontWeight:600, background:c.bg, border:`1px solid ${c.border}`, color:c.text, boxShadow:'0 4px 16px rgba(0,0,0,0.1)', maxWidth:360, textAlign:'center', whiteSpace:'nowrap' }}>
            {t.msg}
          </div>
        );
      })}
    </div>
  );
}

/* ── Risk Gauge ───────────────────────────────────────────────────────── */
function RiskGauge({ score, riskLevel }) {
  const [displayScore, setDisplayScore] = useState(0);
  const CIRC = 238.76;
  const col  = riskColor(riskLevel);
  useEffect(() => {
    let cur = 0;
    const iv = setInterval(() => {
      cur = Math.min(cur + Math.ceil(score / 20), score);
      setDisplayScore(cur);
      if (cur >= score) clearInterval(iv);
    }, 35);
    return () => clearInterval(iv);
  }, [score]);
  return (
    <div style={{ position:'relative', width:96, height:96, flexShrink:0 }}>
      <svg width="96" height="96" viewBox="0 0 96 96" style={{ transform:'rotate(-90deg)' }}>
        <circle cx="48" cy="48" r="40" fill="none" stroke="#E2E8F0" strokeWidth="8"/>
        <circle cx="48" cy="48" r="40" fill="none" stroke={col} strokeWidth="8"
          strokeLinecap="round" strokeDasharray={CIRC * 1.054}
          strokeDashoffset={(CIRC * 1.054) * (1 - score / 100)}
          style={{ transition:'stroke-dashoffset 1s cubic-bezier(.4,0,.2,1)' }}/>
      </svg>
      <div style={{ position:'absolute', inset:0, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center' }}>
        <div style={{ fontSize:26, fontWeight:800, color:col, lineHeight:1, fontVariantNumeric:'tabular-nums' }}>{displayScore}</div>
        <div style={{ fontSize:10, color:'#94A3B8', marginTop:1 }}>/ 100</div>
      </div>
    </div>
  );
}

/* ══════════════════════════════════════════════════════════════════════
   Main App
══════════════════════════════════════════════════════════════════════ */
export default function PhishGuardApp() {
  const [view,       setView]       = useState('scan');
  const [scanMode,   setScanMode]   = useState('sms');
  const [sender,     setSender]     = useState('');
  const [subject,    setSubject]    = useState('');
  const [body,       setBody]       = useState('');
  const [scanning,   setScanning]   = useState(false);
  const [scanStep,   setScanStep]   = useState('');
  const [result,     setResult]     = useState(null);
  const [history,    setHistory]    = useState([]);
  const [histFilter, setHistFilter] = useState('all');
  const [histSearch, setHistSearch] = useState('');
  const [confirmedCount, setConfirmedCount] = useState(0);
  const [lastScanAt, setLastScanAt] = useState(0);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const { toasts, show: toast } = useToast();
  const bodyRef = useRef();

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

  useEffect(() => {
    const handler = e => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); if (view === 'scan') doScan(); }
      if ((e.ctrlKey || e.metaKey) && e.key === '1') { e.preventDefault(); setView('scan'); }
      if ((e.ctrlKey || e.metaKey) && e.key === '2') { e.preventDefault(); setView('history'); }
      if ((e.ctrlKey || e.metaKey) && e.key === '3') { e.preventDefault(); setView('settings'); }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [view]);

  /* ── Scan ─────────────────────────────────────────────────────────── */
  async function doScan() {
    if (!body.trim() && !sender.trim()) { toast('Please paste a message to analyze.', 'warn'); return; }
    if (body.length > 10000) { toast('Message exceeds 10,000 character limit.', 'warn'); return; }
    const now = Date.now();
    if (now - lastScanAt < 3500) { toast('Please wait a moment before scanning again.', 'warn'); return; }
    setLastScanAt(now);
    setScanning(true); setResult(null);
    setScanStep('Extracting URLs…');
    try {
      setScanStep('Analyzing with AI…');
      const res = await fetch('/api/scan', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sender, subject, message: body, mode: scanMode, userId: 'public' }),
      });
      if (!res.ok) { const e = await res.json(); throw new Error(e.error || `HTTP ${res.status}`); }
      const data = await res.json();
      setResult(data);
      setHistory(prev => [
        { ...data, scan_id: data.scanId, scanned_at: data.scannedAt, body: body.slice(0, 300), subject, sender, mode: scanMode },
        ...prev.slice(0, 49),
      ]);
      toast('Scan complete ✓', 'success');
    } catch (err) {
      toast('Scan error: ' + err.message, 'error');
    } finally {
      setScanning(false); setScanStep('');
    }
  }

  /* ── Training ─────────────────────────────────────────────────────── */
  async function confirmScan(isScam) {
    if (!result) return;
    try {
      const res = await fetch('/api/train', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId: 'public', sender, body, type: result.scam_type, risk: result.risk_level, label: isScam ? 'scam' : 'safe' }),
      });
      const d = await res.json();
      if (d.duplicate) { toast('Already in training data', 'info'); return; }
      if (isScam && d.confirmedCount != null) setConfirmedCount(d.confirmedCount);
      toast(isScam ? 'Confirmed scam — added to training ✓' : 'Marked as safe ✓', isScam ? 'warn' : 'success');
    } catch (e) { toast('Training save failed', 'error'); }
  }

  /* ── History ──────────────────────────────────────────────────────── */
  async function clearHistory() {
    if (!history.length) return;
    if (!confirm(`Delete all ${history.length} scan(s)?`)) return;
    await fetch('/api/history?userId=public', { method: 'DELETE' }).catch(() => {});
    setHistory([]);
    toast('History cleared', 'success');
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
    critical: history.filter(h => (h.risk_level || h.riskLevel) === 'CRITICAL').length,
    high:     history.filter(h => (h.risk_level || h.riskLevel) === 'HIGH').length,
    scams:    history.filter(h => h.is_scam || h.isScam).length,
  };

  /* ── Copy ─────────────────────────────────────────────────────────── */
  async function copyResult() {
    if (!result) return;
    const txt = [
      `PhishGuard AI Scan — ${new Date().toLocaleString()}`,
      `Risk: ${result.risk_level} (${result.score}/100)`,
      `Type: ${result.scam_type || 'N/A'}`,
      `Sender: ${sender}`,
      subject ? `Subject: ${subject}` : '',
      `\nAI Analysis:\n${result.reasoning}`,
      result.red_flags?.length ? `\nRed Flags:\n${result.red_flags.map(f => '• ' + f).join('\n')}` : '',
      result.recommended_actions?.length ? `\nRecommended Actions:\n${result.recommended_actions.map((a, i) => `${i + 1}. ${a}`).join('\n')}` : '',
    ].filter(Boolean).join('\n');
    await navigator.clipboard.writeText(txt).catch(() => {});
    toast('Copied to clipboard', 'success');
  }

  function navTo(v) { setView(v); setMobileMenuOpen(false); }

  /* ════════════════════════════════════════════════════════════════════
     Render
  ════════════════════════════════════════════════════════════════════ */
  return (
    <>
      {/* ── Global responsive styles ── */}
      <style>{`
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #F0F4F8; }

        .pg-app { min-height: 100vh; background: #F0F4F8; color: #1E293B; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; }

        /* Navbar */
        .pg-nav { position: sticky; top: 0; z-index: 200; background: #FFFFFF; border-bottom: 1px solid #E2E8F0; box-shadow: 0 1px 4px rgba(0,0,0,0.06); padding: 0 24px; height: 64px; display: flex; align-items: center; justify-content: space-between; gap: 16px; }
        .pg-nav-brand { display: flex; align-items: center; gap: 10px; text-decoration: none; }
        .pg-nav-logo { width: 36px; height: 36px; border-radius: 10px; background: linear-gradient(135deg, #1D4ED8, #0EA5E9); display: flex; align-items: center; justify-content: center; font-size: 18px; box-shadow: 0 2px 8px rgba(29,78,216,0.3); }
        .pg-nav-title { font-size: 18px; font-weight: 800; letter-spacing: -0.02em; color: #0F172A; }
        .pg-nav-title span { color: #2563EB; }
        .pg-nav-tabs { display: flex; gap: 4px; }
        .pg-nav-tab { padding: 8px 16px; border: none; border-radius: 8px; cursor: pointer; font-family: inherit; font-size: 14px; font-weight: 600; transition: all 0.15s; background: transparent; color: #64748B; }
        .pg-nav-tab:hover { background: #F1F5F9; color: #1E293B; }
        .pg-nav-tab.active { background: #EFF6FF; color: #2563EB; }
        .pg-nav-badge { display: flex; align-items: center; gap: 6px; padding: 5px 12px; border-radius: 20px; background: #ECFDF5; border: 1px solid #A7F3D0; color: #065F46; font-size: 12px; font-weight: 700; white-space: nowrap; }
        .pg-hamburger { display: none; flex-direction: column; gap: 5px; background: none; border: none; cursor: pointer; padding: 6px; border-radius: 8px; }
        .pg-hamburger span { display: block; width: 22px; height: 2px; background: #475569; border-radius: 2px; transition: 0.2s; }
        .pg-mobile-menu { display: none; position: fixed; top: 64px; left: 0; right: 0; background: #FFFFFF; border-bottom: 1px solid #E2E8F0; box-shadow: 0 8px 24px rgba(0,0,0,0.08); z-index: 199; padding: 12px 16px; flex-direction: column; gap: 4px; }
        .pg-mobile-menu.open { display: flex; }
        .pg-mobile-tab { padding: 12px 16px; border: none; border-radius: 10px; cursor: pointer; font-family: inherit; font-size: 15px; font-weight: 600; text-align: left; background: transparent; color: #475569; transition: 0.15s; }
        .pg-mobile-tab:hover { background: #F8FAFC; }
        .pg-mobile-tab.active { background: #EFF6FF; color: #2563EB; }

        /* Layout */
        .pg-inner { max-width: 640px; margin: 0 auto; padding: 28px 20px 80px; }

        /* Cards */
        .pg-card { background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 16px; padding: 24px; margin-bottom: 16px; box-shadow: 0 1px 4px rgba(0,0,0,0.04); }
        .pg-card-title { font-size: 11px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #94A3B8; margin-bottom: 20px; }

        /* Mode toggle */
        .pg-mode { display: flex; background: #F1F5F9; border-radius: 10px; padding: 4px; margin-bottom: 20px; gap: 4px; }
        .pg-mbtn { flex: 1; padding: 9px 12px; border: none; border-radius: 8px; cursor: pointer; font-family: inherit; font-size: 14px; font-weight: 600; transition: all 0.2s; color: #64748B; background: transparent; }
        .pg-mbtn.active { background: #FFFFFF; color: #1E293B; box-shadow: 0 1px 6px rgba(0,0,0,0.1); }

        /* Form fields */
        .pg-field { margin-bottom: 16px; }
        .pg-field-label { font-size: 12px; font-weight: 600; color: #475569; margin-bottom: 6px; display: flex; justify-content: space-between; align-items: center; }
        .pg-input { width: 100%; background: #F8FAFC; border: 1.5px solid #E2E8F0; border-radius: 10px; color: #1E293B; font-family: inherit; font-size: 14px; padding: 11px 14px; outline: none; transition: border-color 0.15s; }
        .pg-input:focus { border-color: #93C5FD; box-shadow: 0 0 0 3px rgba(59,130,246,0.1); }
        .pg-textarea { width: 100%; background: #F8FAFC; border: 1.5px solid #E2E8F0; border-radius: 10px; color: #1E293B; font-family: inherit; font-size: 14px; padding: 11px 14px; outline: none; resize: vertical; min-height: 110px; line-height: 1.6; transition: border-color 0.15s; }
        .pg-textarea:focus { border-color: #93C5FD; box-shadow: 0 0 0 3px rgba(59,130,246,0.1); }
        .pg-char-count { font-size: 11px; font-weight: 500; color: #94A3B8; font-variant-numeric: tabular-nums; }
        .pg-char-count.warn { color: #D97706; }

        /* Scan button */
        .pg-scan-btn { width: 100%; margin-top: 4px; padding: 15px; background: linear-gradient(135deg, #1D4ED8, #2563EB); border: none; border-radius: 12px; color: #FFFFFF; font-family: inherit; font-size: 15px; font-weight: 700; letter-spacing: 0.04em; cursor: pointer; transition: all 0.2s; box-shadow: 0 4px 14px rgba(37,99,235,0.3); }
        .pg-scan-btn:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 6px 20px rgba(37,99,235,0.4); }
        .pg-scan-btn:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
        .pg-scan-hint { font-size: 11px; color: #94A3B8; text-align: center; margin-top: 8px; }
        kbd { background: #F1F5F9; border: 1px solid #CBD5E1; border-radius: 4px; padding: 1px 5px; font-family: monospace; font-size: 10px; color: #475569; }

        /* Result card */
        .pg-result-section-head { font-size: 11px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #94A3B8; padding-bottom: 8px; border-bottom: 1px solid #F1F5F9; margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }
        .pg-ai-box { font-size: 14px; line-height: 1.7; color: #374151; padding: 14px 16px; background: #F8FAFC; border-radius: 10px; border-left: 4px solid #E2E8F0; }
        .pg-flag-item { display: flex; align-items: flex-start; gap: 10px; padding: 7px 0; font-size: 13px; color: #374151; border-bottom: 1px solid #F8FAFC; line-height: 1.5; }
        .pg-action-item { display: flex; align-items: flex-start; gap: 10px; padding: 7px 0; font-size: 13px; color: #374151; border-bottom: 1px solid #F8FAFC; line-height: 1.5; }
        .pg-action-num { min-width: 22px; height: 22px; background: #EFF6FF; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 11px; font-weight: 700; color: #2563EB; flex-shrink: 0; margin-top: 1px; }

        /* History */
        .pg-stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 16px; }
        .pg-stat-card { background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 12px; padding: 14px 10px; text-align: center; box-shadow: 0 1px 4px rgba(0,0,0,0.04); }
        .pg-hist-toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
        .pg-hist-search { flex: 1; min-width: 140px; height: 38px; background: #FFFFFF; border: 1.5px solid #E2E8F0; border-radius: 10px; color: #1E293B; font-family: inherit; font-size: 13px; padding: 0 13px; outline: none; }
        .pg-hist-search:focus { border-color: #93C5FD; }
        .pg-filter-btn { padding: 6px 12px; border: 1.5px solid #E2E8F0; border-radius: 8px; background: #FFFFFF; color: #64748B; font-family: inherit; font-size: 12px; font-weight: 600; cursor: pointer; transition: 0.15s; white-space: nowrap; }
        .pg-filter-btn.active { border-color: #93C5FD; background: #EFF6FF; color: #2563EB; }
        .pg-clear-btn { padding: 6px 12px; border: 1.5px solid #FECACA; border-radius: 8px; background: #FEF2F2; color: #DC2626; font-family: inherit; font-size: 12px; font-weight: 600; cursor: pointer; margin-left: auto; }
        .pg-hist-card { display: grid; grid-template-columns: 64px 1fr 24px; gap: 14px; align-items: center; padding: 14px 16px; background: #FFFFFF; border: 1.5px solid #E2E8F0; border-radius: 12px; cursor: pointer; transition: all 0.15s; margin-bottom: 8px; }
        .pg-hist-card:hover { border-color: #93C5FD; box-shadow: 0 2px 12px rgba(37,99,235,0.08); transform: translateY(-1px); }

        /* Settings */
        .pg-ssec { background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 16px; padding: 24px; margin-bottom: 14px; box-shadow: 0 1px 4px rgba(0,0,0,0.04); }
        .pg-ssec-title { font-size: 15px; font-weight: 700; color: #0F172A; margin-bottom: 6px; }
        .pg-ssec-desc { font-size: 13px; color: #64748B; line-height: 1.6; margin-bottom: 18px; }
        .pg-env-row { margin-bottom: 10px; padding: 12px 14px; background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 10px; }
        .pg-env-top { display: flex; align-items: center; justify-content: space-between; margin-bottom: 4px; }
        .pg-status-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
        .pg-status-item { background: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 10px; padding: 12px 14px; }

        /* Empty state */
        .pg-empty { text-align: center; padding: 60px 24px; }

        /* Mobile tweaks */
        @media (max-width: 600px) {
          .pg-nav-tabs { display: none; }
          .pg-nav-badge { display: none; }
          .pg-hamburger { display: flex; }
          .pg-inner { padding: 20px 14px 80px; }
          .pg-card { padding: 18px 16px; border-radius: 14px; }
          .pg-stat-grid { grid-template-columns: repeat(2, 1fr); }
          .pg-hist-card { grid-template-columns: 56px 1fr 20px; gap: 10px; padding: 12px; }
          .pg-ssec { padding: 18px 16px; }
          .pg-status-grid { grid-template-columns: 1fr; }
        }
        @media (max-width: 380px) {
          .pg-nav { padding: 0 14px; }
          .pg-nav-title { font-size: 16px; }
        }
      `}</style>

      <div className="pg-app">
        <ToastContainer toasts={toasts} />

        {/* ── Navbar ─────────────────────────────────────────────────── */}
        <nav className="pg-nav">
          <div className="pg-nav-brand">
            <div className="pg-nav-logo">🛡️</div>
            <div className="pg-nav-title">Phish<span>Guard</span> AI</div>
          </div>

          {/* Desktop tabs */}
          <div className="pg-nav-tabs">
            {[['scan','🔍  Scan'],['history','📋  History'],['settings','⚙️  Settings']].map(([v, label]) => (
              <button key={v} className={`pg-nav-tab${view === v ? ' active' : ''}`} onClick={() => navTo(v)}>{label}</button>
            ))}
          </div>

          <div className="pg-nav-badge">
            🧠 {confirmedCount} confirmed
          </div>

          {/* Hamburger (mobile) */}
          <button className="pg-hamburger" onClick={() => setMobileMenuOpen(o => !o)} aria-label="Menu">
            <span/><span/><span/>
          </button>
        </nav>

        {/* Mobile dropdown menu */}
        <div className={`pg-mobile-menu${mobileMenuOpen ? ' open' : ''}`}>
          {[['scan','🔍  Scan'],['history','📋  History'],['settings','⚙️  Settings']].map(([v, label]) => (
            <button key={v} className={`pg-mobile-tab${view === v ? ' active' : ''}`} onClick={() => navTo(v)}>{label}</button>
          ))}
          <div style={{ padding:'10px 16px 6px', fontSize:12, color:'#94A3B8', fontWeight:600 }}>🧠 {confirmedCount} scams confirmed</div>
        </div>

        {/* ══ SCAN VIEW ═══════════════════════════════════════════════ */}
        {view === 'scan' && (
          <div className="pg-inner">

            {/* Hero banner */}
            <div style={{ background:'linear-gradient(135deg, #1D4ED8 0%, #0EA5E9 100%)', borderRadius:16, padding:'24px 28px', marginBottom:16, color:'#fff', display:'flex', alignItems:'center', gap:20 }}>
              <div style={{ fontSize:44, flexShrink:0 }}>🛡️</div>
              <div>
                <div style={{ fontSize:20, fontWeight:800, letterSpacing:'-0.02em', marginBottom:4 }}>PhishGuard AI</div>
                <div style={{ fontSize:13, opacity:0.85, lineHeight:1.5 }}>Paste any suspicious text message or email below. Our AI will analyze it for scams, phishing, and fraud in seconds.</div>
              </div>
            </div>

            {/* Scan form */}
            <div className="pg-card">
              <div className="pg-card-title">Analyze Message</div>

              <div className="pg-mode">
                <button className={`pg-mbtn${scanMode === 'sms' ? ' active' : ''}`} onClick={() => setScanMode('sms')}>📱  SMS / Text</button>
                <button className={`pg-mbtn${scanMode === 'email' ? ' active' : ''}`} onClick={() => setScanMode('email')}>📧  Email</button>
              </div>

              <div className="pg-field">
                <div className="pg-field-label">Sender</div>
                <input className="pg-input" value={sender} onChange={e => setSender(e.target.value)} maxLength={500} placeholder="Phone number, short code, or email address" />
              </div>

              {scanMode === 'email' && (
                <div className="pg-field">
                  <div className="pg-field-label">Subject</div>
                  <input className="pg-input" value={subject} onChange={e => setSubject(e.target.value)} maxLength={500} placeholder="Email subject line" />
                </div>
              )}

              <div className="pg-field">
                <div className="pg-field-label">
                  Message
                  <span className={`pg-char-count${body.length > 9000 ? ' warn' : ''}`}>{body.length.toLocaleString()} / 10,000</span>
                </div>
                <textarea ref={bodyRef} className="pg-textarea" value={body} onChange={e => setBody(e.target.value)} maxLength={10000} rows={5} placeholder="Paste the suspicious message here…" />
              </div>

              <button className="pg-scan-btn" disabled={scanning} onClick={doScan}>
                {scanning ? `⏳  ${scanStep || 'Analyzing…'}` : '🔍  Scan Message'}
              </button>
              <div className="pg-scan-hint">
                Press <kbd>Ctrl</kbd>+<kbd>Enter</kbd> to scan
              </div>
            </div>

            {/* Result Card */}
            {result && (
              <div className="pg-card" style={{ border:`2px solid ${riskColor(result.risk_level)}40`, boxShadow:`0 4px 24px ${riskColor(result.risk_level)}18` }}>

                {/* Header */}
                <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:20 }}>
                  <span className="pg-card-title" style={{ margin:0 }}>Scan Result</span>
                  <button onClick={copyResult} style={{ padding:'6px 14px', background:'#F8FAFC', border:'1.5px solid #E2E8F0', borderRadius:8, cursor:'pointer', fontSize:12, fontWeight:600, color:'#475569', fontFamily:'inherit' }}>⎘ Copy</button>
                </div>

                {/* Gauge + Verdict */}
                <div style={{ display:'flex', alignItems:'center', gap:20, marginBottom:20, padding:'16px 18px', background:riskBg(result.risk_level), borderRadius:12 }}>
                  <RiskGauge score={result.score} riskLevel={result.risk_level} />
                  <div>
                    <div style={{ fontSize:28, fontWeight:800, letterSpacing:'-0.02em', color:riskColor(result.risk_level), marginBottom:4 }}>{result.risk_level}</div>
                    <div style={{ fontSize:14, color:'#374151', fontWeight:600, marginBottom:2 }}>{result.scam_type || (result.is_scam ? 'Suspicious Content' : 'No Threat Detected')}</div>
                    {result.confidence && <div style={{ fontSize:12, color:'#64748B' }}>Confidence: {Math.round(result.confidence * 100)}%</div>}
                  </div>
                </div>

                {/* URL Safety */}
                {result.urlsChecked?.length > 0 && (
                  <div style={{ marginBottom:18 }}>
                    <div className="pg-result-section-head">
                      URL Safety
                      <span style={{ fontSize:9, padding:'2px 7px', borderRadius:4, background:'#ECFDF5', color:'#059669', border:'1px solid #A7F3D0', fontWeight:700 }}>SAFE BROWSING</span>
                    </div>
                    {result.urlsChecked.map(url => {
                      const threat = result.sbResult?.find(m => m.url === url);
                      const badge = threat ? (threat.threatType === 'MALWARE' ? 'MALWARE' : 'PHISHING') : (result.sbResult ? 'SAFE' : 'UNCHECKED');
                      const col = badge === 'SAFE' ? '#059669' : badge === 'UNCHECKED' ? '#94A3B8' : '#DC2626';
                      const bg  = badge === 'SAFE' ? '#ECFDF5' : badge === 'UNCHECKED' ? '#F8FAFC' : '#FEF2F2';
                      return (
                        <div key={url} style={{ display:'grid', gridTemplateColumns:'auto 1fr', gap:10, alignItems:'center', padding:'8px 12px', borderRadius:8, border:'1px solid #E2E8F0', background:'#F8FAFC', marginBottom:6 }}>
                          <span style={{ fontSize:10, padding:'3px 8px', borderRadius:4, fontWeight:700, color:col, background:bg, border:`1px solid ${col}30`, whiteSpace:'nowrap' }}>{badge}</span>
                          <span style={{ fontSize:12, color:'#64748B', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', fontFamily:'monospace' }}>{url}</span>
                        </div>
                      );
                    })}
                  </div>
                )}

                {/* AI Analysis */}
                <div style={{ marginBottom:18 }}>
                  <div className="pg-result-section-head">AI Analysis</div>
                  <div className="pg-ai-box" style={{ borderLeftColor:riskColor(result.risk_level) }}>{result.reasoning}</div>
                </div>

                {/* Red Flags */}
                {result.red_flags?.length > 0 && (
                  <div style={{ marginBottom:18 }}>
                    <div className="pg-result-section-head">Red Flags</div>
                    {result.red_flags.map((f, i) => (
                      <div key={i} className="pg-flag-item">
                        <span style={{ width:8, height:8, borderRadius:'50%', background:riskColor(result.risk_level), flexShrink:0, marginTop:5 }}/>
                        {f}
                      </div>
                    ))}
                  </div>
                )}

                {/* Recommended Actions */}
                {result.recommended_actions?.length > 0 && (
                  <div style={{ marginBottom:20 }}>
                    <div className="pg-result-section-head">What To Do</div>
                    {result.recommended_actions.map((a, i) => (
                      <div key={i} className="pg-action-item">
                        <span className="pg-action-num">{i + 1}</span>
                        {a}
                      </div>
                    ))}
                  </div>
                )}

                {/* Training feedback */}
                <div style={{ paddingTop:18, borderTop:'1px solid #F1F5F9' }}>
                  <div style={{ fontSize:12, color:'#94A3B8', fontWeight:600, textAlign:'center', marginBottom:10 }}>Was this analysis correct? Help improve PhishGuard</div>
                  <div style={{ display:'flex', gap:8 }}>
                    <button onClick={() => confirmScan(true)} style={{ flex:1, padding:11, borderRadius:10, border:'1.5px solid #FECACA', background:'#FEF2F2', color:'#DC2626', fontFamily:'inherit', fontSize:13, fontWeight:700, cursor:'pointer' }}>⚠️ Confirm Scam</button>
                    <button onClick={() => confirmScan(false)} style={{ flex:1, padding:11, borderRadius:10, border:'1.5px solid #A7F3D0', background:'#ECFDF5', color:'#059669', fontFamily:'inherit', fontSize:13, fontWeight:700, cursor:'pointer' }}>✅ Mark as Safe</button>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ══ HISTORY VIEW ════════════════════════════════════════════ */}
        {view === 'history' && (
          <div className="pg-inner">
            {/* Stats */}
            <div className="pg-stat-grid">
              {[['Total Scans', histStats.total, '#2563EB', '#EFF6FF'], ['Critical', histStats.critical, '#DC2626', '#FEF2F2'], ['High Risk', histStats.high, '#EA580C', '#FFF7ED'], ['Scams Found', histStats.scams, '#D97706', '#FFFBEB']].map(([l, n, c, bg]) => (
                <div key={l} className="pg-stat-card">
                  <div style={{ fontSize:22, fontWeight:800, color:c, lineHeight:1, marginBottom:4, fontVariantNumeric:'tabular-nums' }}>{n}</div>
                  <div style={{ fontSize:11, fontWeight:600, color:'#94A3B8', letterSpacing:'0.05em', textTransform:'uppercase' }}>{l}</div>
                </div>
              ))}
            </div>

            {/* Toolbar */}
            <div className="pg-hist-toolbar">
              <input className="pg-hist-search" value={histSearch} onChange={e => setHistSearch(e.target.value)} placeholder="🔍  Search sender, subject, type…" />
              {[['all','All'],['CRITICAL','Critical'],['scam','Scams'],['safe','Safe']].map(([f, label]) => (
                <button key={f} className={`pg-filter-btn${histFilter === f ? ' active' : ''}`} onClick={() => setHistFilter(f)}>{label}</button>
              ))}
              <button className="pg-clear-btn" onClick={clearHistory}>🗑 Clear</button>
            </div>

            {/* List */}
            {filteredHistory.length === 0 ? (
              <div className="pg-empty">
                <div style={{ fontSize:48, marginBottom:16 }}>📋</div>
                <div style={{ fontSize:18, fontWeight:700, color:'#475569', marginBottom:8 }}>No scans yet</div>
                <div style={{ fontSize:14, color:'#94A3B8' }}>Scan a message to see results here</div>
              </div>
            ) : filteredHistory.map((item, i) => {
              const rl  = item.risk_level || item.riskLevel;
              const col = riskColor(rl);
              const bg  = riskBg(rl);
              const t   = new Date(item.scanned_at || item.scannedAt).toLocaleString(undefined, { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' });
              return (
                <div key={item.scan_id || item.scanId || i} className="pg-hist-card" onClick={() => loadHistoryEntry(item)}>
                  <div style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:6 }}>
                    <span style={{ fontSize:10, padding:'3px 8px', borderRadius:5, fontWeight:700, color:col, background:bg, border:`1px solid ${col}30` }}>{rl}</span>
                    <span style={{ fontSize:20, fontWeight:800, color:col, fontVariantNumeric:'tabular-nums' }}>{item.score}</span>
                  </div>
                  <div style={{ minWidth:0 }}>
                    <div style={{ fontSize:13, fontWeight:700, color:'#0F172A', whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis', marginBottom:3 }}>
                      {(item.mode || 'email') === 'email' ? '📧' : '📱'} {(item.sender || 'Unknown').slice(0, 55)}
                    </div>
                    <div style={{ fontSize:12, color:'#64748B', whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis', marginBottom:4 }}>
                      {(item.scam_type || item.scamType || item.subject || item.body || '—').slice(0, 68)}
                    </div>
                    <div style={{ fontSize:11, color:'#94A3B8' }}>{t}</div>
                  </div>
                  <div style={{ color:'#CBD5E1', fontSize:18, fontWeight:300 }}>›</div>
                </div>
              );
            })}
          </div>
        )}

        {/* ══ SETTINGS VIEW ═══════════════════════════════════════════ */}
        {view === 'settings' && (
          <div className="pg-inner">

            <div className="pg-ssec">
              <div className="pg-ssec-title">⚙️ API Configuration</div>
              <div className="pg-ssec-desc">
                API keys are stored as environment variables in Vercel — they never reach your browser.
                Set them in <strong>Vercel Dashboard → Settings → Environment Variables</strong>.
              </div>
              {[
                ['ANTHROPIC_API_KEY', 'Claude AI (required)', 'https://console.anthropic.com', 'sk-ant-…'],
                ['GOOGLE_SAFE_BROWSING_KEY', 'Google Safe Browsing — URL checking', 'https://console.cloud.google.com', 'AIza…'],
                ['AWS_ACCESS_KEY_ID', 'AWS Access Key — DynamoDB', 'https://console.aws.amazon.com/iam', 'AKIA…'],
                ['AWS_SECRET_ACCESS_KEY', 'AWS Secret Key', '', ''],
                ['AWS_REGION', 'AWS Region', '', 'us-east-1'],
                ['WHATSAPP_ACCESS_TOKEN', 'WhatsApp Business API token', 'https://developers.facebook.com', 'EAA…'],
                ['MESSENGER_ACCESS_TOKEN', 'Messenger Page access token', 'https://developers.facebook.com', 'EAA…'],
              ].map(([key, label, url, example]) => (
                <div key={key} className="pg-env-row">
                  <div className="pg-env-top">
                    <code style={{ fontSize:12, color:'#2563EB', fontFamily:'monospace' }}>{key}</code>
                    {url && <a href={url} target="_blank" rel="noopener noreferrer" style={{ fontSize:12, color:'#2563EB', textDecoration:'none', fontWeight:600 }}>Get key →</a>}
                  </div>
                  <div style={{ fontSize:12, color:'#64748B' }}>{label}</div>
                  {example && <div style={{ fontSize:11, color:'#94A3B8', marginTop:3, fontFamily:'monospace' }}>e.g. {example}</div>}
                </div>
              ))}
            </div>

            <div className="pg-ssec">
              <div className="pg-ssec-title">📊 App Status</div>
              <div className="pg-status-grid">
                {[['18', 'Threat Patterns'], [String(confirmedCount), 'Confirmed Scams'], ['AWS DynamoDB', 'Database'], ['Vercel', 'Hosting']].map(([val, label], i) => (
                  <div key={i} className="pg-status-item">
                    <div style={{ fontSize:/^\d/.test(val) ? 22 : 14, fontWeight:800, color:'#2563EB', marginBottom:4 }}>{val}</div>
                    <div style={{ fontSize:11, color:'#94A3B8', fontWeight:600, textTransform:'uppercase', letterSpacing:'0.05em' }}>{label}</div>
                  </div>
                ))}
              </div>
            </div>

            <div className="pg-ssec">
              <div className="pg-ssec-title">🏆 H01 Hackathon Submission</div>
              <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
                {[['Track','Track 2 — Monetizable B2B App'],['AWS Database','DynamoDB (3 tables)'],['Frontend','Next.js 14 on Vercel'],['Channels','Web · WhatsApp · Messenger'],['Hashtag','#HOHackathon'],['Deadline','June 29, 2026 @ 8:00pm EDT']].map(([k,v]) => (
                  <div key={k} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'9px 0', borderBottom:'1px solid #F1F5F9', fontSize:13 }}>
                    <span style={{ color:'#64748B', fontWeight:600 }}>{k}</span>
                    <span style={{ color:'#0F172A', fontWeight:700 }}>{v}</span>
                  </div>
                ))}
              </div>
            </div>

          </div>
        )}
      </div>
    </>
  );
}
