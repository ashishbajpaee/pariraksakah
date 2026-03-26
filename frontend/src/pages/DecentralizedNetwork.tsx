import React, { useState, useEffect } from 'react';

const DSRN_API = (import.meta.env.VITE_API_URL || 'http://localhost:8067') + '/dsrn';

interface Peer { peer_id: string; organization_name: string; trust_score: number; reputation_score: number; status: string; }
interface ConsensusRound { round_id: string; proposal_type: string; phase: string; prepares: number; commits: number; result: string; }
interface ThreatIntel { threat_id: string; threat_type: string; severity: string; confidence_score: number; source_peer_id: string; }
interface ResponseAction { action_id: string; action_type: string; votes_for: number; votes_against: number; status: string; required_threshold: number; }
interface LedgerBlock { block_number: number; block_hash: string; transactions: any[]; created_at: string; }
interface Alert { type: string; severity: string; message: string; at: string; }

const DecentralizedNetwork: React.FC = () => {
  const [tab, setTab] = useState('overview');
  const [peers, setPeers] = useState<Peer[]>([]);
  const [consensus, setConsensus] = useState<ConsensusRound[]>([]);
  const [threats, setThreats] = useState<ThreatIntel[]>([]);
  const [responses, setResponses] = useState<ResponseAction[]>([]);
  const [blocks, setBlocks] = useState<LedgerBlock[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [resilience, setResilience] = useState<any>({});
  const [trustHealth, setTrustHealth] = useState<any>({});

  useEffect(() => {
    const load = async () => {
      try {
        const [p, c, t, r, b, a, res, th] = await Promise.all([
          fetch(`${DSRN_API}/peers`).then(r=>r.json()).catch(()=>({peers:[]})),
          fetch(`${DSRN_API}/consensus/history`).then(r=>r.json()).catch(()=>({rounds:[]})),
          fetch(`${DSRN_API}/threats/received`).then(r=>r.json()).catch(()=>({threats:[]})),
          fetch(`${DSRN_API}/response/pending`).then(r=>r.json()).catch(()=>({pending:[]})),
          fetch(`${DSRN_API}/ledger/blocks`).then(r=>r.json()).catch(()=>({blocks:[]})),
          fetch(`${DSRN_API}/network/alerts`).then(r=>r.json()).catch(()=>({alerts:[]})),
          fetch(`${DSRN_API}/network/resilience`).then(r=>r.json()).catch(()=>({})),
          fetch(`${DSRN_API}/trust/health`).then(r=>r.json()).catch(()=>({})),
        ]);
        setPeers(p.peers||[]); setConsensus(c.rounds||[]); setThreats(t.threats||[]);
        setResponses(r.pending||[]); setBlocks(b.blocks||[]); setAlerts(a.alerts||[]);
        setResilience(res); setTrustHealth(th);
      } catch(e) {}
    };
    load();
    const iv = setInterval(load, 10000);
    return () => clearInterval(iv);
  }, []);

  const TABS = ['overview','peers','consensus','threats','responses','ledger','alerts'];
  const severityColor = (s: string) => s==='CRITICAL'?'#EF4444':s==='HIGH'?'#F97316':s==='MEDIUM'?'#F59E0B':'#22C55E';
  const phaseColor = (p: string) => p==='REPLY'?'#22C55E':p==='COMMIT'?'#3B82F6':p==='PREPARE'?'#F59E0B':'#94A3B8';

  return (
    <div style={{padding:24,color:'#E2E8F0',fontFamily:"'Inter',sans-serif"}}>
      <h1 style={{margin:0,fontSize:32,fontWeight:800}}>🌐 Decentralized Security Response Network</h1>
      <p style={{color:'#94A3B8',fontSize:14,marginBottom:20}}>Byzantine Fault Tolerant · Zero Single Point of Failure · Peer-to-Peer Threat Intelligence</p>

      <div style={{display:'flex',gap:4,marginBottom:24,borderBottom:'1px solid #334155',paddingBottom:8}}>
        {TABS.map(t=>(
          <button key={t} onClick={()=>setTab(t)} style={{
            background:tab===t?'#6366F1':'transparent',color:tab===t?'#fff':'#94A3B8',
            border:'none',borderRadius:6,padding:'8px 16px',cursor:'pointer',fontWeight:tab===t?600:400,fontSize:13,textTransform:'capitalize'
          }}>{t}</button>
        ))}
      </div>

      {tab==='overview'&&(
        <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:16}}>
          <div style={{background:'#0F172A',borderRadius:12,padding:24,textAlign:'center'}}>
            <div style={{color:'#94A3B8',fontSize:12,marginBottom:8}}>RESILIENCE SCORE</div>
            <div style={{fontSize:56,fontWeight:900,color:resilience.resilience_score>=75?'#22C55E':resilience.resilience_score>=50?'#F59E0B':'#EF4444',
              textShadow:`0 0 30px ${resilience.resilience_score>=75?'#22C55E80':'#EF444480'}`}}>
              {(resilience.resilience_score||0).toFixed(0)}
            </div>
          </div>
          <div style={{background:'#0F172A',borderRadius:12,padding:24,textAlign:'center'}}>
            <div style={{color:'#94A3B8',fontSize:12,marginBottom:8}}>ACTIVE PEERS</div>
            <div style={{fontSize:56,fontWeight:900,color:'#3B82F6'}}>{peers.filter(p=>p.status==='ACTIVE').length}</div>
          </div>
          <div style={{background:'#0F172A',borderRadius:12,padding:24,textAlign:'center'}}>
            <div style={{color:'#94A3B8',fontSize:12,marginBottom:8}}>BYZANTINE TOLERANCE</div>
            <div style={{fontSize:56,fontWeight:900,color:'#8B5CF6'}}>{resilience.byzantine_tolerance||0}</div>
            <div style={{color:'#64748B',fontSize:11}}>faulty peers tolerated</div>
          </div>
          <div style={{background:'#0F172A',borderRadius:12,padding:24,textAlign:'center'}}>
            <div style={{color:'#94A3B8',fontSize:12,marginBottom:8}}>CONSENSUS SUCCESS</div>
            <div style={{fontSize:56,fontWeight:900,color:'#10B981'}}>{resilience.consensus_success_rate||0}%</div>
          </div>
          <div style={{background:'#0F172A',borderRadius:12,padding:24,gridColumn:'span 2'}}>
            <h3 style={{margin:'0 0 12px',color:'#F8FAFC'}}>Trust Network Health</h3>
            <div style={{display:'flex',justifyContent:'space-around'}}>
              <div><span style={{color:'#94A3B8'}}>Avg Reputation:</span> <strong style={{color:'#22C55E'}}>{trustHealth.average_reputation||0}</strong></div>
              <div><span style={{color:'#94A3B8'}}>Above Threshold:</span> <strong>{trustHealth.peers_above_threshold||0}</strong></div>
              <div><span style={{color:'#94A3B8'}}>Blacklisted:</span> <strong style={{color:'#EF4444'}}>{trustHealth.blacklisted||0}</strong></div>
            </div>
          </div>
          <div style={{background:'#0F172A',borderRadius:12,padding:24,gridColumn:'span 2'}}>
            <h3 style={{margin:'0 0 12px',color:'#F8FAFC'}}>Recent Alerts</h3>
            {alerts.length===0&&<div style={{color:'#64748B'}}>No active alerts</div>}
            {alerts.slice(-5).map((a,i)=>(
              <div key={i} style={{padding:8,borderLeft:`3px solid ${severityColor(a.severity)}`,marginBottom:6,background:'#1E293B',borderRadius:4}}>
                <span style={{color:severityColor(a.severity),fontWeight:700,fontSize:12}}>{a.severity}</span>{' '}
                <span style={{color:'#E2E8F0',fontSize:13}}>{a.message}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {tab==='peers'&&(
        <div style={{background:'#0F172A',borderRadius:12,padding:20}}>
          <h3 style={{margin:'0 0 16px'}}>Peer Organizations</h3>
          <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(280px,1fr))',gap:12}}>
            {peers.map(p=>(
              <div key={p.peer_id} style={{background:'#1E293B',borderRadius:8,padding:16,borderLeft:`4px solid ${p.status==='ACTIVE'?'#22C55E':'#EF4444'}`}}>
                <div style={{fontWeight:700,fontSize:15,color:'#F8FAFC'}}>{p.organization_name}</div>
                <div style={{color:'#94A3B8',fontSize:12,fontFamily:'monospace'}}>{p.peer_id}</div>
                <div style={{display:'flex',justifyContent:'space-between',marginTop:8}}>
                  <span style={{color:'#94A3B8',fontSize:12}}>Trust: <strong style={{color:'#60A5FA'}}>{(p.trust_score||0).toFixed(0)}</strong></span>
                  <span style={{color:'#94A3B8',fontSize:12}}>Rep: <strong style={{color:'#A78BFA'}}>{(p.reputation_score||0).toFixed(0)}</strong></span>
                  <span style={{padding:'2px 8px',borderRadius:12,fontSize:11,fontWeight:700,
                    background:p.status==='ACTIVE'?'#166534':'#991B1B',color:p.status==='ACTIVE'?'#4ADE80':'#F87171'}}>{p.status}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {tab==='consensus'&&(
        <div style={{background:'#0F172A',borderRadius:12,padding:20}}>
          <h3 style={{margin:'0 0 16px'}}>Byzantine Consensus Rounds</h3>
          {consensus.length===0&&<div style={{color:'#64748B',textAlign:'center',padding:24}}>No consensus rounds yet</div>}
          {consensus.map(r=>(
            <div key={r.round_id} style={{background:'#1E293B',borderRadius:8,padding:16,marginBottom:8,borderLeft:`4px solid ${phaseColor(r.phase)}`}}>
              <div style={{display:'flex',justifyContent:'space-between'}}>
                <span style={{fontWeight:700,color:'#F8FAFC'}}>{r.proposal_type}</span>
                <span style={{padding:'2px 8px',borderRadius:12,fontSize:11,background:phaseColor(r.phase)+'30',color:phaseColor(r.phase)}}>{r.phase}</span>
              </div>
              <div style={{color:'#94A3B8',fontSize:12,marginTop:6}}>
                Prepares: {r.prepares} · Commits: {r.commits} · Result: <strong style={{color:r.result==='COMMITTED'?'#22C55E':'#F59E0B'}}>{r.result}</strong>
              </div>
            </div>
          ))}
        </div>
      )}

      {tab==='threats'&&(
        <div style={{background:'#0F172A',borderRadius:12,padding:20}}>
          <h3 style={{margin:'0 0 16px'}}>Peer Threat Intelligence Feed</h3>
          {threats.length===0&&<div style={{color:'#64748B',textAlign:'center',padding:24}}>No threats received from network</div>}
          {threats.map((t,i)=>(
            <div key={i} style={{background:'#1E293B',borderRadius:8,padding:12,marginBottom:6,borderLeft:`4px solid ${severityColor(t.severity)}`}}>
              <div style={{display:'flex',justifyContent:'space-between'}}>
                <span style={{fontWeight:600,color:'#F8FAFC'}}>{t.threat_type}</span>
                <span style={{color:severityColor(t.severity),fontSize:12,fontWeight:700}}>{t.severity}</span>
              </div>
              <div style={{color:'#94A3B8',fontSize:12}}>
                Source: {t.source_peer_id} · Confidence: {(t.confidence_score*100).toFixed(0)}%
              </div>
            </div>
          ))}
        </div>
      )}

      {tab==='responses'&&(
        <div style={{background:'#0F172A',borderRadius:12,padding:20}}>
          <h3 style={{margin:'0 0 16px'}}>Response Coordination</h3>
          {responses.length===0&&<div style={{color:'#64748B',textAlign:'center',padding:24}}>No pending response actions</div>}
          {responses.map(r=>(
            <div key={r.action_id} style={{background:'#1E293B',borderRadius:8,padding:16,marginBottom:8}}>
              <div style={{fontWeight:700,color:'#F8FAFC'}}>{r.action_type}</div>
              <div style={{display:'flex',alignItems:'center',gap:12,marginTop:8}}>
                <div style={{flex:1,height:8,background:'#334155',borderRadius:4,overflow:'hidden'}}>
                  <div style={{width:`${(r.votes_for/(r.votes_for+r.votes_against||1))*100}%`,height:'100%',background:'#22C55E',borderRadius:4}}/>
                </div>
                <span style={{color:'#94A3B8',fontSize:12}}>{r.votes_for} for / {r.votes_against} against</span>
                <span style={{padding:'2px 8px',borderRadius:12,fontSize:11,background:r.status==='COMMITTED'?'#166534':'#3730A3',
                  color:r.status==='COMMITTED'?'#4ADE80':'#A78BFA'}}>{r.status}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {tab==='ledger'&&(
        <div style={{background:'#0F172A',borderRadius:12,padding:20}}>
          <h3 style={{margin:'0 0 16px'}}>Distributed Threat Ledger</h3>
          {blocks.map(b=>(
            <div key={b.block_number} style={{background:'#1E293B',padding:12,borderRadius:6,marginBottom:6,borderLeft:'3px solid #8B5CF6'}}>
              <div style={{display:'flex',justifyContent:'space-between'}}>
                <span style={{fontWeight:700,color:'#A78BFA'}}>Block #{b.block_number}</span>
                <span style={{color:'#64748B',fontSize:12}}>{new Date(b.created_at).toLocaleString()}</span>
              </div>
              <div style={{color:'#94A3B8',fontSize:12,fontFamily:'monospace',marginTop:4}}>{b.block_hash?.substring(0,32)}...</div>
            </div>
          ))}
        </div>
      )}

      {tab==='alerts'&&(
        <div style={{background:'#0F172A',borderRadius:12,padding:20}}>
          <h3 style={{margin:'0 0 16px'}}>Network Alerts</h3>
          {alerts.length===0&&<div style={{color:'#64748B',textAlign:'center',padding:24}}>No active alerts</div>}
          {alerts.map((a,i)=>(
            <div key={i} style={{background:'#1E293B',padding:12,borderRadius:6,marginBottom:6,borderLeft:`3px solid ${severityColor(a.severity)}`}}>
              <div style={{display:'flex',justifyContent:'space-between'}}>
                <span style={{fontWeight:700,color:severityColor(a.severity)}}>{a.type}</span>
                <span style={{color:'#64748B',fontSize:12}}>{new Date(a.at).toLocaleString()}</span>
              </div>
              <div style={{color:'#E2E8F0',fontSize:13}}>{a.message}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default DecentralizedNetwork;
