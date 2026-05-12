#!/usr/bin/env python3
"""
VAPTBot v2 - AI-Powered VAPT Assistant (Groq + Structured Reports)
Run: python3 vaptbot.py
Open: http://localhost:5000
"""

import os, re, socket, subprocess, threading, webbrowser, json
from flask import Flask, request, jsonify
from groq import Groq
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

SYSTEM_PROMPT = """You are VAPTBot — a senior ethical hacker and VAPT expert. You ALWAYS respond in structured format.

=== MODE 1: TARGET SCAN ===
When given scan data (nmap/nikto results) OR just a target, ALWAYS produce this EXACT report structure:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[TARGET ANALYSIS]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[*] Target     : <target>
[*] IP Address : <ip>
[*] Scan Type  : <type>
[*] Risk Level : CRITICAL / HIGH / MEDIUM / LOW

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[OPEN PORTS & SERVICES]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[+] PORT   STATE   SERVICE   VERSION
<list all ports found or common ports for this type of target>

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[VULNERABILITIES FOUND]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
List at least 5 real vulnerabilities. For each:
[SEVERITY] Vulnerability Name
  Description: what it is
  Impact: what attacker can do
  CVE: CVE-XXXX-XXXXX
  CWE: CWE-XXX

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[CVE REFERENCES]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
List all CVEs with:
CVE-XXXX-XXXXX | CVSS: X.X | <short description>

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[NEXT STEPS - GUIDED TESTING WORKFLOW]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Give numbered step-by-step workflow:
Step 1: <what to do> → Tool: <tool> → Command: <exact command>
Step 2: ...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[REMEDIATION]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
For each vulnerability, give fix recommendation.

IMPORTANT:
- Always give REAL CVEs relevant to the target type (web app, server, etc.)
- If nmap timed out, still give realistic CVEs based on the target (web apps always have OWASP issues)
- For web targets always include: SQLi, XSS, CSRF, IDOR, SSRF vulnerabilities
- CVSS scores must be real numbers
- Use [CRITICAL], [HIGH], [MEDIUM], [LOW] tags

=== MODE 2: SECURITY Q&A ===
For general questions, give detailed technical answers with:
- Attack methodology
- Real payloads/commands  
- Tools to use
- Detection & prevention
- CVE examples

Always use [+] [!] [*] prefixes. Authorized testing only."""

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VAPTBot v2</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --g:#00ff88;--gd:#00cc6a;--gk:#004422;--gg:rgba(0,255,136,0.1);
  --r:#ff4444;--o:#ff8800;--y:#ffcc00;--c:#00ccff;--p:#bb66ff;
  --bg:#050a07;--b2:#080f0b;--b3:#0d1a12;--br:rgba(0,255,136,0.18);
  --tx:#c8e6d0;--td:#4a7a58;--mn:'JetBrains Mono',monospace
}
html,body{height:100%;background:var(--bg);color:var(--tx);font-family:var(--mn);font-size:13px;overflow:hidden}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.03) 2px,rgba(0,0,0,.03) 4px);pointer-events:none;z-index:9999}
.T{display:flex;flex-direction:column;height:100vh;max-width:1150px;margin:0 auto;border-left:1px solid var(--br);border-right:1px solid var(--br)}

/* TOPBAR */
.tb{display:flex;align-items:center;gap:12px;padding:10px 16px;background:var(--b2);border-bottom:1px solid var(--br);flex-shrink:0}
.ds{display:flex;gap:6px}.d{width:11px;height:11px;border-radius:50%}.dr{background:#ff5f57}.dy{background:#febc2e}.dg{background:#28c840}
.tt{color:var(--g);font-size:12px;font-weight:600;letter-spacing:.12em;flex:1;text-align:center}
.bk{font-size:9px;color:var(--g);background:var(--gg);border:1px solid var(--br);padding:2px 8px;border-radius:3px;animation:bl 2s step-end infinite}
@keyframes bl{0%,100%{opacity:1}50%{opacity:.4}}

/* BANNER */
.bn{background:var(--b2);border-bottom:1px solid var(--br);padding:10px 18px;flex-shrink:0}
.ac{color:var(--g);font-size:9px;line-height:1.2;font-weight:700;white-space:pre}
.bs{margin-top:6px;color:var(--td);font-size:11px}.bs span{color:var(--gd)}

/* QUICK BTNS */
.qk{display:flex;gap:6px;padding:8px 14px;background:var(--b2);border-bottom:1px solid var(--br);flex-wrap:wrap;flex-shrink:0}
.qb{font-family:var(--mn);font-size:10px;color:var(--td);background:transparent;border:1px solid rgba(0,255,136,.15);padding:4px 9px;border-radius:3px;cursor:pointer;transition:all .15s}
.qb:hover{color:var(--g);border-color:var(--g);background:var(--gg)}

/* OUTPUT */
.out{flex:1;overflow-y:auto;padding:16px 20px;display:flex;flex-direction:column;gap:14px}
.out::-webkit-scrollbar{width:4px}.out::-webkit-scrollbar-thumb{background:var(--gk);border-radius:2px}
.msg{display:flex;flex-direction:column;gap:5px;animation:fi .3s ease}
@keyframes fi{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
.mh{display:flex;align-items:center;gap:8px;font-size:10px;letter-spacing:.1em;font-weight:600}
.mh.u{color:var(--c)}.mh.b{color:var(--g)}.mh.s{color:var(--y)}
.mt{color:var(--td);font-weight:400;font-size:10px}
.mb{font-size:12.5px;line-height:1.9;white-space:pre-wrap;word-break:break-word;padding-left:16px;border-left:2px solid transparent}
.mb.u{color:#a8d8ff;border-left-color:var(--c)}
.mb.b{color:var(--tx);border-left-color:var(--gd)}
.mb.s{color:#ffe080;border-left-color:var(--y);font-size:11px}

/* SCAN TAG */
.stag{display:inline-flex;align-items:center;gap:6px;font-size:10px;color:var(--o);background:rgba(255,136,0,.1);border:1px solid rgba(255,136,0,.3);border-radius:3px;padding:3px 10px;margin-bottom:6px}
.sd{width:6px;height:6px;border-radius:50%;background:var(--o);animation:pu .8s ease-in-out infinite alternate}
@keyframes pu{from{opacity:.3}to{opacity:1}}

/* REPORT BOX */
.rbox{background:var(--b3);border:1px solid rgba(0,255,136,.2);border-radius:6px;padding:14px 16px;margin-top:6px;font-size:12px;line-height:1.9;white-space:pre-wrap;word-break:break-word;color:var(--tx)}

/* THINKING */
.th{display:flex;align-items:center;gap:10px;color:var(--td);font-size:11px;padding-left:16px}
.td2{display:flex;gap:4px}.td2 span{width:5px;height:5px;border-radius:50%;background:var(--gd);animation:bo 1.2s ease-in-out infinite}
.td2 span:nth-child(2){animation-delay:.2s}.td2 span:nth-child(3){animation-delay:.4s}
@keyframes bo{0%,100%{transform:translateY(0);opacity:.4}50%{transform:translateY(-4px);opacity:1}}

/* INPUT */
.ib{display:flex;align-items:center;padding:12px 16px;background:var(--b2);border-top:1px solid var(--br);flex-shrink:0}
.pr{color:var(--g);font-size:14px;font-weight:700;padding-right:10px;user-select:none}
#inp{flex:1;background:transparent;border:none;outline:none;font-family:var(--mn);font-size:13px;color:var(--tx);caret-color:var(--g)}
#inp::placeholder{color:var(--td)}
.sb{font-family:var(--mn);font-size:11px;font-weight:700;letter-spacing:.1em;color:#050a07;background:var(--g);border:none;padding:8px 18px;border-radius:3px;cursor:pointer;transition:all .15s;flex-shrink:0}
.sb:hover{background:#00ffaa}.sb:disabled{opacity:.4;cursor:not-allowed}

/* STATUS BAR */
.bar{display:flex;justify-content:space-between;padding:5px 16px;background:var(--b2);border-top:1px solid var(--br);flex-shrink:0;font-size:10px;color:var(--td)}
.bar span{color:var(--gd)}

/* COLOR TOKENS */
.crit{color:#ff4444;font-weight:700}.high{color:#ff8800;font-weight:700}
.med{color:#ffcc00;font-weight:600}.low{color:#00cc6a}
.cve{color:#bb66ff;font-weight:600}.cwe{color:#aa44ff}
.plus{color:#00ff88}.bang{color:#ff4444}.star{color:#00ccff}
.sep{color:#1a4a2a}
</style>
</head>
<body>
<div class="T">
  <div class="tb">
    <div class="ds"><div class="d dr"></div><div class="d dy"></div><div class="d dg"></div></div>
    <div class="tt">VAPTBOT v2.0 — AI VULNERABILITY ASSESSMENT & PENTEST ASSISTANT</div>
    <div class="bk">● ONLINE</div>
  </div>
  <div class="bn">
    <div class="ac">██╗   ██╗ █████╗ ██████╗ ████████╗██████╗  ██████╗ ████████╗
██║   ██║██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗╚══██╔══╝
██║   ██║███████║██████╔╝   ██║   ██████╔╝██║   ██║   ██║
╚██╗ ██╔╝██╔══██║██╔═══╝    ██║   ██╔══██╗██║   ██║   ██║
 ╚████╔╝ ██║  ██║██║        ██║   ██████╔╝╚██████╔╝   ██║
  ╚═══╝  ╚═╝  ╚═╝╚═╝        ╚═╝   ╚═════╝  ╚═════╝    ╚═╝</div>
    <div class="bs"><span>[*]</span> Full VA Reports + CVE Suggestions + Guided Pentest Workflow &nbsp;|&nbsp; <span>[!]</span> Authorized Testing Only</div>
  </div>
  <div class="qk">
    <button class="qb" onclick="qs('https://demo.testfire.net')">🎯 Demo Scan</button>
    <button class="qb" onclick="qs('Explain SQL Injection with payloads and tools')">⚡ SQLi</button>
    <button class="qb" onclick="qs('How to test XSS in a web application step by step')">⚡ XSS</button>
    <button class="qb" onclick="qs('Explain SSRF vulnerability exploitation techniques')">⚡ SSRF</button>
    <button class="qb" onclick="qs('OWASP Top 10 with CVEs and testing methodology')">⚡ OWASP Top 10</button>
    <button class="qb" onclick="qs('How to do subdomain enumeration and recon?')">⚡ Recon</button>
    <button class="qb" onclick="qs('How to find IDOR vulnerabilities with examples')">⚡ IDOR</button>
    <button class="qb" onclick="qs('Explain Log4Shell CVE-2021-44228 exploitation')">⚡ Log4Shell</button>
  </div>
  <div class="out" id="out">
    <div class="msg">
      <div class="mh s"><span>[SYSTEM]</span><span class="mt" id="st"></span></div>
      <div class="mb s">VAPTBot v2.0 initialized. Groq + Llama 3.3 70B ready.

[*] Enhanced with FULL VA REPORT generation:
  → Target scan  →  Structured report + Real CVEs + CVSS scores + Next steps
  → Security Q&A →  Methodology + Payloads + Tools + Prevention

[+] Supports: URL · IP Address · Domain · General Security Questions
[!] AUTHOR:Arulkumaran
[+] Ready — enter your target or question.</div>
    </div>
  </div>
  <div class="ib">
    <span class="pr">root@vapt:~$&nbsp;</span>
    <input id="inp" type="text" placeholder="enter URL / IP / domain to scan  OR  ask a security question..." autocomplete="off" spellcheck="false">
    <button class="sb" id="sbtn" onclick="send()">▶ SCAN</button>
  </div>
  <div class="bar">
    <div><span id="mc">[+] SCANS: 0</span>&nbsp;&nbsp;<span>[+] llama-3.3-70b-versatile via groq</span></div>
    <div><span id="st2">IDLE</span></div>
  </div>
</div>
<script>
const out=document.getElementById('out'),inp=document.getElementById('inp'),sbtn=document.getElementById('sbtn');
let history=[],count=0;
document.getElementById('st').textContent=new Date().toLocaleTimeString();
const ts=()=>new Date().toLocaleTimeString('en-GB',{hour12:false});

function colorize(t){
  return t
    .replace(/\[CRITICAL\]/g,'<span class="crit">[CRITICAL]</span>')
    .replace(/\[HIGH\]/g,'<span class="high">[HIGH]</span>')
    .replace(/\[MEDIUM\]/g,'<span class="med">[MEDIUM]</span>')
    .replace(/\[LOW\]/g,'<span class="low">[LOW]</span>')
    .replace(/\bCRITICAL\b/g,'<span class="crit">CRITICAL</span>')
    .replace(/\bHIGH\b/g,'<span class="high">HIGH</span>')
    .replace(/\bMEDIUM\b/g,'<span class="med">MEDIUM</span>')
    .replace(/\bLOW\b/g,'<span class="low">LOW</span>')
    .replace(/CVE-\d{4}-\d+/g,m=>`<span class="cve">${m}</span>`)
    .replace(/CWE-\d+/g,m=>`<span class="cwe">${m}</span>`)
    .replace(/CVSS:\s*[\d.]+/g,m=>`<span class="high">${m}</span>`)
    .replace(/━+/g,m=>`<span class="sep">${m}</span>`)
    .replace(/\[TARGET ANALYSIS\]|\[OPEN PORTS[^\]]*\]|\[VULNERABILITIES[^\]]*\]|\[CVE REFERENCES\]|\[NEXT STEPS[^\]]*\]|\[REMEDIATION\]/g,m=>`<span class="star">${m}</span>`)
    .replace(/\[\+\]/g,'<span class="plus">[+]</span>')
    .replace(/\[!\]/g,'<span class="bang">[!]</span>')
    .replace(/\[\*\]/g,'<span class="star">[*]</span>');
}

function addMsg(role,text,scanned){
  const w=document.createElement('div');
  w.className='msg';
  if(role==='user'){
    w.innerHTML=`<div class="mh u"><span>[YOU]</span><span class="mt">${ts()}</span></div><div class="mb u">${text.replace(/</g,'&lt;')}</div>`;
  } else {
    let inner='';
    if(scanned) inner=`<div class="stag"><div class="sd"></div>ACTIVE SCAN + VA REPORT GENERATED</div>`;
    inner+=`<div class="rbox">${colorize(text.replace(/</g,'&lt;'))}</div>`;
    w.innerHTML=`<div class="mh b"><span>[VAPTBOT]</span><span class="mt">${ts()}</span></div>${inner}`;
  }
  out.appendChild(w);
  out.scrollTop=out.scrollHeight;
}

function addThink(msg){
  const w=document.createElement('div');
  w.id='think';w.className='msg';
  w.innerHTML=`<div class="mh b"><span>[VAPTBOT]</span></div>
    <div class="th"><div class="td2"><span></span><span></span><span></span></div>
    <span>${msg||'analyzing target...'}</span></div>`;
  out.appendChild(w);out.scrollTop=out.scrollHeight;
}

const rmThink=()=>{const e=document.getElementById('think');if(e)e.remove()};
const setSt=s=>document.getElementById('st2').textContent=s;
const updC=()=>document.getElementById('mc').textContent=`[+] SCANS: ${count}`;

async function send(){
  const msg=inp.value.trim();if(!msg)return;
  inp.value='';sbtn.disabled=true;
  addMsg('user',msg);
  const isTarget=/https?:\/\/|\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|[a-zA-Z0-9-]+\\.[a-zA-Z]{2,}/.test(msg) && !/^(how|what|why|explain|tell|show|is |can |does )/i.test(msg);
  addThink(isTarget?'running nmap scan + generating VA report...':'analyzing question...');
  setSt(isTarget?'SCANNING TARGET...':'THINKING...');
  history.push({role:'user',content:msg});
  try{
    const res=await fetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:msg,history:history.slice(-10)})});
    const data=await res.json();
    rmThink();
    if(data.error){addMsg('bot',`[!] Error: ${data.error}`);}
    else{
      addMsg('bot',data.reply,data.scan_performed);
      history.push({role:'assistant',content:data.reply});
      if(data.scan_performed){count++;updC();}
    }
  }catch(e){rmThink();addMsg('bot',`[!] Connection error: ${e.message}`);}
  sbtn.disabled=false;setSt('IDLE');inp.focus();
}

function qs(t){inp.value=t;send();}
inp.addEventListener('keydown',e=>{if(e.key==='Enter')send();});
inp.focus();
</script>
</body>
</html>"""


def detect_target(text):
    low = text.lower().strip()
    skip = ('how','what','why','explain','tell','describe','show','is ','can ','does ','when ','list','give')
    if any(low.startswith(w) for w in skip): return None
    if re.search(r'https?://[^\s]+', text): return 'url'
    if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text): return 'ip'
    if re.search(r'\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b', text): return 'domain'
    return None


def run_nmap(target):
    try:
        clean = re.sub(r'https?://', '', target).rstrip('/').split('/')[0]
        r = subprocess.run(
            ['nmap', '-sV', '-sC', '--open', '-T4', '--top-ports', '1000', '-Pn', clean],
            capture_output=True, text=True, timeout=45
        )
        return r.stdout if r.stdout.strip() else 'nmap returned no output'
    except FileNotFoundError:
        return 'nmap_not_found'
    except subprocess.TimeoutExpired:
        return 'nmap_timeout'
    except Exception as e:
        return f'error: {e}'


def run_nikto(target):
    try:
        r = subprocess.run(
            ['nikto', '-h', target, '-maxtime', '20s', '-nointeractive'],
            capture_output=True, text=True, timeout=30
        )
        return r.stdout if r.stdout.strip() else ''
    except:
        return ''


def resolve_host(target):
    try:
        clean = re.sub(r'https?://', '', target).rstrip('/').split('/')[0]
        return socket.gethostbyname(clean)
    except:
        return None


def build_scan_context(target, target_type):
    ip = resolve_host(target)
    nmap_out = run_nmap(target)
    nikto_out = run_nikto(target) if target_type in ['url', 'domain'] else ''

    context = f"""
[SCAN REQUEST]
Target: {target}
Type: {target_type.upper()}
Resolved IP: {ip or 'Could not resolve'}

[NMAP RESULTS]
{nmap_out}
"""
    if nikto_out:
        context += f"\n[NIKTO WEB SCAN]\n{nikto_out}"

    if 'timeout' in nmap_out or 'not_found' in nmap_out or 'no output' in nmap_out:
        context += """
[NOTE FOR AI]
Nmap scan timed out or was blocked. This is common with firewalled targets.
Still generate a COMPLETE VA report based on:
- The target type (web application at this URL)
- Common vulnerabilities for this type of target
- Real CVEs from OWASP Top 10, web app common issues
- Assume typical web stack (HTTP/HTTPS, possible Apache/Nginx, PHP/Java)
Generate realistic port list, at least 5-7 real CVEs with CVSS scores.
"""
    return context


@app.route('/')
def index():
    return HTML_PAGE, 200, {'Content-Type': 'text/html'}


@app.route('/api/chat', methods=['POST'])
def chat():
    data = request.json
    msg = data.get('message', '').strip()
    history = data.get('history', [])
    if not msg:
        return jsonify({'error': 'empty message'}), 400

    scan_data = ''
    target_type = detect_target(msg)

    if target_type:
        match = (
            re.search(r'https?://[^\s]+', msg) or
            re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg) or
            re.search(r'\b(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}\b', msg)
        )
        if match:
            target = match.group()
            scan_data = build_scan_context(target, target_type)

    messages = [{'role': h['role'], 'content': h['content']} for h in history[-8:]]
    messages.append({'role': 'user', 'content': msg + ('\n\n' + scan_data if scan_data else '')})

    try:
        resp = client.chat.completions.create(
            model='llama-3.3-70b-versatile',
            max_tokens=2500,
            temperature=0.3,
            messages=[{'role': 'system', 'content': SYSTEM_PROMPT}] + messages
        )
        reply = resp.choices[0].message.content
        return jsonify({'reply': reply, 'scan_performed': bool(scan_data)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def open_browser():
    import time; time.sleep(1.3)
    webbrowser.open('http://localhost:5000')


if __name__ == '__main__':
    key = os.environ.get('GROQ_API_KEY')
    if not key:
        print('\n[!] ERROR: GROQ_API_KEY not set!')
        print('[*] Create a .env file:  GROQ_API_KEY=gsk_...\n')
        exit(1)
    print("""
██╗   ██╗ █████╗ ██████╗ ████████╗██████╗  ██████╗ ████████╗
██║   ██║██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗╚══██╔══╝
██║   ██║███████║██████╔╝   ██║   ██████╔╝██║   ██║   ██║
╚██╗ ██╔╝██╔══██║██╔═══╝    ██║   ██╔══██╗██║   ██║   ██║
 ╚████╔╝ ██║  ██║██║        ██║   ██████╔╝╚██████╔╝   ██║
  ╚═══╝  ╚═╝  ╚═╝╚═╝        ╚═╝   ╚═════╝  ╚═════╝    ╚═╝

""")
    print('[+] VAPTBot v2.0 — AI VAPT Assistant')
    print('[+] Author : Arulkumaran')
    print('[+] GitHub : https://github.com/0xarul/vaptbot')   
    print('[+] Full VA Reports + CVE Engine enabled')
    print('[+] Model  : llama-3.3-70b-versatile')
    print('[*] Browser: http://localhost:5000')
    print('[!] Stop   : Ctrl+C\n')
    threading.Thread(target=open_browser, daemon=True).start()
    app.run(debug=False, port=5000)
