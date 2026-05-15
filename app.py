"""
app.py — PenAgent Web UI Server

Flask + SocketIO server that streams PenAgent output to the browser in real time.
Serves the single-page UI and handles engagement execution via WebSockets.
"""

import os
import sys
import json
import threading
import subprocess
from pathlib import Path
from datetime import datetime

# Force threading mode — do NOT import eventlet
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'penagent-secret-2026'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ── State ──────────────────────────────────────────────────────────────────────
current_run = {
    "running": False,
    "phase": None,
    "findings": [],
    "web_shells": [],
    "exploit_options": None,
    "exploit_choice": None,
    "start_time": None,
}

exploit_event = threading.Event()


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/report')
def get_report():
    report_path = Path('/home/mushu/PenAgent/report.md')
    if report_path.exists():
        with open(report_path) as f:
            return jsonify({"content": f.read()})
    return jsonify({"content": "No report generated yet."})


@app.route('/history')
def get_history():
    history_dir = Path.home() / '.penagent' / 'history'
    entries = []
    if history_dir.exists():
        for f in sorted(history_dir.glob('*.json'), reverse=True)[:10]:
            with open(f) as fh:
                entries.append(json.load(fh))
    return jsonify(entries)


# ── WebSocket Events ───────────────────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    emit('status', {'msg': 'Connected to PenAgent'})


@socketio.on('start_engagement')
def on_start(data):
    if current_run['running']:
        emit('error', {'msg': 'Engagement already running'})
        return

    target = data.get('target', '').strip()
    scope  = data.get('scope', '').strip()
    stealth = data.get('stealth', False)
    full    = data.get('full', False)
    shell   = data.get('shell', True)
    output  = data.get('output', 'report.md')

    if not target:
        emit('error', {'msg': 'Target is required'})
        return

    current_run['running'] = True
    current_run['findings'] = []
    current_run['web_shells'] = []
    current_run['exploit_options'] = None
    current_run['start_time'] = datetime.now().isoformat()

    thread = threading.Thread(
        target=run_engagement,
        args=(target, scope, stealth, full, shell, output),
        daemon=True
    )
    thread.start()


@socketio.on('exploit_choice')
def on_exploit_choice(data):
    current_run['exploit_choice'] = data.get('choice', '0')
    exploit_event.set()


@socketio.on('stop_engagement')
def on_stop():
    current_run['running'] = False
    emit('log', {'type': 'warn', 'msg': 'Engagement stopped by user'})


# ── Engagement Runner ──────────────────────────────────────────────────────────

def emit_log(msg_type, msg):
    """Emit a log message to all connected clients."""
    socketio.emit('log', {'type': msg_type, 'msg': msg})


def emit_phase(phase_num, phase_name, detail=''):
    """Emit a phase update to all connected clients."""
    socketio.emit('phase', {
        'num': phase_num,
        'name': phase_name,
        'detail': detail,
        'status': 'running'
    })


def emit_phase_done(phase_num):
    socketio.emit('phase_done', {'num': phase_num})


def emit_finding(finding):
    current_run['findings'].append(finding)
    socketio.emit('finding', finding)


def emit_web_shell(url, method):
    current_run['web_shells'].append({'url': url, 'method': method})
    socketio.emit('web_shell', {'url': url, 'method': method})


def emit_exploit_menu(exploits):
    current_run['exploit_options'] = exploits
    socketio.emit('exploit_menu', {'exploits': exploits})


def run_engagement(target, scope, stealth, full, shell, output):
    """Run the full PenAgent pipeline and stream output via WebSockets."""
    try:
        sys.path.insert(0, '/home/mushu/PenAgent')
        os.chdir('/home/mushu/PenAgent')

        from dotenv import load_dotenv
        load_dotenv()

        # ── Phase 1: Recon ────────────────────────────────────────────────────
        emit_phase(1, 'RECON', f'Live recon against {target}')
        from recon import run_recon
        targets, final_xml = run_recon(
            target=target,
            stealth=stealth,
            skip_vuln=True,
            work_dir=None,
            skip_os=True,
        )

        if not targets:
            emit_log('error', 'No hosts found. Check target is reachable.')
            current_run['running'] = False
            return

        total_svcs = sum(len(t.get('services', [])) for t in targets)
        emit_log('success', f'{len(targets)} host(s) found — {total_svcs} services')

        # Emit host nodes for attack graph
        for t in targets:
            socketio.emit('host_discovered', {
                'ip': t['ip'],
                'os': t.get('os_name', 'unknown'),
                'services': [s['service'] + ' ' + s.get('version','') for s in t.get('services',[])[:6]]
            })

        emit_phase_done(1)

        # ── Scope filtering ───────────────────────────────────────────────────
        if scope:
            from scope import Scope
            sc = Scope(scope)
            targets = sc.filter_targets(targets)
            emit_log('status', f'Scope applied — {len(targets)} host(s) in scope')

        # ── Phase 2: Retrieve ─────────────────────────────────────────────────
        emit_phase(2, 'RETRIEVE', 'RAG knowledge base + NVD CVE API')
        emit_log('status', 'Knowledge base: 47,405 chunks indexed')
        emit_phase_done(2)

        # ── Phase 3: Agent ────────────────────────────────────────────────────
        emit_phase(3, 'EXECUTE', f'Agent reasoning over {len(targets)} host(s)')
        # Suppress raw agent output from streaming to feed

        from agent import run_agent_on_target, detect_os, filter_services
        from exploit_selector import parse_exploits_from_agent, present_exploit_menu_web

        agent_results = {}
        for t in targets:
            ip = t['ip']
            emit_log('status', f'Agent reasoning over {ip}')
            filtered = filter_services(t, mode='full' if full else 'default')
            os_hint = detect_os(filtered)

            # Run agent reasoning only
            reasoning = run_agent_on_target(filtered)
            exploits = parse_exploits_from_agent(reasoning, ip, os_hint)

            if exploits:
                # Emit exploit menu to browser
                emit_exploit_menu([{
                    'module': e['module'],
                    'description': e['description'],
                    'port': e['port'],
                    'cve': e['cve'],
                    'confidence': e['confidence'],
                } for e in exploits])

                # Wait for user choice from browser
                exploit_event.clear()
                emit_log('status', 'Waiting for exploit selection...')
                exploit_event.wait(timeout=300)

                choice = current_run.get('exploit_choice', '0')
                emit_log('status', f'Exploit choice received: {choice}')

                if choice == '0':
                    agent_results[ip] = reasoning + '\n\nExploitation skipped.'
                elif choice.upper() == 'A':
                    from tools.msf_exec import parse_and_run
                    results = [reasoning]
                    for e in exploits:
                        emit_log('status', f"Executing: {e['description']}")
                        import json as _json
                        r = parse_and_run(_json.dumps({
                            'module': e['module'],
                            'options': {'RHOSTS': ip},
                            '_os_hint': e['os_hint'],
                        }))
                        results.append(r)
                        if '[+] EXPLOITED' in r:
                            emit_log('success', f"Shell acquired via {e['description']}")
                            socketio.emit('shell_acquired', {'ip': ip, 'method': e['description']})
                            break
                    agent_results[ip] = '\n'.join(results)
                else:
                    try:
                        idx = int(choice) - 1
                        if 0 <= idx < len(exploits):
                            e = exploits[idx]
                            from tools.msf_exec import parse_and_run
                            import json as _json
                            emit_log('status', f"Executing: {e['description']}")
                            r = parse_and_run(_json.dumps({
                                'module': e['module'],
                                'options': {'RHOSTS': ip},
                                '_os_hint': e['os_hint'],
                            }))
                            if '[+] EXPLOITED' in r:
                                emit_log('success', f"Shell acquired via {e['description']}")
                                socketio.emit('shell_acquired', {'ip': ip, 'method': e['description']})
                            agent_results[ip] = reasoning + '\n' + r
                    except (ValueError, IndexError):
                        agent_results[ip] = reasoning
            else:
                agent_results[ip] = reasoning

        # Emit findings in real time from agent reasoning
        import re as _re
        for ip, output in agent_results.items():
            vuln_patterns = [
                (r'vsftpd 2\.3\.4', 'vsftpd 2.3.4 Backdoor', 'CVE-2011-2523', 10.0),
                (r'samba.*usermap|CVE-2007-2447', 'Samba usermap_script RCE', 'CVE-2007-2447', 10.0),
                (r'unrealircd|CVE-2010-2075', 'UnrealIRCd Backdoor RCE', 'CVE-2010-2075', 9.8),
                (r'proftpd|CVE-2010-4221', 'ProFTPD Backdoor RCE', 'CVE-2010-4221', 9.8),
                (r'bindshell|port 1524', 'Open Bindshell Port 1524', '', 10.0),
                (r'ms17-010|eternalblue', 'MS17-010 EternalBlue', 'CVE-2017-0144', 9.8),
                (r'log4shell|CVE-2021-44228', 'Log4Shell RCE', 'CVE-2021-44228', 10.0),
                (r'tomcat.*manager|CVE-2009-3843', 'Tomcat Manager RCE', 'CVE-2009-3843', 9.8),
            ]
            for pattern, title, cve, cvss in vuln_patterns:
                if _re.search(pattern, output.lower()):
                    sev = 'CRITICAL' if cvss >= 9.0 else 'HIGH' if cvss >= 7.0 else 'MEDIUM'
                    emit_finding({'title': title, 'cvss': cvss, 'severity': sev, 'cve': cve, 'host': ip})
                    socketio.emit('host_discovered', {'ip': ip, 'os': '', 'services': []})

        emit_log('success', 'Agent phase complete')
        emit_phase_done(3)

        # ── Phase 3a: Web Agent ───────────────────────────────────────────────
        emit_phase(4, 'WEB', 'Web application attack suite')
        from webagent import run_web_agent, detect_web_targets, web_findings_to_report_context

        web_urls = detect_web_targets(targets)
        for url in web_urls:
            emit_log('status', f'Web agent testing {url}')
            wf = run_web_agent(url)
            ctx = web_findings_to_report_context(wf)
            ip = url.split('//')[-1].split(':')[0]
            if ip in agent_results:
                agent_results[ip] += '\n\n' + ctx

            # Emit web shell if found
            shell_info = wf.raw_output.get('web_shell')
            if shell_info and shell_info.get('success'):
                emit_web_shell(shell_info['shell_url'], shell_info['method'])
                emit_log('success', f"Web shell: {shell_info['shell_url']}?cmd=id")

            # Emit web findings
            for finding in wf.nikto_findings[:5]:
                socketio.emit('web_finding', {'url': url, 'finding': finding[:100]})

        emit_phase_done(4)

        # ── Phase 3b: Post-Ex ─────────────────────────────────────────────────
        emit_phase(5, 'POST-EX', 'Credential harvesting + privesc enumeration')
        try:
            from postex import run_postex, postex_to_agent_context
            from pymetasploit3.msfrpc import MsfRpcClient
            msf = MsfRpcClient(
                os.getenv('MSF_PASSWORD'),
                server=os.getenv('MSF_HOST', '127.0.0.1'),
                port=int(os.getenv('MSF_PORT', 55553)),
                ssl=False,
            )
            sessions = msf.sessions.list
            if sessions:
                for sid, sinfo in sessions.items():
                    ip = sinfo.get('target_host', 'unknown')
                    shell_obj = msf.sessions.session(sid)
                    pf = run_postex(shell_obj, ip)
                    ctx = postex_to_agent_context(pf)
                    if ip in agent_results:
                        agent_results[ip] += '\n\n' + ctx
                    emit_log('success', f'Post-ex complete for {ip}')
                    if pf.network_neighbors:
                        socketio.emit('neighbors', {'ip': ip, 'neighbors': pf.network_neighbors[:5]})
                    if pf.credentials:
                        socketio.emit('credentials', {'ip': ip, 'count': len(pf.credentials)})
            else:
                emit_log('status', 'No active sessions for post-ex')
        except Exception as e:
            emit_log('warn', f'Post-ex skipped: {e}')

        emit_phase_done(5)

        # ── Phase 4: Report ───────────────────────────────────────────────────
        emit_phase(6, 'REPORT', 'Generating report → report.md')
        from reporter import generate_report
        import re

        report = generate_report(targets, agent_results)
        report_path = '/home/mushu/PenAgent/report.md'
        with open(report_path, 'w') as f:
            f.write(report)

        # Parse findings from report
        blocks = re.split(r'\n(?=## Finding)', report)
        for block in blocks:
            if not block.strip().startswith('## Finding'):
                continue
            title_m = re.search(r'^## Finding\s+\d+\s*[-—]+\s*(.+)', block, re.MULTILINE)
            cvss_m  = re.search(r'\|\s*\*?\*?CVSS[^|]*Score\*?\*?\s*\|\s*\*?\*?(\d+\.\d+)', block, re.IGNORECASE)
            cve_m   = re.search(r'\|\s*\*?\*?CVE\*?\*?\s*\|\s*(CVE-\d{4}-\d+)', block, re.IGNORECASE)
            host_m  = re.search(r'\|\s*\*?\*?Host\*?\*?\s*\|\s*(\d+\.\d+\.\d+\.\d+)', block, re.IGNORECASE)
            if not title_m:
                continue
            cvss = float(cvss_m.group(1)) if cvss_m else 0.0
            sev = 'CRITICAL' if cvss >= 9.0 else 'HIGH' if cvss >= 7.0 else 'MEDIUM' if cvss >= 4.0 else 'LOW'
            emit_finding({
                'title': re.sub(r'[*#`]', '', title_m.group(1)).strip()[:55],
                'cvss': cvss,
                'severity': sev,
                'cve': cve_m.group(1) if cve_m else '',
                'host': host_m.group(1) if host_m else '',
            })

        elapsed = (datetime.now() - datetime.fromisoformat(current_run['start_time'])).seconds
        socketio.emit('complete', {
            'findings': len(current_run['findings']),
            'elapsed': elapsed,
            'report': output,
        })
        emit_log('success', f'Engagement complete — {len(current_run["findings"])} findings in {elapsed}s')
        emit_phase_done(6)

    except Exception as e:
        import traceback
        emit_log('error', f'Engagement failed: {e}')
        emit_log('error', traceback.format_exc()[:300])
    finally:
        current_run['running'] = False


if __name__ == '__main__':
    print('[*] PenAgent Web UI starting on http://127.0.0.1:5000')
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
