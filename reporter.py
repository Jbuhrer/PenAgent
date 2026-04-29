import anthropic, os
from dotenv import load_dotenv
load_dotenv()

def generate_report(targets: list, agent_output: str) -> str:
    client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))
    prompt = f"""You are writing a professional penetration test report.

Targets assessed:
{targets}

Agent findings:
{agent_output}

Write a report with these sections:
1. Executive Summary
2. Scope and Methodology
3. Findings (for each finding include:
   - Title
   - CVSS score and vector
   - Description
   - Evidence
   - ### Quick Access Commands
     Include the exact terminal commands someone would run to exploit this vulnerability manually.
     Use real IP addresses from the target profile above.
     Examples:
     - nc commands
     - metasploit use/set/run commands
     - mysql/psql login commands
     - netcat listeners
     - any other direct exploitation commands
   - Remediation)
4. Quick Reference — at the very end, a single consolidated table of ALL quick access commands from every finding in one place, organized by port number

Be specific. Use the actual IP addresses, ports, service versions, and exploit outcomes from the findings above.
"""
    msg = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=8000,
        messages=[{"role": "user", "content": prompt}]
    )
    return msg.content[0].text
