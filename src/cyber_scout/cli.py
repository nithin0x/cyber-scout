from __future__ import annotations

from markdown_pdf import MarkdownPdf, Section
from .db import init_db, insert_run, insert_findings
from .parser import parse_report, format_soc_action_list
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from textwrap import dedent
from typing import Iterable, Any

from crewai.llms.base_llm import BaseLLM
from dotenv import load_dotenv
from pydantic import PrivateAttr


DEFAULT_MODEL = "digitalocean-agent"
MIN_SUPPORTED_PYTHON = (3, 10)
MAX_SUPPORTED_PYTHON = (3, 15)


@dataclass(frozen=True)
class SearchItem:
    title: str
    url: str
    published_date: str
    summary: str


class DigitalOceanLLM(BaseLLM):
    """CrewAI-compatible LLM adapter backed by DigitalOcean AI Agents."""

    llm_type: str = "digitalocean_agent"
    _client: object = PrivateAttr()

    def __init__(self, agent_url: str, api_key: str, temperature: float = 0) -> None:
        from langchain_openai import ChatOpenAI

        # DigitalOcean Agents require /api/v1 prefix for OpenAI compatibility
        base_url = agent_url.rstrip("/")
        if not base_url.endswith("/api/v1"):
            if base_url.endswith("/v1"):
                base_url = base_url.replace("/v1", "/api/v1")
            else:
                base_url = f"{base_url}/api/v1"

        super().__init__(model="digitalocean-agent", api_key=api_key, provider="openai", temperature=temperature)
        self._client = ChatOpenAI(
            base_url=base_url,
            api_key=api_key,
            temperature=temperature,
            model="digitalocean-agent"
        )

    def call(
        self,
        messages: str | list[dict[str, object]],
        tools: list[dict[str, object]] | None = None,
        callbacks: list[object] | None = None,
        available_functions: dict[str, object] | None = None,
        from_task: object | None = None,
        from_agent: object | None = None,
        response_model: type[object] | None = None,
    ) -> str | object:
        del tools, callbacks, available_functions, from_task, from_agent, response_model

        from langchain_core.messages import AIMessage, HumanMessage

        if isinstance(messages, str):
            langchain_messages = [HumanMessage(content=messages)]
        else:
            langchain_messages = []
            for msg in messages:
                if isinstance(msg, dict):
                    role = str(msg.get("role", "user"))
                    content = msg.get("content", "")
                else:
                    role = str(getattr(msg, "role", "user"))
                    content = getattr(msg, "content", "")
                content_text = str(content)
                
                # DigitalOcean Agents don't allow 'system' messages.
                # We convert them to 'human' messages to preserve context.
                if role == "system":
                    langchain_messages.append(HumanMessage(content=f"[Instruction]: {content_text}"))
                elif role == "assistant":
                    langchain_messages.append(AIMessage(content=content_text))
                else:
                    langchain_messages.append(HumanMessage(content=content_text))

        response = self._client.invoke(langchain_messages)
        if isinstance(response.content, str):
            return response.content
        return str(response.content)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a cybersecurity threat intelligence report with CrewAI, DigitalOcean AI Agents, and Exa."
    )
    parser.add_argument(
        "--threat-query",
        default="latest cybersecurity threats malware ransomware active campaigns",
        help="Search query used for current threat intelligence.",
    )
    parser.add_argument(
        "--cve-query",
        default="latest CVEs exploited vulnerabilities security advisories",
        help="Search query used for vulnerability intelligence.",
    )
    parser.add_argument(
        "--results",
        type=positive_int,
        default=5,
        help="Number of search results to fetch for each research query.",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help="DigitalOcean Agent identifier.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("threat_intelligence_report.md"),
        help="Markdown file to write.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Write a sample report without calling DigitalOcean or Exa.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose CrewAI logging.",
    )
    parser.add_argument(
        "--send-slack",
        action="store_true",
        help="Send the generated report to Slack via incoming webhook.",
    )
    parser.add_argument(
        "--slack-webhook-url",
        default=None,
        help="Slack incoming webhook URL. Overrides SLACK_WEBHOOK_URL from .env.",
    )

    parser.add_argument(
        "--schedule",
        default=None,
        help="Schedule time to run daily (e.g. '08:00'). Loops indefinitely.",
    )
    parser.add_argument(
        "--export-json",
        action="store_true",
        help="Export JSON of the parsed report.",
    )
    parser.add_argument(
        "--export-pdf",
        action="store_true",
        help="Export PDF of the generated report.",
    )
    return parser.parse_args(argv)


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("--results must be greater than 0.")
    return parsed


def ensure_supported_python() -> None:
    current = sys.version_info[:2]
    if current < MIN_SUPPORTED_PYTHON or current >= MAX_SUPPORTED_PYTHON:
        raise RuntimeError(
            f"Unsupported Python {current[0]}.{current[1]}. "
            "Use Python 3.10, 3.11, 3.12, or 3.13 for this project."
        )


def load_environment() -> None:
    load_dotenv()


def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(
            f"{name} is not set. Create a .env file from .env.example or export {name} in your shell."
        )
    return value


def item_to_markdown(item: SearchItem) -> str:
    return dedent(
        f"""
        - Title: {item.title}
          URL: {item.url}
          Published: {item.published_date}
          Summary: {item.summary}
        """
    ).strip()


def items_to_markdown(items: Iterable[SearchItem]) -> str:
    return "\n".join(item_to_markdown(item) for item in items)


def fetch_exa_results(query: str, limit: int, api_key: str) -> list[SearchItem]:
    from exa_py import Exa

    client = Exa(api_key=api_key)
    try:
        result = client.search_and_contents(query, num_results=limit, summary=True)
    except TypeError:
        result = client.search_and_contents(query, summary=True)

    items: list[SearchItem] = []
    for raw_item in getattr(result, "results", [])[:limit]:
        items.append(
            SearchItem(
                title=getattr(raw_item, "title", None) or "No title",
                url=getattr(raw_item, "url", None) or "#",
                published_date=getattr(raw_item, "published_date", None) or "Unknown",
                summary=getattr(raw_item, "summary", None) or "No summary returned.",
            )
        )
    return items


def build_crew(threats: list[SearchItem], cves: list[SearchItem], model: str, verbose: bool):
    from crewai import Agent, Crew, Process, Task

    agent_url = require_env("DIGITALOCEAN_AGENT_URL")
    api_key = require_env("DIGITALOCEAN_TOKEN")
    
    llm = DigitalOceanLLM(agent_url=agent_url, api_key=api_key, temperature=0)
    verbose_level = 2 if verbose else False
    threat_context = items_to_markdown(threats) or "No threat intelligence results were returned."
    cve_context = items_to_markdown(cves) or "No vulnerability results were returned."

    threat_analyst = Agent(
        role="Cybersecurity Threat Intelligence Analyst",
        goal="Analyze recent cybersecurity threats and identify the most relevant patterns.",
        backstory=(
            "You track emerging threats, malware campaigns, ransomware operations, "
            "security incidents, and attacker tradecraft."
        ),
        verbose=verbose,
        allow_delegation=False,
        llm=llm,
        max_iter=5,
        memory=False,
    )
    vulnerability_researcher = Agent(
        role="Vulnerability & Exploit Researcher",
        goal="Analyze software vulnerabilities, exploit chains, and potential for lateral movement.",
        backstory=(
            "You are a deep-dive vulnerability researcher. You analyze the root cause of "
            "vulnerabilities (memory corruption, logic flaws, etc.) and the mechanics of "
            "exploit chains. You provide EPSS scores and CVSS 4.0 analysis."
        ),
        verbose=verbose,
        allow_delegation=False,
        llm=llm,
        max_iter=5,
        memory=False,
    )
    malware_researcher = Agent(
        role="Specialized Malware & Ransomware Analyst",
        goal="Deconstruct malware families, persistence mechanisms, and command-and-control (C2) tradecraft.",
        backstory=(
            "You are an expert in reverse engineering and malware behavior analysis. You "
            "identify specific persistence techniques (Registry, Scheduled Tasks, WMI), "
            "C2 frameworks (Cobalt Strike, Sliver, Havoc), and encryption/obfuscation methods."
        ),
        verbose=verbose,
        allow_delegation=False,
        llm=llm,
        max_iter=5,
        memory=False,
    )
    incident_response_advisor = Agent(
        role="Lead Detection Engineer & Threat Hunter",
        goal="Develop granular, high-fidelity detection logic and hardened mitigation playbooks.",
        backstory=(
            "You are a specialist in Detection Engineering. You develop specific, "
            "code-level SIGMA rules, YARA signatures, and KQL/Splunk hunting queries. "
            "You map every finding to specific MITRE ATT&CK Techniques and Sub-techniques."
        ),
        verbose=verbose,
        allow_delegation=False,
        llm=llm,
        max_iter=5,
        memory=False,
    )
    cybersecurity_writer = Agent(
        role="Senior Cybersecurity Intelligence Architect",
        goal="Architect a multi-layered, exhaustive cybersecurity intelligence report with actionable SOC focus.",
        backstory=(
            "You produce the 'Gold Standard' of intelligence reports. Your work is highly structured, "
            "combining high-level executive summaries with granular technical details, "
            "mitigation playbooks, and ready-to-deploy detection signatures."
        ),
        verbose=verbose,
        allow_delegation=False,
        llm=llm,
        max_iter=5,
        memory=False,
    )

    threat_analysis_task = Task(
        description=(
            "Analyze the following threat intelligence results. Identify specific TTPs, "
            "targeted industries, and the operational maturity of the threat actors.\n\n"
            f"{threat_context}"
        ),
        expected_output="An analysis of active threats, actor profiles, and high-level patterns.",
        agent=threat_analyst,
    )
    vulnerability_research_task = Task(
        description=(
            "Examine the vulnerability intelligence. Analyze the root cause of flaws, "
            "exploit chain potential, and lateral movement paths.\n\n"
            f"{cve_context}"
        ),
        expected_output="Technical breakdown of vulnerabilities and exploit potential.",
        agent=vulnerability_researcher,
    )
    malware_analysis_task = Task(
        description=(
            "Analyze the identified threats specifically for malware behavior. "
            "Identify persistence mechanisms, C2 communication patterns, and "
            "evasion techniques used in recent campaigns."
        ),
        expected_output="Granular malware behavior analysis and C2 tradecraft details.",
        agent=malware_researcher,
        context=[threat_analysis_task],
    )
    incident_response_task = Task(
        description=(
            "Develop a comprehensive defensive strategy. This MUST include: "
            "1) Hardened Mitigation (GPOs, firewall rules, compensating controls) and "
            "2) High-Fidelity Detection (specific Event IDs, SIGMA rules, YARA strings, "
            "and hunting queries mapped to MITRE ATT&CK)."
        ),
        expected_output="Ready-to-deploy mitigation playbooks and detection signatures.",
        agent=incident_response_advisor,
        context=[threat_analysis_task, vulnerability_research_task, malware_analysis_task],
    )
    write_threat_report_task = Task(
        description=(
            "Consolidate all findings into an exhaustive intelligence report. "
            "The report MUST include the following specific sections:\n"
            "- Executive Summary\n"
            "- Top Threats (detailed list of identified threats)\n"
            "- Latest Vulnerabilities (detailed list of identified CVEs)\n"
            "- Recommended Actions\n"
            "- Prioritized Defensive Actions (mapped to threats and vulnerabilities)\n"
            "- Cited Sources\n"
            "- Prioritized SOC Action List (Each entry MUST include: Threat/CVE name, Description, "
            "Mitigation steps, Detection steps, and Sources).\n\n"
            "Maintain technical granularity throughout, including malware mechanics and vulnerability root-cause where applicable."
        ),
        expected_output="A structured, exhaustive Markdown report following the requested section headers.",
        agent=cybersecurity_writer,
        context=[threat_analysis_task, vulnerability_research_task, malware_analysis_task, incident_response_task],
    )

    return Crew(
        agents=[
            threat_analyst,
            vulnerability_researcher,
            malware_researcher,
            incident_response_advisor,
            cybersecurity_writer,
        ],
        tasks=[
            threat_analysis_task,
            vulnerability_research_task,
            malware_analysis_task,
            incident_response_task,
            write_threat_report_task,
        ],
        verbose=verbose_level,
        process=Process.sequential,
    )


def extract_final_output(result: object) -> str:
    if isinstance(result, dict):
        final_output = result.get("final_output") or result.get("output")
        if final_output:
            return str(final_output)
    final_output = getattr(result, "final_output", None) or getattr(result, "raw", None)
    return str(final_output or result)


def write_report(output: Path, content: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content.strip() + "\n", encoding="utf-8")


def send_report_to_slack(
    webhook_url: str | None, 
    output: Path, 
    report_content: str, 
    parsed_data: dict[str, Any],
    is_critical: bool = False
) -> None:
    """Sends a comprehensive report summary to Slack using Block Kit."""
    today = date.today().isoformat()
    priority_emoji = ":red_circle:" if is_critical else ":large_green_circle:"
    status_text = "CRITICAL ALERT" if is_critical else "Daily Intelligence"
    
    sections = parsed_data.get("sections", {})
    
    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"Cyber Scout: {status_text} | {today}", "emoji": True}
        }
    ]

    # Helper to add section
    def add_section(title: str, content: str):
        if not content:
            return
        # Clean markdown headers from content
        clean_content = re.sub(r"^#+ ", "", content, flags=re.MULTILINE)
        
        # Slack block text limit is 3000 chars
        if len(clean_content) > 2900:
            clean_content = clean_content[:2897] + "..."
            
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{title}*\n{clean_content}"}
        })
        blocks.append({"type": "divider"})

    # 1. Executive Summary
    summary = sections.get("Executive Summary")
    if not summary and "Executive Summary" in report_content:
        # Fallback if parser missed it
        summary_raw = report_content.split("Executive Summary")[1]
        summary = re.split(r"\n##\s", summary_raw, maxsplit=1)[0].strip()
    
    add_section("Executive Summary", summary or "Threat intelligence scan completed.")

    # 2. Statistics
    findings = parsed_data.get("findings", [])
    threat_count = len([f for f in findings if f.get("type") == "threat"])
    cve_count = len([f for f in findings if f.get("type") == "cve"])
    critical_count = len([f for f in findings if f.get("severity") == "Critical"])

    stats_line = (
        f"- Total Findings: *{len(findings)}*\n"
        f"- Critical Risks: *{critical_count}*\n"
        f"- Active Threats: *{threat_count}*\n"
        f"- CVEs: *{cve_count}*"
    )
    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": f"*Key Metrics*\n{stats_line}"}
    })
    blocks.append({"type": "divider"})

    # 3. Top Threats
    threats = sections.get("Top Threats", sections.get("Sample Threats"))
    add_section("Top Threats", threats)

    # 4. Latest Vulnerabilities
    vulnerabilities = sections.get("Latest Vulnerabilities", sections.get("Sample Vulnerabilities"))
    add_section("Latest Vulnerabilities", vulnerabilities)

    # 5. Recommended Actions
    actions = sections.get("Recommended Actions")
    add_section("Recommended Actions", actions)

    # 6. Prioritized Defensive Actions
    defensive = sections.get("Prioritized Defensive Actions")
    add_section("Prioritized Defensive Actions", defensive)

    # 7. Cited Sources
    sources = sections.get("Cited Sources")
    add_section("Cited Sources", sources)

    # 8. SOC Action List
    soc_text = sections.get("Prioritized SOC Action List")
    if not soc_text:
        # Generate it if not in report
        soc_text = format_soc_action_list(parsed_data)
        soc_text = soc_text.replace("## Prioritized SOC Action List", "").strip()
    
    add_section("Prioritized SOC Action List (24h Review)", soc_text)

    # Final construction
    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": f":page_facing_up: Full report attached: `{output.name}` | Detailed PDF below"}
        ]
    })

    payload = {
        "text": f"Cyber Scout Update: {status_text}",
        "blocks": blocks
    }

    # 6. Send
    if webhook_url:
        _post_to_slack_url(webhook_url, payload)

    bot_token = os.getenv("SLACK_BOT_TOKEN")
    channel_id = os.getenv("SLACK_CHANNEL_ID")
    pdf_path = output.with_suffix('.pdf')
    
    if bot_token and channel_id and pdf_path.exists():
        try:
            print(f"Uploading PDF to Slack channel {channel_id}...")
            _upload_file_to_slack(bot_token, channel_id, pdf_path, f"Detailed Report: {output.name}")
        except Exception as e:
            print(f"Failed to upload PDF to Slack: {e}")


def _post_to_slack_url(url: str, payload: dict[str, Any]) -> None:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        status = getattr(response, "status", 200)
        if status >= 300:
            body = response.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Slack API returned HTTP {status}: {body}")

def _upload_file_to_slack(token: str, channel: str, file_path: Path, title: str) -> None:
    """Uploads a file using the modern Slack files.upload v2 flow."""
    import urllib.parse
    file_size = file_path.stat().st_size
    filename = file_path.name

    # Step 1: Get upload URL (Note: URL is capitalized)
    get_url = "https://slack.com/api/files.getUploadURLExternal"
    params1 = urllib.parse.urlencode({
        "filename": filename,
        "length": file_size
    }).encode("utf-8")
    
    req1 = urllib.request.Request(
        get_url, 
        data=params1,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded"
        },
        method="POST"
    )
    
    with urllib.request.urlopen(req1) as resp:
        res1 = json.loads(resp.read().decode('utf-8'))
        if not res1.get("ok"):
            raise RuntimeError(f"Slack getUploadURLExternal failed: {res1.get('error')}")
        
        upload_url = res1["upload_url"]
        file_id = res1["file_id"]

    # Step 2: Upload file bytes to the provided URL
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    req2 = urllib.request.Request(
        upload_url,
        data=file_data,
        method="POST"
    )
    with urllib.request.urlopen(req2) as resp:
        if resp.getcode() >= 300:
            raise RuntimeError(f"Slack file byte upload failed with status {resp.getcode()}")

    # Step 3: Complete the upload
    complete_url = "https://slack.com/api/files.completeUploadExternal"
    # The 'files' parameter must be a JSON-encoded string
    files_payload = [{"id": file_id, "title": title}]
    params3 = urllib.parse.urlencode({
        "files": json.dumps(files_payload),
        "channel_id": channel
    }).encode("utf-8")
    
    req3 = urllib.request.Request(
        complete_url,
        data=params3,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded"
        },
        method="POST"
    )
    with urllib.request.urlopen(req3) as resp:
        res3 = json.loads(resp.read().decode('utf-8'))
        if not res3.get("ok"):
            raise RuntimeError(f"Slack completeUploadExternal failed: {res3.get('error')}")




def dry_run_report() -> str:
    today = date.today().isoformat()
    return f"""# Cybersecurity Threat Intelligence Report

Date: {today}

## Executive Summary
This is a dry-run intelligence report. It demonstrates the structural output of the Cyber Scout agentic pipeline without consuming live API tokens from DigitalOcean or Exa. The system is currently configured and ready for live threat analysis.

## Current Threats
- **Ransomware campaigns** targeting exposed remote access services.
- **Credential phishing** against cloud identity providers.

## Latest Vulnerabilities
- **Internet-facing appliances** with recently disclosed remote code execution flaws.
- **Browser and endpoint vulnerabilities** requiring normal patch cadence review.

## Mitigation Strategies
- Implement multi-factor authentication (MFA) across all external-facing services.
- Apply emergency patches for perimeter security appliances immediately upon release.
- Segment network traffic to isolate critical assets from general office environments.

## Detection Guidance
- Monitor for unusual login patterns from geographically impossible locations.
- Implement SIGMA rules to detect common ransomware persistence mechanisms.
- Watch for spikes in DNS queries to newly registered or suspicious domains.

## Recommended Actions
- Confirm API keys in `.env` before live execution.
- Run the live command after reviewing query terms and output path.
"""


def run_live(args: argparse.Namespace) -> tuple[str, str]:
    # Validate DigitalOcean env vars
    require_env("DIGITALOCEAN_AGENT_URL")
    require_env("DIGITALOCEAN_TOKEN")
    
    exa_api_key = require_env("EXA_API_KEY")

    threats = fetch_exa_results(args.threat_query, args.results, exa_api_key)
    cves = fetch_exa_results(args.cve_query, args.results, exa_api_key)
    
    # Generate sources markdown for the appendix
    sources_md = "## Technical Appendix: Research Sources\n\n"
    sources_md += "### Threat Intelligence Sources\n"
    sources_md += items_to_markdown(threats) or "No results found."
    sources_md += "\n\n### Vulnerability Intelligence Sources\n"
    sources_md += items_to_markdown(cves) or "No results found."

    crew = build_crew(threats, cves, args.model, args.verbose)
    report = extract_final_output(crew.kickoff())
    
    return report, sources_md


def process_run(args: argparse.Namespace) -> None:
    if args.dry_run:
        report = dry_run_report()
        sources_md = ""
    else:
        report, sources_md = run_live(args)
        
    parsed = parse_report(report)
    soc_actions = format_soc_action_list(parsed)
    
    # Combine everything for the final detailed report
    full_report_md = report + "\n\n" + soc_actions
    if sources_md:
        full_report_md += "\n\n" + sources_md
    
    write_report(args.output, full_report_md)
    print(f"Wrote {args.output}")
    
    if args.export_json:
        json_path = args.output.with_suffix('.json')
        json_path.write_text(json.dumps(parsed, indent=2))
        print(f"Wrote JSON to {json_path}")
        
    if args.export_pdf:
        pdf_path = args.output.with_suffix('.pdf')
        pdf = MarkdownPdf(toc_level=2)
        pdf.add_section(Section(full_report_md))
        pdf.save(str(pdf_path))
        print(f"Wrote PDF to {pdf_path}")

    # Slack sending
    slack_status = "Skipped"
    is_critical = parsed.get("critical_found", False)
    if args.send_slack or is_critical:
        webhook_url = args.slack_webhook_url or os.getenv("SLACK_WEBHOOK_URL")
        # We always attempt PDF generation if Slack is enabled
        args.export_pdf = True 
        
        if webhook_url or os.getenv("SLACK_BOT_TOKEN"):
            try:
                # Need to re-generate PDF if it wasn't requested but we are sending to Slack
                if not (args.output.with_suffix('.pdf')).exists():
                    pdf_path = args.output.with_suffix('.pdf')
                    pdf = MarkdownPdf(toc_level=2)
                    pdf.add_section(Section(full_report_md))
                    pdf.save(str(pdf_path))
                
                send_report_to_slack(webhook_url, args.output, full_report_md, parsed, is_critical)
                print("Sent report to Slack")
                slack_status = "Sent"
            except Exception as e:
                print(f"Failed to send to slack: {e}")
                slack_status = f"Error: {e}"
        else:
            slack_status = "Error: No URL/Token"
            if is_critical:
                print("Critical vulnerabilities found, but no SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN provided to alert.")


    # DB persistence
    run_id = insert_run(
        timestamp=datetime.now().isoformat(),
        threat_query=args.threat_query,
        cve_query=args.cve_query,
        model=args.model,
        output_path=str(args.output),
        summary="Automated run",
        top_risks=json.dumps(parsed.get("top_risks", [])),
        slack_status=slack_status
    )
    insert_findings(run_id, parsed.get("findings", []))

def main(argv: list[str] | None = None) -> int:
    try:
        ensure_supported_python()
        args = parse_args(argv)
        load_environment()
        init_db()

        # schedule_time = args.schedule or os.getenv("SCHEDULE_TIME")
        # if schedule_time:
        #     print(f"Scheduling run daily at {schedule_time}")
        #     schedule.every().day.at(schedule_time).do(process_run, args)
        #     
        #     # optionally, run once initially
        #     if args.dry_run:
        #          process_run(args)
        #          
        #     while True:
        #         schedule.run_pending()
        #         time.sleep(60)
        # else:
        #     process_run(args)
        
        process_run(args)
            
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    main()
    main()
