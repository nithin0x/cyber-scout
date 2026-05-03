# Cyber Scout: AI-Powered Cybersecurity Threat Intelligence

Cyber Scout is an automated threat intelligence pipeline that leverages multi-agent AI (CrewAI) and DigitalOcean AI Agents to hunt, analyze, and report on emerging cyber threats and vulnerabilities.

![Slack Output](evidence/04_results/01_slack_formatted_output.png)
*Figure: Automated Slack report with executive summary, top threats, and SOC actions.*

## Key Features

- Multi-Agent Analysis: Dedicated AI agents for threat analysis, vulnerability research, and incident response.
- Automated Scheduling: Daily intelligence reports via cron or internal scheduler.
- Web Dashboard: Visual analytics, trend tracking, and historical report management.
- Multi-Format Export: Generates professional reports in Markdown, JSON, and PDF.
- Slack Integration: Real-time alerts and full report uploads to Slack channels.
- IOC Extraction: Automatically extracts and scores Domains, IPs, and CVEs.

---

## Prerequisites and Integration Setup

To use Cyber Scout, you need to set up the following external services:

### 1. DigitalOcean AI Agent
Cyber Scout uses DigitalOcean's Agent Platform for high-performance AI orchestration.
- Setup Guide: [How to Create Agents on DigitalOcean AI Platform](https://docs.digitalocean.com/products/gen-ai-platform/how-to/create-agents/)
- What you need: DIGITALOCEAN_TOKEN and the DIGITALOCEAN_AGENT_URL.

### 2. Exa AI (Search Engine)
Exa provides the real-time web intelligence data.
- Website: [Exa.ai](https://exa.ai)
- What you need: EXA_API_KEY.

### 3. Slack Integration
- Incoming Webhooks: Required for formatted text reports.
  - Setup Guide: [Sending messages using Incoming Webhooks](https://api.slack.com/messaging/webhooks)
  - What you need: SLACK_WEBHOOK_URL.
- Bot Token: Required for uploading PDF reports to Slack.
  - Setup Guide: [Uploading files to Slack](https://api.slack.com/messaging/files/uploading)
  - Required Scopes: files:write, chat:write.
  - What you need: SLACK_BOT_TOKEN (starts with xoxb-) and SLACK_CHANNEL_ID.

---

## Workflow Showcase

Cyber Scout follows a structured pipeline from setup to delivery.

### Phase 1: Environment and Setup
The run_daily_report.sh script automates the environment preparation on any Linux distribution.
| Step 1.1: Automated Setup | Step 1.2: API Configuration |
|:---:|:---:|
| ![Setup](evidence/01_setup/01_env_setup.png) | ![Config](evidence/01_setup/02_env_config.png) |
| *Running --setup to prepare Python and venv.* | *Configuring the .env file with your API keys.* |

### Phase 2: Intelligence Gathering (CLI)
The CLI orchestrates the AI agents to hunt for threats and vulnerabilities.
| Step 2.1: CLI Execution | Step 2.2: Local Results |
|:---:|:---:|
| ![CLI](evidence/02_cli/01_dry_run_execution.png) | ![Reports](evidence/02_cli/06_reports_directory_structure.png) |
| *The AI agent pipeline in action.* | *Reports organized by timestamp in /reports.* |

### Phase 3: Monitoring and Analytics (Dashboard)
Use the web dashboard to track trends and deep-dive into historical intelligence.
| Step 3.1: Trend Analytics | Step 3.2: Detailed Report View |
|:---:|:---:|
| ![Dashboard](evidence/03_dashboard/03_main_analytics_view.png) | ![Report](evidence/03_dashboard/05_individual_report_view.png) |
| *Visualizing risk and recurring threats.* | *Inspecting individual run findings and SOC actions.* |

### Phase 4: Automation and Delivery
Set it and forget it with cron-based scheduling and instant Slack notifications.
| Step 4.1: Cron Scheduling | Step 4.2: Slack Delivery |
|:---:|:---:|
| ![Cron](evidence/05_automation/02_cron_scheduling_confirmation.png) | ![Slack](evidence/04_results/01_slack_formatted_output.png) |
| *Automating daily runs via crontab.* | *Real-time intelligence delivered to your team.* |

---

## Installation

### Quick Start (Linux)
```bash
# 1. Setup the environment
./run_daily_report.sh --setup

# 2. Schedule daily reports (e.g., at 08:00 AM)
./run_daily_report.sh --schedule 08:00

# 3. Run manually
./run_daily_report.sh --run
```

---

## Usage

### Running the CLI
```bash
cyber-scout --send-slack --export-pdf --export-json
```

### Running the Dashboard
```bash
cyber-scout-dashboard
```
*Access at http://127.0.0.1:8501 (Default Login: admin / scout123)*

---

## How it Works
1. Intelligence Retrieval: Exa fetches live threat data.
2. AI Analysis: Multi-agent CrewAI pipeline (Analyst, Researcher, Advisor).
3. Persistence: Saves to SQLite and local files.
4. Delivery: Automated Slack alerts and PDF uploads.

---

## Python Compatibility
Supports Python 3.10, 3.11, 3.12, 3.13.

---

## License
MIT License. See [LICENSE](LICENSE) for details.
