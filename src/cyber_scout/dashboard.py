from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, Response, redirect, render_template_string, request, send_file, url_for, jsonify, session
from werkzeug.security import check_password_hash
from cyber_scout.db import get_recent_runs, get_run_by_id, get_trends, get_user_by_username, init_db


REPORTS_DIR = Path("reports")
DEFAULT_MODEL = "digitalocean-agent"

LOGIN_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Cyber Scout Login</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --accent: #1f6feb;
      --danger: #da3633;
    }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; 
      background: var(--bg);
      color: var(--text);
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
    }
    .login-card { 
      background: var(--card-bg); 
      border: 1px solid var(--border); 
      border-radius: 6px; 
      padding: 2rem; 
      width: 100%; 
      max-width: 320px; 
      text-align: center;
    }
    h1 { color: #f0f6fc; margin-bottom: 1.5rem; font-size: 1.5rem; }
    input[type=text], input[type=password] { 
      width: 100%; padding: 0.75rem; background: var(--bg); border: 1px solid var(--border); 
      border-radius: 6px; color: var(--text); box-sizing: border-box; margin-bottom: 1rem;
    }
    button { 
      background: #238636; color: white; border: 1px solid rgba(240,246,252,0.1); 
      padding: 0.75rem; border-radius: 6px; font-weight: 600; cursor: pointer; width: 100%;
    }
    .error { color: var(--danger); font-size: 0.9rem; margin-bottom: 1rem; }
  </style>
</head>
<body>
  <div class="login-card">
    <h1>Cyber Scout</h1>
    {% if error %}
      <div class="error">{{ error }}</div>
    {% endif %}
    <form method="post">
      <input type="text" name="username" placeholder="Username" required autofocus>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Sign In</button>
    </form>
  </div>
</body>
</html>
"""

PAGE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Cyber Scout Dashboard</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-dim: #8b949e;
      --primary: #238636;
      --primary-hover: #2ea043;
      --accent: #1f6feb;
      --danger: #da3633;
      --success: #3fb950;
    }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; 
      background: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 0;
      line-height: 1.5;
    }
    .container { max-width: 1200px; margin: 0 auto; padding: 2rem 1rem; }
    h1, h2, h3 { color: #f0f6fc; margin-bottom: 1rem; }
    .header { border-bottom: 1px solid var(--border); padding-bottom: 1rem; margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: center; }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 6px; padding: 1.5rem; margin-bottom: 1.5rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .stat-card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; text-align: center; }
    .stat-value { font-size: 2rem; font-weight: bold; color: var(--accent); }
    .stat-label { font-size: 0.875rem; color: var(--text-dim); text-transform: uppercase; }
    
    .form-group { margin-bottom: 1rem; }
    label { display: block; margin-bottom: 0.5rem; font-weight: 600; font-size: 0.9rem; }
    input[type=text], input[type=number], select { 
      width: 100%; padding: 0.5rem; background: var(--bg); border: 1px solid var(--border); 
      border-radius: 6px; color: var(--text); box-sizing: border-box;
    }
    input:focus { border-color: var(--accent); outline: none; box-shadow: 0 0 0 3px rgba(31, 111, 235, 0.3); }
    
    .checkbox-group { display: flex; gap: 1.5rem; margin-top: 1rem; flex-wrap: wrap; }
    .checkbox-item { display: flex; align-items: center; gap: 0.5rem; font-size: 0.9rem; cursor: pointer; }
    
    button { 
      background: var(--primary); color: white; border: 1px solid rgba(240,246,252,0.1); 
      padding: 0.75rem 1.5rem; border-radius: 6px; font-weight: 600; cursor: pointer; 
      transition: background 0.2s; width: 100%;
    }
    button:hover { background: var(--primary-hover); }
    
    .badge { padding: 0.2rem 0.5rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }
    .badge-high { background: rgba(218, 54, 51, 0.2); color: #f85149; border: 1px solid rgba(218, 54, 51, 0.4); }
    .badge-med { background: rgba(210, 153, 34, 0.2); color: #d29922; border: 1px solid rgba(210, 153, 34, 0.4); }
    .badge-low { background: rgba(63, 185, 80, 0.2); color: #3fb950; border: 1px solid rgba(63, 185, 80, 0.4); }

    pre { background: #010409; color: #e6edf3; padding: 1rem; border-radius: 6px; overflow: auto; border: 1px solid var(--border); font-size: 0.85rem; }
    
    .report-link { display: flex; align-items: center; justify-content: space-between; padding: 0.75rem; border-bottom: 1px solid var(--border); text-decoration: none; color: var(--text); }
    .report-link:hover { background: rgba(255,255,255,0.03); }
    .report-link:last-child { border-bottom: none; }
    
    .alert { padding: 1rem; border-radius: 6px; margin-bottom: 1.5rem; border: 1px solid transparent; }
    .alert-success { background: rgba(63, 185, 80, 0.1); border-color: var(--success); color: var(--success); }
    .alert-error { background: rgba(218, 54, 51, 0.1); border-color: var(--danger); color: var(--danger); }
    
    .trend-item { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; font-size: 0.9rem; }
    .trend-bar-container { flex-grow: 1; background: var(--bg); height: 8px; border-radius: 4px; margin: 0 1rem; overflow: hidden; }
    .trend-bar { height: 100%; background: var(--accent); }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Cyber Scout</h1>
      <div style="text-align: right">
        <div style="font-size: 0.8rem; color: var(--text-dim);">Threat Intelligence Platform</div>
        <div style="font-size: 0.7rem; color: var(--accent);">
          <span style="margin-right: 1rem">{{ session.get('username') }}</span>
          <a href="{{ url_for('logout') }}" style="color: var(--danger); text-decoration: none;">Logout</a>
        </div>
      </div>
    </div>

    {% if message %}
      <div class="alert {{ 'alert-success' if success else 'alert-error' }}">
        {{ message }}
      </div>
    {% endif %}

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value">{{ trends.total_reports }}</div>
        <div class="stat-label">Total Reports</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: var(--danger)">{{ trends.severities.get('High', 0) + trends.severities.get('Critical', 0) }}</div>
        <div class="stat-label">Critical Risks</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: var(--success)">{{ reports|length }}</div>
        <div class="stat-label">Stored Assets</div>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <h2>Launch Scan</h2>
        <form method="post">
          <div class="form-group">
            <label>Threat Intel Query</label>
            <input type="text" name="threat_query" value="{{ form.threat_query }}" required>
          </div>
          <div class="form-group">
            <label>CVE Intelligence Query</label>
            <input type="text" name="cve_query" value="{{ form.cve_query }}" required>
          </div>
          <div class="grid" style="grid-template-columns: 1fr 1fr; gap: 1rem;">
            <div class="form-group">
              <label>Model</label>
              <input type="text" name="model" value="{{ form.model }}" required>
            </div>
            <div class="form-group">
              <label>Results Depth</label>
              <input type="number" min="1" name="results" value="{{ form.results }}" required>
            </div>
          </div>
          
          <div class="checkbox-group">
            <label class="checkbox-item">
              <input type="checkbox" name="dry_run" {% if form.dry_run %}checked{% endif %}> Dry Run
            </label>
            <label class="checkbox-item">
              <input type="checkbox" name="send_slack" {% if form.send_slack %}checked{% endif %}> Send to Slack
            </label>
            <label class="checkbox-item">
              <input type="checkbox" name="verbose" {% if form.verbose %}checked{% endif %}> Verbose Logs
            </label>
          </div>
          <br>
          <button type="submit">Generate Intelligence Report</button>
        </form>
      </div>

      <div class="card">
        <h2>Trend Analysis</h2>
        <h3>Severity Distribution</h3>
        {% for sev, count in trends.severities.items() %}
          <div class="trend-item">
            <span style="width: 80px">{{ sev }}</span>
            <div class="trend-bar-container">
              <div class="trend-bar" style="width: {{ (count / (trends.total_reports if trends.total_reports > 0 else 1) * 100)|round }}%; background: {{ 'var(--danger)' if sev in ['High', 'Critical'] else 'var(--accent)' }}"></div>
            </div>
            <span>{{ count }}</span>
          </div>
        {% endfor %}

        <h3 style="margin-top: 1.5rem">Top Recurring Findings</h3>
        {% for r in trends.top_recurring %}
          <div class="trend-item">
            <span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 200px;" title="{{ r.title }}">{{ r.title }}</span>
            <span class="badge badge-med">{{ r.count }} matches</span>
          </div>
        {% endfor %}
      </div>
    </div>

    {% if generated_path %}
    <div class="card">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
        <h2>Latest Intelligence: {{ generated_path.name }}</h2>
        <a href="{{ url_for('download_report', filename=generated_path.name) }}" style="color: var(--accent); text-decoration: none; font-size: 0.9rem;">Download Markdown</a>
      </div>
      <pre>{{ report_content }}</pre>
    </div>
    {% endif %}

    <div class="card">
      <h2>Intelligence History</h2>
      {% if reports %}
        <div style="border: 1px solid var(--border); border-radius: 6px; overflow: hidden;">
        {% for report in reports %}
          <a href="{{ url_for('download_report', filename=report.name) }}" class="report-link">
            <span>{{ report.name }}</span>
            <span style="font-size: 0.8rem; color: var(--text-dim);">{{ report.stat().st_mtime | datetimeformat }}</span>
          </a>
        {% endfor %}
        </div>
      {% else %}
        <p style="color: var(--text-dim); text-align: center; padding: 2rem;">No reports generated yet.</p>
      {% endif %}
    </div>
  </div>
</body>
</html>
"""


def _list_reports() -> list[Path]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return sorted(REPORTS_DIR.glob("*.md"), key=lambda path: path.stat().st_mtime, reverse=True)


def _parse_bool_field(name: str) -> bool:
    return request.form.get(name) == "on"


def _run_cli(
    *,
    threat_query: str,
    cve_query: str,
    model: str,
    results: int,
    output: Path,
    dry_run: bool,
    verbose: bool,
    send_slack: bool,
) -> None:
    # Try to find the CLI script in the same directory as the python executable
    # or fallback to shutil.which.
    cli_cmd = shutil.which("cyber-scout")
    if not cli_cmd:
        # Fallback for development if not installed in PATH
        script_path = Path(sys.executable).parent / "cyber-scout"
        if script_path.exists():
            cli_cmd = str(script_path)
        else:
            raise RuntimeError(
                "cyber-scout command not found. Activate .venv and reinstall with `pip install -e .`."
            )

    command = [
        cli_cmd,
        "--threat-query",
        threat_query,
        "--cve-query",
        cve_query,
        "--model",
        model,
        "--results",
        str(results),
        "--output",
        str(output),
    ]
    if dry_run:
        command.append("--dry-run")
    if verbose:
        command.append("--verbose")
    if send_slack:
        command.append("--send-slack")

    env = os.environ.copy()
    env.setdefault("CREWAI_TRACING_ENABLED", "false")
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            env=env,
            check=False,
            timeout=300, # Increased timeout for CrewAI
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "Report generation timed out. Try again with dry-run enabled or simpler queries."
        ) from exc
    if completed.returncode != 0:
        error_text = (completed.stderr or completed.stdout or "Unknown CLI error").strip()
        raise RuntimeError(error_text)


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key-replace-this-in-env")

    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get("logged_in"):
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return decorated_function

    @app.template_filter('datetimeformat')
    def datetimeformat(value):
        return datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M')

    @app.route("/login", methods=["GET", "POST"])
    def login() -> str | Response:
        error = None
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            user = get_user_by_username(username)
            if user and check_password_hash(user["password_hash"], password):
                session["logged_in"] = True
                session["username"] = username
                return redirect(url_for("home"))
            error = "Invalid credentials"
        return render_template_string(LOGIN_TEMPLATE, error=error)

    @app.get("/logout")
    def logout() -> Response:
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def home() -> str:
        defaults = {
            "threat_query": "latest cybersecurity threats malware ransomware active campaigns",
            "cve_query": "latest CVEs exploited vulnerabilities security advisories",
            "model": DEFAULT_MODEL,
            "results": "5",
            "dry_run": False,
            "send_slack": False,
            "verbose": False,
        }
        return render_template_string(
            PAGE_TEMPLATE,
            form=defaults,
            reports=_list_reports(),
            generated_path=None,
            report_content="",
            message="",
            success=True,
            trends=get_trends()
        )

    @app.post("/")
    @login_required
    def generate() -> str:
        form = {
            "threat_query": request.form.get("threat_query", "").strip(),
            "cve_query": request.form.get("cve_query", "").strip(),
            "model": request.form.get("model", DEFAULT_MODEL).strip(),
            "results": request.form.get("results", "5").strip(),
            "dry_run": _parse_bool_field("dry_run"),
            "send_slack": _parse_bool_field("send_slack"),
            "verbose": _parse_bool_field("verbose"),
        }

        try:
            results = int(form["results"])
            if results < 1:
                raise ValueError
        except ValueError:
            return render_template_string(
                PAGE_TEMPLATE,
                form=form,
                reports=_list_reports(),
                generated_path=None,
                report_content="",
                message="Results per query must be greater than 0.",
                success=False,
                trends=get_trends()
            )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = REPORTS_DIR / f"threat_intelligence_report_{timestamp}.md"

        try:
            _run_cli(
                threat_query=form["threat_query"],
                cve_query=form["cve_query"],
                model=form["model"],
                results=results,
                output=output,
                dry_run=form["dry_run"],
                verbose=form["verbose"],
                send_slack=form["send_slack"],
            )
            report = output.read_text(encoding="utf-8", errors="replace")
            message = f"Report generated: {output.name}"
            if form["send_slack"]:
                message += " (sent to Slack)"
            success = True
        except Exception as exc:
            report = ""
            output = None
            message = str(exc)
            success = False

        return render_template_string(
            PAGE_TEMPLATE,
            form=form,
            reports=_list_reports(),
            generated_path=output,
            report_content=report,
            message=message,
            success=success,
            trends=get_trends()
        )


    @app.get("/reports/<path:filename>")
    @login_required
    def download_report(filename: str) -> Response:
        base = REPORTS_DIR.resolve()
        candidate = (REPORTS_DIR / filename).resolve()
        if not candidate.is_file() or base not in candidate.parents:
            return redirect(url_for("home"))
        return send_file(candidate, as_attachment=False)


    @app.get("/api/reports")
    @login_required
    def api_get_reports():
        limit = request.args.get("limit", 10, type=int)
        return jsonify(get_recent_runs(limit))

    @app.get("/api/reports/latest")
    @login_required
    def api_get_latest_report():
        runs = get_recent_runs(1)
        if not runs:
            return jsonify({"error": "No reports found"}), 404
        return jsonify(runs[0])

    @app.get("/api/reports/<int:run_id>")
    @login_required
    def api_get_report(run_id: int):
        run = get_run_by_id(run_id)
        if not run:
            return jsonify({"error": "Report not found"}), 404
        return jsonify(run)

    @app.get("/api/trends")
    @login_required
    def api_get_trends():
        return jsonify(get_trends())

    return app


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the cyber threat intelligence web dashboard.")
    parser.add_argument("--host", default="127.0.0.1", help="Host for the dashboard server.")
    parser.add_argument("--port", type=int, default=8501, help="Port for the dashboard server.")
    parser.add_argument("--debug", action="store_true", help="Run Flask in debug mode.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    init_db()
    app = create_app()
    app.run(host=args.host, port=args.port, debug=args.debug)
    return 0


if __name__ == "__main__":
    main()
