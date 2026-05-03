import re
from typing import Any, Dict

def parse_report(report_md: str) -> Dict[str, Any]:
    findings = []
    top_risks = []
    
    # Simple regexes to extract domains, IPs, CVEs
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    # Extract sections
    sections = {}
    current_section = None
    section_headers = [
        "Executive Summary",
        "Top Threats",
        "Sample Threats",
        "Latest Vulnerabilities",
        "Sample Vulnerabilities",
        "Recommended Actions",
        "Prioritized Defensive Actions",
        "Cited Sources",
        "Technical Appendix",
        "Prioritized SOC Action List"
    ]
    
    lines = report_md.splitlines()
    for i, line in enumerate(lines):
        header_match = re.match(r"^#+\s*(.*)$", line)
        if header_match:
            header_text = header_match.group(1).strip()
            found_header = None
            for sh in section_headers:
                if sh.lower() in header_text.lower():
                    found_header = sh
                    break
            
            if found_header:
                current_section = found_header
                sections[current_section] = []
                continue
        
        if current_section:
            sections[current_section].append(line)

    # Clean up sections
    for k in sections:
        sections[k] = "\n".join(sections[k]).strip()

    # Extract findings from lines containing CVEs
    for line in lines:
        cves_found = cve_pattern.findall(line)
        if cves_found:
            severity = "Unknown"
            if "Critical" in line or "critical" in line:
                severity = "Critical"
            elif "High" in line or "high" in line:
                severity = "High"
            elif "Medium" in line or "medium" in line:
                severity = "Medium"
            elif "Low" in line or "low" in line:
                severity = "Low"
            else:
                if "exploit" in line.lower() or "active" in line.lower():
                    severity = "High"
                    
            for cve in cves_found:
                findings.append({
                    "type": "cve",
                    "title": cve,
                    "severity": severity,
                    "description": line.strip("-*1234567890. ").strip()
                })
                if severity in ("Critical", "High"):
                    top_risks.append(f"{cve}: {line.strip('-*1234567890. ').strip()}")

        # Look for IPs as IOCs
        ips_found = ip_pattern.findall(line)
        for ip in ips_found:
            findings.append({
                "type": "ioc",
                "title": ip,
                "severity": "Info",
                "description": f"IP found: {ip}"
            })
            
    # Extract findings from Threats section
    threat_section_text = sections.get("Top Threats", sections.get("Sample Threats", ""))
    if threat_section_text:
        for line in threat_section_text.splitlines():
            if line.strip().startswith("-") or line.strip().startswith("*") or bool(re.match(r"^\d+\.", line.strip())):
                clean_title = line.strip("-*1234567890. ").split(":")[0].split("**")[0].strip()
                if clean_title:
                    findings.append({
                        "type": "threat",
                        "title": clean_title,
                        "severity": "High",
                        "description": line.strip("-*1234567890. ").strip()
                    })

    return {
        "findings": findings,
        "top_risks": top_risks,
        "sections": sections,
        "critical_found": any(f.get("severity") == "Critical" for f in findings)
    }

def format_soc_action_list(parsed_data: Dict[str, Any]) -> str:
    lines = ["## Prioritized SOC Action List\n"]
    criticals = [f for f in parsed_data["findings"] if f["severity"] == "Critical"]
    highs = [f for f in parsed_data["findings"] if f["severity"] == "High"]
    
    if criticals:
        lines.append("### CRITICAL PRIORITY (Immediate Action Required)")
        for f in criticals:
            lines.append(f"- Block/Patch {f['type'].upper()}: {f['title']} - {f['description']}")
        lines.append("")
        
    if highs:
        lines.append("### HIGH PRIORITY (Review within 24h)")
        for f in highs:
            lines.append(f"- Investigate {f['type'].upper()}: {f['title']} - {f['description']}")
        lines.append("")
        
    if not criticals and not highs:
        lines.append("No critical or high priority actions identified in this run.")
        
    return "\n".join(lines)
