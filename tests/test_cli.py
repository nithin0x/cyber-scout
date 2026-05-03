import pytest
from cyber_scout.cli import main

def test_cli_dry_run(tmp_path):
    output_file = tmp_path / "report.md"
    # Run CLI in dry-run mode
    exit_code = main([
        "--dry-run",
        "--output", str(output_file)
    ])
    
    assert exit_code == 0
    assert output_file.exists()
    content = output_file.read_text()
    assert "# Cybersecurity Threat Intelligence Report" in content
    assert "This is a dry-run intelligence report" in content

def test_cli_results_positive_int():
    from cyber_scout.cli import parse_args
    with pytest.raises(SystemExit):
        parse_args(["--results", "0"])
    
    args = parse_args(["--results", "10"])
    assert args.results == 10
