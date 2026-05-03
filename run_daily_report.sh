#!/usr/bin/env bash

# ==============================================================================
# Cyber Scout - Automated Intelligence Job
# Optimized for portability across Linux distributions.
# This script handles setup, execution, and automation scheduling.
# ==============================================================================

# 1. Configuration & Path Setup
SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"
PROJECT_DIR="$(cd "$(dirname "${SCRIPT_PATH}")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="${PROJECT_DIR}/reports"
LOG_FILE="${OUTPUT_DIR}/automation.log"
DEFAULT_SCHEDULE_TIME="08:00"

# Ensure reports directory exists
mkdir -p "${OUTPUT_DIR}"

# Logging helper
log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo "$msg"
    echo "$msg" >> "${LOG_FILE}"
}

# --- Functions ---

show_help() {
    echo "Usage: ./run_daily_report.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --setup           Install dependencies and setup environment"
    echo "  --schedule [TIME] Schedule daily automation via cron (default: 08:00)"
    echo "  --run             Run the report immediately (default action)"
    echo "  --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  ./run_daily_report.sh --setup"
    echo "  ./run_daily_report.sh --schedule 09:30"
}

check_python() {
    log "Checking Python version..."
    if ! command -v python3 >/dev/null 2>&1; then
        log "ERROR: python3 not found. Please install Python 3.10, 3.11, 3.12, or 3.13."
        exit 1
    fi

    # CrewAI supports 3.10 to 3.13
    if ! python3 -c 'import sys; exit(0 if sys.version_info.major == 3 and 10 <= sys.version_info.minor <= 13 else 1)'; then
        PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        log "ERROR: Unsupported Python version $PY_VER. Required: 3.10 - 3.13."
        exit 1
    fi
    log "Python version OK."
}

setup_environment() {
    check_python
    
    cd "${PROJECT_DIR}" || exit 1

    # Create virtual environment if it doesn't exist
    if [ ! -d ".venv" ]; then
        log "Creating virtual environment in .venv..."
        python3 -m venv .venv || { log "ERROR: Failed to create venv."; exit 1; }
    fi

    # Activate and install
    log "Installing/Updating dependencies..."
    source .venv/bin/activate
    pip install -U pip --quiet
    pip install -e . --quiet || { log "ERROR: Failed to install package."; exit 1; }
    
    # Handle .env
    if [ ! -f ".env" ]; then
        log "Initializing .env from .env.example..."
        cp .env.example .env
        log "WARNING: .env created. PLEASE EDIT IT with your API keys before running."
    fi

    log "Setup complete."
}

schedule_automation() {
    local sched_time="${1:-$DEFAULT_SCHEDULE_TIME}"
    
    # Validate time format (HH:MM)
    if [[ ! "$sched_time" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]]; then
        log "ERROR: Invalid time format '$sched_time'. Use HH:MM (e.g., 08:30)."
        exit 1
    fi

    local hour="${sched_time%%:*}"
    local minute="${sched_time#*:}"
    
    # Remove leading zeros for cron (some crons are picky)
    hour=$((10#$hour))
    minute=$((10#$minute))

    # Absolute path to this script
    local script_abs_path="${PROJECT_DIR}/run_daily_report.sh"
    
    # Construct cron line
    local cron_cmd="$minute $hour * * * /usr/bin/bash $script_abs_path --run >> $LOG_FILE 2>&1"
    
    # Add to crontab, avoiding duplicates
    (crontab -l 2>/dev/null | grep -v "$script_abs_path"; echo "$cron_cmd") | crontab -
    
    log "SUCCESS: Scheduled daily report at $sched_time via cron."
    log "Cron command: $cron_cmd"
}

run_report() {
    log "Starting Cyber Scout report execution..."

    # Ensure environment is ready
    if [ ! -f ".venv/bin/activate" ]; then
        log "Environment not found. Running setup first..."
        setup_environment
    fi

    source .venv/bin/activate

    # Check for .env
    if [ ! -f ".env" ]; then
        log "ERROR: .env file missing. Run with --setup and configure your keys."
        exit 1
    fi

    # Ensure command exists
    if ! command -v cyber-scout >/dev/null 2>&1; then
        log "ERROR: 'cyber-scout' command not found. Re-running setup..."
        setup_environment
        source .venv/bin/activate
    fi

    OUTPUT_PATH="${OUTPUT_DIR}/automated_report_${TIMESTAMP}.md"

    # Execute
    cyber-scout \
        --output "${OUTPUT_PATH}" \
        --export-pdf \
        --export-json \
        --send-slack \
        >> "${LOG_FILE}" 2>&1

    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        log "SUCCESS: Report generated at ${OUTPUT_PATH}"
    else
        log "FAILURE: Cyber Scout exited with code ${exit_code}. Check ${LOG_FILE} for details."
    fi

    return $exit_code
}

# --- Main Entry Point ---

cd "${PROJECT_DIR}" || exit 1

if [ $# -eq 0 ]; then
    run_report
    exit $?
fi

case "$1" in
    --setup)
        setup_environment
        ;;
    --schedule)
        schedule_automation "$2"
        ;;
    --run)
        run_report
        ;;
    --help|-h)
        show_help
        ;;
    *)
        log "Unknown option: $1"
        show_help
        exit 1
        ;;
esac
