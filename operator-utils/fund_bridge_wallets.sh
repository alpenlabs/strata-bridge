#!/bin/bash

# Bridge Wallet Funding Script
# Loads wallet addresses from bridge_wallets.toml and funds them via Bitcoin CLI
# Usage: ./fund_wallets.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}=== Bridge Wallet Funding Script ===${NC}"

# Check if TOML file exists
if [[ ! -f "bridge_wallets.toml" ]]; then
    echo -e "${RED}Error: bridge_wallets.toml file not found!${NC}"
    echo "Please make sure the bridge_wallets.toml file is in the same directory."
    echo "Generate it by running ./fund_bridge_wallets.sh first."
    exit 1
fi

echo "Loading wallet addresses from bridge_wallets.toml..."

# Simple TOML parser for our specific format
parse_toml() {
    local toml_file="bridge_wallets.toml"

    # Parse funding amounts
    GENERAL_AMOUNT=$(grep "general_amount" "$toml_file" | sed 's/.*= *\([0-9.]*\).*/\1/')
    STAKECHAIN_AMOUNT=$(grep "stakechain_amount" "$toml_file" | sed 's/.*= *\([0-9.]*\).*/\1/')

    # Parse bridge entries
    declare -g -a BRIDGE_NAMES
    declare -g -a GENERAL_WALLETS
    declare -g -a STAKECHAIN_WALLETS

    # Extract all bridge sections
    local bridge_section=""
    local in_bridge_section=false

    while IFS= read -r line; do
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

        if [[ "$line" =~ ^\[\[bridges\]\] ]]; then
            in_bridge_section=true
            bridge_section=""
        elif [[ "$line" =~ ^\[.*\] ]] && [[ "$line" != "[[bridges]]" ]]; then
            in_bridge_section=false
        elif [[ "$in_bridge_section" == true ]]; then
            if [[ "$line" =~ name[[:space:]]*=[[:space:]]*\"([^\"]+)\" ]]; then
                BRIDGE_NAMES+=("${BASH_REMATCH[1]}")
            elif [[ "$line" =~ general_wallet[[:space:]]*=[[:space:]]*\"([^\"]+)\" ]]; then
                GENERAL_WALLETS+=("${BASH_REMATCH[1]}")
            elif [[ "$line" =~ stakechain_wallet[[:space:]]*=[[:space:]]*\"([^\"]+)\" ]]; then
                STAKECHAIN_WALLETS+=("${BASH_REMATCH[1]}")
            fi
        fi
    done < "$toml_file"

    echo -e "${GREEN}Found ${#BRIDGE_NAMES[@]} bridge(s) to fund${NC}"
}

# Parse the TOML file
parse_toml

# Check if bitcoin-cli is available
if ! command -v bitcoin-cli &> /dev/null; then
    echo -e "${RED}Error: bitcoin-cli command not found!${NC}"
    echo "Please make sure Bitcoin Core is installed and in your PATH."
    exit 1
fi

echo -e "${YELLOW}Funding bridge wallets with Bitcoin...${NC}"
echo

# Fund General Wallets
echo -e "${BLUE}=== Funding General Wallets (${GENERAL_AMOUNT} BTC each) ===${NC}"

for i in "${!BRIDGE_NAMES[@]}"; do
    bridge_name="${BRIDGE_NAMES[$i]}"
    general_wallet="${GENERAL_WALLETS[$i]}"

    if [[ -n "$general_wallet" ]]; then
        echo -e "${YELLOW}Funding ${bridge_name} general wallet: ${general_wallet}${NC}"
        bitcoin-cli sendtoaddress "$general_wallet" "$GENERAL_AMOUNT"
        echo -e "${GREEN}✓ Sent ${GENERAL_AMOUNT} BTC to ${bridge_name} general wallet${NC}"
    fi
done

echo
echo -e "${BLUE}=== Funding Stakechain Wallets (${STAKECHAIN_AMOUNT} BTC each) ===${NC}"

for i in "${!BRIDGE_NAMES[@]}"; do
    bridge_name="${BRIDGE_NAMES[$i]}"
    stakechain_wallet="${STAKECHAIN_WALLETS[$i]}"

    if [[ -n "$stakechain_wallet" ]]; then
        echo -e "${YELLOW}Funding ${bridge_name} stakechain wallet: ${stakechain_wallet}${NC}"
        bitcoin-cli sendtoaddress "$stakechain_wallet" "$STAKECHAIN_AMOUNT"
        echo -e "${GREEN}✓ Sent ${STAKECHAIN_AMOUNT} BTC to ${bridge_name} stakechain wallet${NC}"
    fi
done

echo
echo -e "${BLUE}=== Mining block to confirm transactions ===${NC}"
echo -e "${YELLOW}Generating block to confirm all transactions...${NC}"
bitcoin-cli generatetoaddress 1 "$(bitcoin-cli getnewaddress)"
echo -e "${GREEN}✓ Block mined and transactions confirmed${NC}"

echo
echo -e "${GREEN}🎉 Bridge wallets funded successfully!${NC}"
echo -e "${YELLOW}You can now restart the bridge services with:${NC}"
echo -e "${BLUE}docker compose -f compose-public.yml restart bridge-1 bridge-2 bridge-3${NC}"

# Show funding summary
echo
echo -e "${GREEN}=== FUNDING SUMMARY ===${NC}"

bridge_count=${#BRIDGE_NAMES[@]}
total_general_btc=$(echo "scale=8; $bridge_count * $GENERAL_AMOUNT" | bc -l 2>/dev/null || echo "$(($bridge_count * ${GENERAL_AMOUNT%.*}))")
total_stakechain_btc=$(echo "scale=8; $bridge_count * $STAKECHAIN_AMOUNT" | bc -l 2>/dev/null || echo "$STAKECHAIN_AMOUNT")

echo -e "${BLUE}Bridges funded: ${bridge_count}${NC}"
echo -e "${BLUE}General wallets: ${bridge_count} × ${GENERAL_AMOUNT} BTC = ${total_general_btc} BTC total${NC}"
echo -e "${BLUE}Stakechain wallets: ${bridge_count} × ${STAKECHAIN_AMOUNT} BTC = ${total_stakechain_btc} BTC total${NC}"

for i in "${!BRIDGE_NAMES[@]}"; do
    echo -e "${YELLOW}${BRIDGE_NAMES[$i]}:${NC}"
    echo -e "  General: ${GENERAL_WALLETS[$i]}"
    echo -e "  Stakechain: ${STAKECHAIN_WALLETS[$i]}"
done

echo -e "${GREEN}All operations completed successfully!${NC}"