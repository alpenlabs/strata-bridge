#!/bin/bash

# Script to extract wallet addresses from bridge logs and generate funding commands
# Usage: ./fund_bridge_wallets.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}Bridge Wallet Funding Script${NC}"
echo -e "${YELLOW}Extracting wallet addresses from bridge logs...${NC}"

# Arrays to store extracted wallets
declare -a general_wallets
declare -a stakechain_wallets

# Function to extract wallets from a specific bridge container
extract_wallets_from_bridge() {
    local bridge_num=$1
    local service_name="bridge-${bridge_num}"

    echo -e "${YELLOW}Extracting wallets from ${service_name}...${NC}"

    # Get container logs
    local logs=$(docker compose -f ../compose-public.yml logs ${service_name} 2>/dev/null)

    # Extract general wallet address
    local general_wallet=$(echo "$logs" | grep "general wallet address:" | tail -1 | sed -n 's/.*general wallet address: \([a-zA-Z0-9]*\).*/\1/p')

    # Extract stakechain wallet address
    local stakechain_wallet=$(echo "$logs" | grep "stakechain wallet address:" | tail -1 | sed -n 's/.*stakechain wallet address: \([a-zA-Z0-9]*\).*/\1/p')

    if [[ -n "$general_wallet" && -n "$stakechain_wallet" ]]; then
        echo -e "${GREEN}  Extracted wallets for ${service_name}:${NC}"
        echo -e "    General: ${general_wallet}"
        echo -e "    Stakechain: ${stakechain_wallet}"

        general_wallets+=("$general_wallet")
        stakechain_wallets+=("$stakechain_wallet")
        return 0
    else
        echo -e "${RED}  Could not extract wallet addresses from ${service_name}${NC}"
        echo -e "${YELLOW}  General wallet: ${general_wallet:-'NOT FOUND'}${NC}"
        echo -e "${YELLOW}  Stakechain wallet: ${stakechain_wallet:-'NOT FOUND'}${NC}"
        return 1
    fi
}


# Function to save wallets to TOML file
save_wallets_to_toml() {
    local toml_file="bridge_wallets.toml"

    echo -e "${YELLOW}Saving wallets to ${toml_file}...${NC}"

    cat > "$toml_file" << EOF
# Bridge Wallet Addresses
# Generated on $(date)

[funding]
general_amount = 200.0
stakechain_amount = 0.00027720

[[bridges]]
EOF

    # Add bridge entries
    for i in "${!general_wallets[@]}"; do
        local bridge_num=$((i + 1))
        local general_wallet="${general_wallets[$i]}"
        local stakechain_wallet="${stakechain_wallets[$i]}"

        if [[ $i -gt 0 ]]; then
            echo "" >> "$toml_file"
            echo "[[bridges]]" >> "$toml_file"
        fi

        echo "name = \"bridge-${bridge_num}\"" >> "$toml_file"
        echo "general_wallet = \"${general_wallet}\"" >> "$toml_file"
        echo "stakechain_wallet = \"${stakechain_wallet}\"" >> "$toml_file"
    done

    echo -e "${GREEN}Wallets saved to ${toml_file}${NC}"
}


# Function to show wallet summary
show_wallet_summary() {
    echo
    echo -e "${GREEN}=== WALLET SUMMARY ===${NC}"
    echo -e "${BLUE}Extracted ${#general_wallets[@]} general wallet(s) and ${#stakechain_wallets[@]} stakechain wallet(s)${NC}"
    echo

    for i in "${!general_wallets[@]}"; do
        local bridge_num=$((i + 1))
        echo -e "${YELLOW}Bridge-${bridge_num}:${NC}"
        echo -e "  General:    ${general_wallets[$i]} (will receive 200 BTC)"
        echo -e "  Stakechain: ${stakechain_wallets[$i]} (will receive 0.00027720 BTC)"
    done
    echo
}

# Main execution
main() {
    echo -e "${YELLOW}Step 1: Extracting wallet addresses from bridge logs...${NC}"

    # Extract wallets from all bridges
    extracted_count=0
    for i in 1 2 3; do
        if extract_wallets_from_bridge $i; then
            extracted_count=$((extracted_count + 1))
        fi
    done

    if [[ $extracted_count -eq 0 ]]; then
        echo -e "${RED}No wallet addresses could be extracted from any bridge logs.${NC}"
        echo -e "${YELLOW}Make sure bridges have run and generated wallet addresses.${NC}"
        echo -e "${YELLOW}Look for log lines containing:${NC}"
        echo -e "${YELLOW}  - 'general wallet address:'${NC}"
        echo -e "${YELLOW}  - 'stakechain wallet address:'${NC}"
        exit 1
    fi

    echo -e "${GREEN}Successfully extracted wallets from ${extracted_count} bridge(s)${NC}"

    # Show wallet summary
    show_wallet_summary

    # Save wallets to TOML file
    save_wallets_to_toml

    echo -e "${GREEN}Wallet extraction completed!${NC}"
    echo
    echo -e "${YELLOW}=== NEXT STEPS ===${NC}"
    echo -e "${YELLOW}1. Check the generated bridge_wallets.toml file${NC}"
    echo -e "${YELLOW}2. Copy bridge_wallets.toml to your Bitcoin miner node${NC}"
    echo -e "${YELLOW}3. Use the fund_bridge_wallets.sh script to fund the wallets${NC}"
    echo -e "${YELLOW}4. Restart bridge services after funding${NC}"
}

# Run main function
main
