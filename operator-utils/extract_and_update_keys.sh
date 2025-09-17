#!/bin/bash

# Script to extract keys from bridge logs and update params.toml files using pattern matching
# Usage: ./extract_and_update_keys.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting key extraction and update process...${NC}"

# Function to extract keys from a specific bridge container
extract_keys_from_bridge() {
    local bridge_num=$1
    local service_name="bridge-${bridge_num}"

    echo -e "${YELLOW}Extracting keys from ${service_name}...${NC}"

    # Get container logs and extract the keys
    local logs=$(docker compose -f ../compose-public.yml logs ${service_name} 2>/dev/null)

    # Extract p2p public key (66 chars including 02 prefix) - strip ANSI codes first
    local p2p_key=$(echo "$logs" | grep "p2p public key" | tail -1 | sed 's/\x1b\[[0-9;]*m//g' | sed -n 's/.*key=\([a-f0-9A-F]\{66\}\).*/\1/p')

    # Extract musig2 public key (64 chars) - strip ANSI codes first
    local musig2_key=$(echo "$logs" | grep "musig2 public key" | tail -1 | sed 's/\x1b\[[0-9;]*m//g' | sed -n 's/.*key=\([a-f0-9A-F]\{64\}\).*/\1/p')

    if [[ -z "$p2p_key" || -z "$musig2_key" ]]; then
        echo -e "${RED}Warning: Could not extract keys from ${service_name} logs${NC}"
        echo "P2P key: $p2p_key"
        echo "Musig2 key: $musig2_key"
        return 1
    fi

    echo -e "${GREEN}Extracted keys for ${service_name}:${NC}"
    echo "  P2P key: $p2p_key"
    echo "  Musig2 key: $musig2_key"

    # Store keys in variables for this bridge
    eval "p2p_key_${bridge_num}=\"$p2p_key\""
    eval "musig2_key_${bridge_num}=\"$musig2_key\""

    return 0
}

# Function to update params.toml file using pattern matching
update_params_toml() {
    local bridge_num=$1
    # Use path relative to project root (go up one directory from operator-utils)
    local params_file="../docker/vol/alpen-bridge-${bridge_num}/params.toml"

    # Get the keys for this bridge
    local p2p_key_var="p2p_key_${bridge_num}"
    local musig2_key_var="musig2_key_${bridge_num}"
    local p2p_key="${!p2p_key_var}"
    local musig2_key="${!musig2_key_var}"

    if [[ -z "$p2p_key" || -z "$musig2_key" ]]; then
        echo -e "${RED}Error: No keys available for bridge-${bridge_num}${NC}"
        return 1
    fi

    if [[ ! -f "$params_file" ]]; then
        echo -e "${RED}Error: ${params_file} does not exist${NC}"
        return 1
    fi

    echo -e "${YELLOW}Updating ${params_file}...${NC}"

    # Create backup
    cp "$params_file" "${params_file}.backup"

    # Read current keys to determine which position this bridge should update
    local current_musig2_keys=($(grep -A 3 'musig2 = \[' "$params_file" | grep -o '"[a-f0-9]\{64\}"' | tr -d '"'))
    local current_p2p_keys=($(grep -A 3 'p2p = \[' "$params_file" | grep -o '"[a-f0-9]\{66\}"' | tr -d '"'))

    if [[ ${#current_musig2_keys[@]} -lt 3 || ${#current_p2p_keys[@]} -lt 3 ]]; then
        echo -e "${RED}Error: Could not find 3 keys in ${params_file}${NC}"
        return 1
    fi

    # Update the specific key for this bridge (bridge_num - 1 for array index)
    local key_index=$((bridge_num - 1))
    local old_musig2_key="${current_musig2_keys[$key_index]}"
    local old_p2p_key="${current_p2p_keys[$key_index]}"

    echo -e "${YELLOW}Replacing keys at position ${key_index}:${NC}"
    echo "  Old musig2: $old_musig2_key -> New: $musig2_key"
    echo "  Old p2p: $old_p2p_key -> New: $p2p_key"

    # Replace the specific musig2 key
    sed -i.tmp "s/\"${old_musig2_key}\"/\"${musig2_key}\"/g" "$params_file"

    # Replace the specific p2p key
    sed -i.tmp "s/\"${old_p2p_key}\"/\"${p2p_key}\"/g" "$params_file"

    # Update wallet_pk values to match current musig2 keys by position
    # Get current musig2 keys to match with wallet_pk
    local current_musig2_keys_for_wallet=($(grep -A 3 'musig2 = \[' "$params_file" | grep -o '"[a-f0-9A-F]\{64\}"' | tr -d '"'))

    if [[ ${#current_musig2_keys_for_wallet[@]} -ge 3 ]]; then
        # For each bridge, update the corresponding wallet_pk to match its current musig2 key
        for pos in 0 1 2; do
            local current_musig2_for_pos="${current_musig2_keys_for_wallet[$pos]}"
            local expected_wallet_pk="0x${current_musig2_for_pos}"

            # Find the current wallet_pk at this position
            local line_num=$((37 + pos))  # Lines 37, 38, 39 contain the operator configs
            local current_line=$(sed -n "${line_num}p" "$params_file")
            local current_wallet_pk=$(echo "$current_line" | grep -o 'wallet_pk = "[^"]*"' | cut -d'"' -f2)

            if [[ "$current_wallet_pk" != "$expected_wallet_pk" ]]; then
                echo "  Position ${pos}: wallet_pk ${current_wallet_pk} -> ${expected_wallet_pk}"
                # Replace the specific wallet_pk in this line
                sed -i.tmp "${line_num}s/wallet_pk = \"[^\"]*\"/wallet_pk = \"${expected_wallet_pk}\"/g" "$params_file"
            fi
        done
    else
        echo -e "${YELLOW}  Warning: Could not find 3 musig2 keys for wallet_pk update${NC}"
    fi

    # Remove temporary file
    rm "${params_file}.tmp"

    echo -e "${GREEN}Updated ${params_file} successfully${NC}"
    return 0
}

# Function to show current keys in params files
show_current_keys() {
    echo -e "${YELLOW}Current keys in params files:${NC}"
    for i in 1 2 3; do
        local params_file="../docker/vol/alpen-bridge-${i}/params.toml"
        if [[ -f "$params_file" ]]; then
            echo -e "${GREEN}Bridge-${i} (${params_file}):${NC}"
            echo "  Musig2 keys:"
            grep -A 3 'musig2 = \[' "$params_file" | grep '"' | sed 's/^/    /'
            echo "  P2P keys:"
            grep -A 3 'p2p = \[' "$params_file" | grep '"' | sed 's/^/    /'
            echo
        fi
    done
}

# Function to update master params file with all extracted keys
update_master_params() {
    echo -e "${YELLOW}Step 2: Updating master params.toml with all extracted keys...${NC}"

    local master_file="../docker/vol/alpen-bridge-1/params.toml"

    if [[ ! -f "$master_file" ]]; then
        echo -e "${RED}Error: Master file $master_file does not exist${NC}"
        return 1
    fi

    # Create backup
    cp "$master_file" "${master_file}.master_backup"

    # Update all keys in the master file
    for i in 1 2 3; do
        local p2p_key_var="p2p_key_${i}"
        local musig2_key_var="musig2_key_${i}"
        local p2p_key="${!p2p_key_var}"
        local musig2_key="${!musig2_key_var}"

        if [[ -n "$p2p_key" && -n "$musig2_key" ]]; then
            local key_index=$((i - 1))

            # Get current keys at this position
            local current_musig2_keys=($(grep -A 3 'musig2 = \[' "$master_file" | grep -o '"[a-f0-9A-F]\{64\}"' | tr -d '"'))
            local current_p2p_keys=($(grep -A 3 'p2p = \[' "$master_file" | grep -o '"[a-f0-9A-F]\{66\}"' | tr -d '"'))

            if [[ ${#current_musig2_keys[@]} -gt $key_index && ${#current_p2p_keys[@]} -gt $key_index ]]; then
                local old_musig2_key="${current_musig2_keys[$key_index]}"
                local old_p2p_key="${current_p2p_keys[$key_index]}"

                echo "  Position ${key_index}: musig2 ${old_musig2_key} -> ${musig2_key}"
                echo "  Position ${key_index}: p2p ${old_p2p_key} -> ${p2p_key}"

                # Replace keys
                sed -i.tmp "s/\"${old_musig2_key}\"/\"${musig2_key}\"/g" "$master_file"
                sed -i.tmp "s/\"${old_p2p_key}\"/\"${p2p_key}\"/g" "$master_file"
            fi
        fi
    done

    # Update wallet_pk values to match musig2 keys
    local current_musig2_keys_for_wallet=($(grep -A 3 'musig2 = \[' "$master_file" | grep -o '"[a-f0-9A-F]\{64\}"' | tr -d '"'))

    if [[ ${#current_musig2_keys_for_wallet[@]} -ge 3 ]]; then
        for pos in 0 1 2; do
            local current_musig2_for_pos="${current_musig2_keys_for_wallet[$pos]}"
            local expected_wallet_pk="0x${current_musig2_for_pos}"

            local line_num=$((37 + pos))
            local current_line=$(sed -n "${line_num}p" "$master_file")
            local current_wallet_pk=$(echo "$current_line" | grep -o 'wallet_pk = "[^"]*"' | cut -d'"' -f2)

            if [[ "$current_wallet_pk" != "$expected_wallet_pk" ]]; then
                echo "  Position ${pos}: wallet_pk ${current_wallet_pk} -> ${expected_wallet_pk}"
                sed -i.tmp "${line_num}s/wallet_pk = \"[^\"]*\"/wallet_pk = \"${expected_wallet_pk}\"/g" "$master_file"
            fi
        done
    fi

    # Remove temporary file
    rm "${master_file}.tmp" 2>/dev/null || true

    echo -e "${GREEN}Updated master file $master_file successfully${NC}"
    return 0
}

# Function to synchronize params.toml files
sync_params_files() {
    echo -e "${YELLOW}Step 3: Synchronizing all params.toml files...${NC}"

    local master_file="../docker/vol/alpen-bridge-1/params.toml"
    local target_files=("../docker/vol/alpen-bridge-2/params.toml" "../docker/vol/alpen-bridge-3/params.toml")

    # Create backups and copy
    for target in "${target_files[@]}"; do
        if [[ -f "$target" ]]; then
            echo -e "${YELLOW}Backing up $target to ${target}.sync_backup${NC}"
            cp "$target" "${target}.sync_backup"
        fi

        echo -e "${YELLOW}Copying $master_file to $target${NC}"
        cp "$master_file" "$target"

        echo -e "${GREEN}✓ Synchronized $target${NC}"
    done

    echo -e "${GREEN}All params.toml files are now synchronized!${NC}"
    return 0
}

# Main execution
main() {
    echo -e "${YELLOW}Step 0: Showing current keys before update...${NC}"
    show_current_keys

    echo -e "${YELLOW}Step 1: Extracting keys from all bridges...${NC}"

    # Extract keys from all bridges
    extracted_count=0
    for i in 1 2 3; do
        if extract_keys_from_bridge $i; then
            extracted_count=$((extracted_count + 1))
        else
            echo -e "${RED}Failed to extract keys from bridge-${i}. Skipping update for this bridge.${NC}"
        fi
    done

    if [[ $extracted_count -eq 0 ]]; then
        echo -e "${RED}No keys could be extracted. Exiting.${NC}"
        exit 1
    fi

    # Update master params file with all extracted keys
    if ! update_master_params; then
        echo -e "${RED}Failed to update master params file${NC}"
        exit 1
    fi

    # Synchronize all params files to match the master
    if ! sync_params_files; then
        echo -e "${RED}Failed to synchronize params files${NC}"
        exit 1
    fi

    echo -e "${GREEN}Key extraction and update process completed!${NC}"
    echo -e "${GREEN}Successfully updated all 3 params files${NC}"
    echo -e "${YELLOW}Backup files created with .master_backup and .sync_backup extensions${NC}"

    echo -e "${YELLOW}Step 4: Showing final synchronized keys...${NC}"
    show_current_keys

    echo -e "${YELLOW}All bridges now have identical configurations. Restart with:${NC}"
    echo "docker compose -f ../compose-public.yml restart bridge-1 bridge-2 bridge-3"
}

# Run main function
main