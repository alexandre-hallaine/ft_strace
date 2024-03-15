#!/bin/bash

# Function to find the appropriate syscall header file
get_syscall_header() {
    bit_version=$1
    header_dir=${2:-"/usr/include/$(uname -m)-linux-gnu/asm"}
    header_file="${header_dir}/unistd_${bit_version}.h"

    if [[ -f "$header_file" ]]; then
        echo "$header_file"
    else
        echo "Error: Unsupported architecture or invalid bit version." >&2
        return 1
    fi
}

# Function to extract a syscall prototype with refinements
extract_syscall_prototype() {
    syscall_name=$1
    man_page=$(man 2 "$syscall_name" 2>/dev/null)

    if [[ $? -eq 0 ]]; then
        echo "$man_page" | \
        sed -n '/^SYNOPSIS/,/^DESCRIPTION/p' | \
        grep -oE '\b[a-z_]+\([^\)]*\)\s*;' | \
        grep -F "$syscall_name"
    fi
}

# Function to generate the syscall table content for a given architecture
generate_syscall_table() {
    bit_version=$1
    output_file="${bit_version}.h"
    syscall_header=$(get_syscall_header $bit_version)

    echo "#pragma once" > "$output_file" 
    echo "#include \"types.h\"" >> "$output_file"

    echo "" >> "$output_file"
    echo "#define ${bit_version}_BIT_SYSCALL_TABLE { \\" >> "$output_file"

    grep -oE '__NR_[a-z0-9_]+\s+[0-9]+' "$syscall_header" | \
        while read -r syscall_line; do
            syscall_name=$(echo "$syscall_line" | awk '{print $1}' | sed 's/__NR_//')
            syscall_number=$(echo "$syscall_line" | awk '{print $2}')
            prototype=$(extract_syscall_prototype $syscall_name | sed 's/\/\*.*\*\///g')
            
            if [[ -z "$prototype" ]]; then
                prototype="UNKNOWN PROTOTYPE"
            fi 

            echo "/* $prototype */" >> "$output_file"
            echo "[$syscall_number] = { \"$syscall_name\", { UNKNOWN }, UNKNOWN }, \\" >> "$output_file"
        done

    echo "}" >> "$output_file"
    echo "Syscall table generated: $output_file"
}

# Generate header files
generate_syscall_table "32"
generate_syscall_table "64"
