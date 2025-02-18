#!/bin/bash

# Function to replace content in files
replace_in_file() {
    local file="$1"
    sed -i '' \
        -e 's/AtomicTechnique/AttackLibTechnique/g' \
        -e 's/AtomicTest/AttackLibTest/g' \
        -e 's/AtomicDependency/AttackLibDependency/g' \
        -e 's/AtomicInputArgument/AttackLibInputArgument/g' \
        -e 's/AtomicExecutorBase/AttackLibExecutorBase/g' \
        -e 's/AtomicExecutorDefault/AttackLibExecutorDefault/g' \
        -e 's/AtomicExecutorManual/AttackLibExecutorManual/g' \
        -e 's/Atomic Red Team/Attack Lib/g' \
        -e 's/AtomicRedTeam/AttackLib/g' \
        -e 's/atomic-red-team/attack-lib/g' \
        -e 's/atomicredteam/attacklib/g' \
        -e 's/Invoke-Atomic/Invoke-AttackLib/g' \
        -e 's/Get-Atomic/Get-AttackLib/g' \
        -e 's/New-Atomic/New-AttackLib/g' \
        -e 's/Start-Atomic/Start-AttackLib/g' \
        -e 's/Stop-Atomic/Stop-AttackLib/g' \
        "$file"
}

# Process all PowerShell files
find . -type f -name "*.ps1" -o -name "*.psd1" -o -name "*.psm1" | while read -r file; do
    echo "Processing $file"
    replace_in_file "$file"
done
