#!/bin/bash
set -eux

# Install lsb_release if missing
apt-get update
apt-get install -y lsb-release wget gnupg software-properties-common

wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
./llvm.sh 20

# Create unversioned symlinks — force in case they already exist
ln -sf /usr/bin/clang-20 /usr/local/bin/clang
ln -sf /usr/bin/clang++-20 /usr/local/bin/clang++
ln -sf /usr/bin/llvm-config-20 /usr/local/bin/llvm-config
ln -sf /usr/bin/opt-20 /usr/local/bin/opt
ln -sf /usr/bin/llc-20 /usr/local/bin/llc

# Verify
clang --version
llvm-config --version