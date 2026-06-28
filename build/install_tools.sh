#!/bin/bash
set -euxo pipefail

# wllvm
pip3 install --upgrade pip
pip3 install wllvm

# gllvm
mkdir -p ${HOME}/go
export GOPATH=${HOME}/go
export PATH=$PATH:/usr/local/go/bin:${GOPATH}/bin

go install github.com/SRI-CSL/gllvm/cmd/...@latest