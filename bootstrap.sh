#!/bin/sh
set -e
VERSION=v2025.12.20
curl -fsSL https://github.com/3leaps/sfetch/releases/download/${VERSION}/sfetch_$(uname -s)_$(uname -m).tar.gz | tar xz
./sfetch --self-verify
mv sfetch /usr/local/bin/
sfetch --version