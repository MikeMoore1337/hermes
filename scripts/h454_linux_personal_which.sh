#!/bin/sh
# Installed as bin/which: the sandbox does not expose /etc/alternatives.
[ "$#" -gt 0 ] || exit 1
for name do
    command -v "$name" || exit 1
done
