#!/bin/sh
grep -n "def var2pairs\|def cook\|int(\|float(" /usr/lib/python3.12/site-packages/ntp/util.py | head -30
echo "---"
awk "/def var2pairs/,/^def /" /usr/lib/python3.12/site-packages/ntp/util.py | head -50
echo "==="
awk "/def cook/,/^def /" /usr/lib/python3.12/site-packages/ntp/util.py | head -50
