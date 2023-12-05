#!/bin/bash
DATE=$(date +%d%m%y%H%M)
cat capture | egrep -o "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | \
	grep -v "255.*" | egrep -v "127\.[0-9]{1,3}.*" | sort | uniq > /tmp/$DATE

while read -r line; do echo "ip lookup: $line" ; dig -x $line +short; echo ""; done < /tmp/$DATE
rm -f /tmp/$DATE

