#!/bin/bash

if [ -e capture ] ; then

  if [ -n "$1" ]; then
    src_ip=$1;
    echo "searching for ip $src_ip";
    cat capture | sort | uniq | sed 's/[A-Z].*[0-9][0-9]:[0-9][0-9]:[0-9][0-9] 2[0-9][0-9][0-9] //g' | grep $src_ip;
  else
    cat capture | sort | uniq | sed 's/[A-Z].*[0-9][0-9]:[0-9][0-9]:[0-9][0-9] 2[0-9][0-9][0-9] //g';
  fi

else
echo "no capture file in same directory";
fi
unset src_ip;
