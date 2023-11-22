if [ -e capture ] ; then
cat capture | sort | uniq | sed 's/[A-Z].*[0-9][0-9]:[0-9][0-9]:[0-9][0-9] 2[0-9][0-9][0-9] //g'
else echo "no capture file in same directory";
fi
