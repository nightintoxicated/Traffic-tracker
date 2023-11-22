# whos_speaking
https://github.com/nightintoxicated/Traffic-tracker/blob/main/logo.png
![alt text](https://github.com/nightintoxicated/Traffic-tracker/blob/main/logo.png?raw=true)



<img src="https://github.com/nightintoxicated/Traffic-tracker/blob/main/logo.png" alt="drawing" width="200"/>

monitor outgoing traffic

would be good to have something that does reverse lookups of the ip and a geo location also


config options
default:

dev=ens3

filter=not port 22 | https://www.tcpdump.org/manpages/pcap-filter.7.html

packets_per_loop=10 | x

bytes_to_capture=1024 | 65535

promiscuous=0 | 1

verbose=high | how

logging=yes | no


dev=device to monitor
filter=same syntax style as tcpdump
packets_per_loop=x
bytes_to_capture=x
promiscuous=self explain
verbose=high (or low)
logging=yes (or no)


print unique events
sed 's/[A-Z].*2023 //g' capture | sort | uniq
