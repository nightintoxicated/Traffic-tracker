# Traffic-tracker
<img src="https://github.com/nightintoxicated/Traffic-tracker/blob/main/logo.png" alt="drawing" width="200"/>

Monitor outgoing traffic easily, log what you want and find unique hits.

would be good to have something that does reverse lookups of the ip and a geo location also

Traffic tracker is a program sitting ontop of libpcap to see the flow of traffic through your system.

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
