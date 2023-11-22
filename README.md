# Traffic-tracker
<img src="https://github.com/nightintoxicated/Traffic-tracker/blob/main/logo.png" alt="drawing" width="200"/>
Traffic tracker is a program sitting ontop of libpcap and net::pcap::easy to see the flow of traffic through your system.  
You can easily monitor outgoing traffic, log what you want and find unique hits.  
Run it on idle and see if your computer is making any outbound connections somewhere unwanted.   

# Config File  
The config file contains a number of lines you can edit to change the behaviour of the program.  
  
dev: The base device to monitor traffic from  
filter: same syntax as youd expect from tcpdump et al: https://www.tcpdump.org/manpages/pcap-filter.7.html  
packets_per_loop: how many packets do you want to capture for each loop cycle.  
bytes_to_capture: 256 to 65535 (maximum value of an unsigned 16-bit integer)  
promiscuous: want to capture traffic for other devices?  
verbose: high verbosity will spit out LOTS more details in the capture.high log file.  
logging: self explanatory  
intrudermode: This is a mode that only prints unique connections, you can run it while your computer is idle to see if traffic of your filter is going.  


config options example, where | seperates options to choose, select only one, e.g. intrudermode=yes  

dev=ens3  
filter=not port 22  
packets_per_loop=10  
bytes_to_capture=65535  
promiscuous=0 | 1  
verbose=high | low  
logging=yes | no  
intrudermode=yes | no  
  
# Other Files  
setup.sh (install required dependencies)  
unique.sh (show unique addresses from the log file if you captured with intruder mode off)  
pcap.pl (the main program, make it executable with chmod +x pcap.pl, then run "perl pcap.pl" to start the program)  
  
would be good to have something that does reverse lookups of the ip and a geo location also

# no warranty, or whatever
