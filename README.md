# Traffic-tracker


<img src="https://github.com/nightintoxicated/Traffic-tracker/blob/main/logo.png" alt="drawing" width="200"/>  
Traffic tracker is a program sitting ontop of libpcap and net::pcap::easy to see the flow of traffic through your system.  
You can easily monitor outgoing traffic, log what you want and find unique hits.  

With intruder mode, run traffic tracker on idle and see if your computer is making any unwanted outbound connections then block them with a firewall, or investigate.  


<img src="https://github.com/nightintoxicated/Traffic-tracker/blob/main/edit.jpg" alt="drawing"/>  


# Setup: setup.sh  
install the dependencies you need


# Setup: Config File  
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

# Running the program  
if you ran the setup script and you have usr/local/sbin in your path, you can type monitor and the program will start running, otherwise, the executable is in /etc/traffictracker.
the logging also logs to /etc/traffictracker. 

  
# Other Files  
unique.sh (show unique addresses from the log file if you captured with intruder mode off)  
unique.sh can take an argument as an ip address, this pulls out only logs relevant to that ip, otherwise without an argument it shows everything.
Useful for if you have a firewall and something is blocking but youre not sure what (bare in mind this wont capture other defined protocols such as proto 50 or proto 51)


hostnamelookup.sh (does a reverse lookup of the unique ip's captured from the capture file if logging is on)



# no warranty, or whatever

