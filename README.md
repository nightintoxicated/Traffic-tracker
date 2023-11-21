# whos_speaking

monitor outgoing traffic

would be good to have something that does reverse lookups of the ip and a geo location also


config options
default:

dev=ens3

filter=not port 22

packets_per_loop=10

bytes_to_capture=1024

promiscuous=0

verbose=high

logging=yes


dev=device to monitor
filter=same syntax style as tcpdump
packets_per_loop=x
bytes_to_capture=x
promiscuous=self explain
verbose=high (or low)
logging=yes (or no)
