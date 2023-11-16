#!/usr/bin/perl
$|=1;
use strict;
use warnings;
use Data::Dumper;
use Net::Pcap::Easy;

#time to capture the settings from file
my $config_file = 'config';
my ($dev, $filter, $packets_per_loop, $bytes_to_capture, $promiscuous, $verbose);
open (my $config_fh, '<', $config_file) or die "cannot open configuration file: $config_file\n";

while (<$config_fh>) {

  #device
  if ($_ =~ m/^dev/) {
    #capture stuff after "="
    if (/=(\S+)/) {
      $dev = $1;
      print "Device found: $dev\n";
    } else {
      print "No match found in the 'dev' line\n";
      }}

  #filter
  if ($_ =~ m/^filter/) {
    #capture stuff after "="
    if (/=(.+)/) {
      $filter = $1;
      print "filter found: $filter\n";
    } else {
      print "No match found in the 'filter' line\n";
      }}

  #packets_per_loop
  if ($_ =~ m/^packets_per_loop/) {
    #capture stuff after "="
    if (/=(\S+)/) {
      $packets_per_loop = $1;
      print "packets per loop count found: $packets_per_loop\n";
    } else {
      print "No match found in the 'packets_per_loop' line\n";
      }}


  #bytes_to_capture
  if ($_ =~ m/^bytes_to_capture/) {
    #capture stuff after "="
    if (/=(\S+)/) {
      $bytes_to_capture = $1;
      print "bytes to capture count found: $bytes_to_capture\n";
    } else {
      print "No match found in the 'bytes_to_capture' line\n";
      }}


  #promiscuous
  if ($_ =~ m/^promiscuous/) {
    #capture stuff after "="
    if (/=(\S+)/) {
      $promiscuous = $1;
      print "promiscuous mode found: $promiscuous\n";
    } else {
      print "No match found in the 'promiscuous mode' line\n";
      }}

  #verbose
  if ($_ =~ m/^verbose/) {
    #capture stuff after "="
    if (/=(\S+)/) {
      $verbose = $1;
      print "verbosity found: $verbose\n";
    } else {
      print "No match found in the 'verbose' line\n";
      }}
}
close($config_fh);
exit 0;




#todo, can we dump to pcap format to open in wireshark?
#npe = net packet easy object, ether = ethernet object, ip = ip object, tcp = tcp object, header = header object

# all arguments to new are optional
my $npe = Net::Pcap::Easy->new(
        #todo, read ens3 from a config file
  dev              => $dev,
#todo, read filter from a config file, else dont cap port 22
  filter           => "not port 22",
  packets_per_loop => 10,
  bytes_to_capture => 1024,
#todo, read this from a config file
  promiscuous      => 0, # true or false

  #todo, expand print to filehandle so it can unclude the scalars, i.e verbosity levels (set from config file)


tcp_callback => sub {
  my ($npe, $ether, $ip, $tcp, $header ) = @_;
  my $xmit = localtime( $header->{tv_sec} );

  print "$xmit TCP: $ip->{src_ip}:$tcp->{src_port}"
  . " -> $ip->{dest_ip}:$tcp->{dest_port}\n";

  open(my $FH, '>>', "capture") or die $!;
  print $FH "$xmit TCP: $ip->{src_ip}:$tcp->{src_port}"
  . " -> $ip->{dest_ip}:$tcp->{dest_port}\n";
  close($FH);
},


udp_callback => sub {
  my ($npe, $ether, $ip, $udp, $header ) = @_;
  my $xmit = localtime( $header->{tv_sec} );

  print "$xmit UDP: $ip->{src_ip}:$udp->{src_port}"
  . " -> $ip->{dest_ip}:$udp->{dest_port}\n";


  open(my $FH, '>>', "capture") or die $!;
  print $FH "$xmit UDP: $ip->{src_ip}:$udp->{src_port}"
  . " -> $ip->{dest_ip}:$udp->{dest_port}\n";
  close($FH);
},
icmp_callback => sub {
  my ($npe, $ether, $ip, $icmp, $header ) = @_;
  my $xmit = localtime( $header->{tv_sec} );

  print "$xmit ICMP: $ether->{src_mac}:$ip->{src_ip}"
  . " -> $ether->{dest_mac}:$ip->{dest_ip}\n";

  open(my $FH, '>>', "capture") or die $!;
  print "$xmit ICMP: $ether->{src_mac}:$ip->{src_ip}"
  . " -> $ether->{dest_mac}:$ip->{dest_ip}\n";
  close($FH);
},


igmp_callback => sub {
  my ($npe, $ether, $ip, $igmp, $header ) = @_;
  my $xmit = localtime( $header->{tv_sec} );

  print "$xmit IGMP: $ether->{src_mac}:$ip->{src_ip}"
  . " -> $ether->{dest_mac}:$ip->{dest_ip}\n";

  open(my $FH, '>>', "capture") or die $!;
  print "$xmit IGMP: $ether->{src_mac}:$ip->{src_ip}"
  . " -> $ether->{dest_mac}:$ip->{dest_ip}\n";
  close($FH);
},






);

print "beginning packet capture
Device: $npe->{dev}\n";

while (1) {
        $npe->loop;
 }
