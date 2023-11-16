#!/usr/bin/perl
$|=1;
use strict;
use warnings;
use Data::Dumper;
use Net::Pcap::Easy;



#todo, can we dump to pcap format to open in wireshark?
#npe = net packet easy object, ether = ethernet object, ip = ip object, tcp = tcp object, header = header object

# all arguments to new are optional
my $npe = Net::Pcap::Easy->new(
        #todo, read ens3 from a config file
  dev              => "ens3",
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
