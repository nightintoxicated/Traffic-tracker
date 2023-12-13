#!/usr/bin/perl
$|=1;
use strict;
use Socket;
use warnings;
use Data::Dumper;
use Net::Pcap::Easy;

#npe = net packet easy object
#ether = ethernet object, the ip = ip object, etc

#---------------
#BEGIN capture settings from file
my $config_file = '/etc/traffictracker/config';
my ($dev, $filter, $packets_per_loop, $bytes_to_capture, $promiscuous, $verbose, $logging, $intruder);
my (@tcp_array, @udp_array, @icmp_array, @igmp_array);
open (my $config_fh, '<', $config_file) or die "cannot open configuration file: $config_file\n";

while (<$config_fh>) {

  #device
  if ($_ =~ m/^dev/) {
    #capture stuff after "="
    if (/=(\S+)/) {
      $dev = $1;
      print "Device found: $dev\n";
    }}

  #filter
  if ($_ =~ m/^filter/) {
    if (/=(.+)/) {
      $filter = $1;
      print "filter found: $filter\n";
    }}

  #packets_per_loop
  if ($_ =~ m/^packets_per_loop/) {
    if (/=(\S+)/) {
      $packets_per_loop = $1;
      print "packets per loop count found: $packets_per_loop\n";
    }}

  #bytes_to_capture
  if ($_ =~ m/^bytes_to_capture/) {
    if (/=(\S+)/) {
      $bytes_to_capture = $1;
      print "bytes to capture count found: $bytes_to_capture\n";
    }}

  #promiscuous
  if ($_ =~ m/^promiscuous/) {
    if (/=(\S+)/) {
      $promiscuous = $1;
      print "promiscuous mode found: $promiscuous\n";
    }}

  #verbose
  if ($_ =~ m/^verbose/) {
    if (/=(\S+)/) {
      $verbose = $1;
      print "verbosity found: $verbose\n";
    }}

  #logging
  if ($_ =~ m/^logging/) {
    if (/=(\S+)/) {
      $logging = $1;
      print "logging found: $logging\n";
    }}


  #intruder mode
  if ($_ =~ m/^intruder/) {
    if (/=(\S+)/) {
      $intruder = $1;
      print "intruder mode found: $intruder\n";
    }}



}
close($config_fh);
#END capture settings from file
#---------------
  if ($verbose eq "low" || $verbose eq "LOW") {
    if ($logging eq "yes" || $logging eq "YES") {
    print "\n\nWarning: low verbosity does not log much details\n";
    sleep 3;
  }}
#---------------
#setup and subroutines

my $npe = Net::Pcap::Easy->new(
  dev              => $dev,
  filter           => $filter,
  packets_per_loop => $packets_per_loop,
  bytes_to_capture => $bytes_to_capture,
  promiscuous      => $promiscuous,


#tcp packets
tcp_callback => sub {
  my ($npe, $ether, $ip, $tcp, $header ) = @_;
  my $datetime = localtime( $header->{tv_sec} );


## intruder mode start
 if ($intruder eq "yes" || $intruder eq "YES") {
   my $entry = "$ip->{src_ip}:$tcp->{src_port}" 
  . " -> $ip->{dest_ip}:$tcp->{dest_port}\n";

  my $found_duplicate = 0;
    foreach my $item (@tcp_array) {
      if ($item eq $entry) {
        $found_duplicate = 1;
	last;
      }}

      if ($found_duplicate == 0 ) {
        print "====TCP unique entry==== $entry";
	 push(@tcp_array, $entry);
      }}

## intruder mode end


 if ($intruder ne "yes" && $intruder ne "YES") {
  print "$datetime TCP: $ip->{src_ip}:$tcp->{src_port}" 
  . " -> $ip->{dest_ip}:$tcp->{dest_port}\n";
 }


  if ($logging eq "yes" || $logging eq "YES") {
    open(my $FH, '>>', "capture") or die $!;
    print $FH "$datetime TCP: $ip->{src_ip}:$tcp->{src_port}" 
    . " -> $ip->{dest_ip}:$tcp->{dest_port}\n";
    if ($verbose eq "high" || $verbose eq "HIGH") {
      open(my $FHHIGH, '>>', "capture.high") or die $!;
      print $FHHIGH "TCP Packet\n";
      
      print $FHHIGH "Source: ", $ip->{src_ip}, ":";
      print $FHHIGH $tcp->{src_port}, "\n";

      print $FHHIGH "Destination ", $ip->{dest_ip}, ":";
      print $FHHIGH $tcp->{dest_port}, "\n";

      print $FHHIGH "Data: ", $tcp->{data}, "\n";
      print $FHHIGH "Sequence: " . $tcp->{seqnum}, "\n";
      #print $FHHIGH Dumper($npe, $ether, $ip, $tcp, $header);
      print $FHHIGH "----------------------------\n";
    }
  #close($FH);
  }
},

#udp packets
udp_callback => sub {
  my ($npe, $ether, $ip, $udp, $header ) = @_;
  my $datetime = localtime( $header->{tv_sec} );
  
  
  
## intruder mode start
 if ($intruder eq "yes" || $intruder eq "YES") {
   my $entry = "$ip->{src_ip}:$udp->{src_port}" 
  . " -> $ip->{dest_ip}:$udp->{dest_port}\n";

  my $found_duplicate = 0;
    foreach my $item (@udp_array) {
      if ($item eq $entry) {
        $found_duplicate = 1;
	last;
      }}

      if ($found_duplicate == 0 ) {
        print "====UDP unique entry==== $entry\n";
	 push(@udp_array, $entry);
      }}

## intruder mode end
  
  
 if ($intruder ne "yes" && $intruder ne "YES") {
  print "$datetime UDP: $ip->{src_ip}:$udp->{src_port}"
  . " -> $ip->{dest_ip}:$udp->{dest_port}\n";
  }


  if ($logging eq "yes" || $logging eq "YES") {
    open(my $FH, '>>', "capture") or die $!;
    print $FH "$datetime UDP: $ip->{src_ip}:$udp->{src_port}"
    . " -> $ip->{dest_ip}:$udp->{dest_port}\n";
    if ($verbose eq "high" || $verbose eq "HIGH") {
      open(my $FHHIGH, '>>', "capture.high") or die $!;
      print $FHHIGH "UDP Packet\n";
      
      print $FHHIGH "Source: ", $ip->{src_ip}, ":";
      print $FHHIGH $udp->{src_port}, "\n";

      print $FHHIGH "Destination ", $ip->{dest_ip}, ":";
      print $FHHIGH $udp->{dest_port}, "\n";

      print $FHHIGH "Data: ", $udp->{data}, "\n";
      #print $FHHIGH Dumper($npe, $ether, $ip, $udp, $header);
      print $FHHIGH "UDP ------------------------------\n";
    }
  #close($FH);
  }
},

#icmp packets
icmp_callback => sub {
  my ($npe, $ether, $ip, $icmp, $header ) = @_;
  my $datetime = localtime( $header->{tv_sec} );



## intruder mode start
 if ($intruder eq "yes" || $intruder eq "YES") {
   my $entry = "$ip->{src_ip}:" 
  . " -> $ip->{dest_ip}:$ip->{data}\n";

  my $found_duplicate = 0;
    foreach my $item (@icmp_array) {
      if ($item eq $entry) {
        $found_duplicate = 1;
	last;
      }}

      if ($found_duplicate == 0 ) {
        print "====ICMP unique entry==== $entry\n";

	 push(@icmp_array, $entry);
      }}

## intruder mode end
  
  
  if ($intruder ne "yes" && $intruder ne "YES") {
  print "$datetime ICMP: $ether->{src_mac}:$ip->{src_ip}"
  . " -> $ether->{dest_mac}:$ip->{dest_ip}\n";
}

  if ($logging eq "yes" || $logging eq "YES") {
    open(my $FH, '>>', "capture") or die $!;
    print "$datetime ICMP: $ether->{src_mac}:$ip->{src_ip}"
    . " -> $ether->{dest_mac}:$ip->{dest_ip}\n";
    if ($verbose eq "high" || $verbose eq "HIGH") {
      open(my $FHHIGH, '>>', "capture.high") or die $!;
      print $FHHIGH "ICMP Packet\n";
      
      print $FHHIGH "Source: ", $ip->{src_ip}, "\n";
      print $FHHIGH "Destination ", $ip->{dest_ip}, "\n";
      print $FHHIGH "Data: ", $ip->{data}, "\n";

      #print $FHHIGH Dumper($npe, $ether, $ip, $udp, $header);
      print $FHHIGH "ICMP ------------------------------\n";
    }
  #close($FH);
  }
},

#igmp packets
igmp_callback => sub {
  my ($npe, $ether, $ip, $igmp, $header ) = @_;
  my $datetime = localtime( $header->{tv_sec} );


## intruder mode start
 if ($intruder eq "yes" || $intruder eq "YES") {
   my $entry = "$ip->{src_ip}:" 
  . " -> $ip->{dest_ip}:$ip->{data}\n";

  my $found_duplicate = 0;
    foreach my $item (@igmp_array) {
      if ($item eq $entry) {
        $found_duplicate = 1;
	last;
      }}

      if ($found_duplicate == 0 ) {
        print "====IGMP unique entry==== $entry\n";
	 push(@igmp_array, $entry);
      }}

## intruder mode end
  
  
  if ($intruder ne "yes" && $intruder ne "YES") {
  print "$datetime IGMP: $ether->{src_mac}:$ip->{src_ip}"
  . " -> $ether->{dest_mac}:$ip->{dest_ip}\n";
 } 

  if ($logging eq "yes" || $logging eq "YES") {
    open(my $FH, '>>', "capture") or die $!;
    print "$datetime IGMP: $ether->{src_mac}:$ip->{src_ip}"
    . " -> $ether->{dest_mac}:$ip->{dest_ip}\n";
    if ($verbose eq "high" || $verbose eq "HIGH") {
      open(my $FHHIGH, '>>', "capture.high") or die $!;
      print $FHHIGH "IGMP Packet\n";
      
      print $FHHIGH "Source: ", $ip->{src_ip}, "\n";
      print $FHHIGH "Destination ", $ip->{dest_ip}, "\n";
      print $FHHIGH "Data: ", $ip->{data}, "\n";

      #print $FHHIGH Dumper($npe, $ether, $ip, $igmp, $header);
      print $FHHIGH "IGMP ------------------------------\n";
    }
  #close($FH);
  }
},

);
#---------------


#main() is here
print "beginning packet capture
Device: $npe->{dev}\n";

while (1) {
	$npe->loop;
 }

##EOF
