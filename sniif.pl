#!/usr/bin/perl
$|=1;
use strict;
use warnings;
use Data::Dumper;
use Net::Pcap::Easy;

#time to capture the settings from file
my $config_file = 'config';
my ($dev, $filter, $packets_per_loop, $bytes_to_capture, $promiscuous, $verbose, $logging);
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
    }
      }


  #bytes_to_capture
  if ($_ =~ m/^bytes_to_capture/) {
    #capture stuff after "="
    if (/=(\S+)/) {
      $bytes_to_capture = $1;
      print "bytes to capture count found: $bytes_to_capture\n";
    }
      }


  #promiscuous
  if ($_ =~ m/^promiscuous/) {
    #capture stuff after "="
    if (/=(\S+)/) {
      $promiscuous = $1;
      print "promiscuous mode found: $promiscuous\n";
    }
      }


  #verbose
  if ($_ =~ m/^verbose/) {
    #capture stuff after "="
    if (/=(\S+)/) {
      $verbose = $1;
      print "verbosity found: $verbose\n";
    }
      }

  #logging
  if ($_ =~ m/^logging/) {
    #capture stuff after "="
    if (/=(\S+)/) {
      $logging = $1;
      print "logging found: $logging\n";
    }
      }


}
close($config_fh);
#exit 0;

    if ($verbose eq "low" || $verbose eq "LOW") {
            if ($logging eq "yes" || $logging eq "YES") {
                print "\n\nwarning: low verbosity does not log much details\n";
                sleep 3;
        }}



#todo, can we dump to pcap format to open in wireshark?
#npe = net packet easy object, ether = ethernet object, ip = ip object, tcp = tcp object, header = header object

# all arguments to new are optional
my $npe = Net::Pcap::Easy->new(
        #todo, read ens3 from a config file
  dev              => $dev,
#todo, read filter from a config file, else dont cap port 22
  filter           => $filter,
  packets_per_loop => $packets_per_loop,
  bytes_to_capture => $bytes_to_capture,
  promiscuous      => $promiscuous, # true or false


tcp_callback => sub {
  my ($npe, $ether, $ip, $tcp, $header ) = @_;
  my $xmit = localtime( $header->{tv_sec} );

  print "$xmit TCP: $ip->{src_ip}:$tcp->{src_port}"
  . " -> $ip->{dest_ip}:$tcp->{dest_port}\n";

  if ($logging eq "yes" || $logging eq "YES") {
  open(my $FH, '>>', "capture") or die $!;
  print $FH "$xmit TCP: $ip->{src_ip}:$tcp->{src_port}"
  . " -> $ip->{dest_ip}:$tcp->{dest_port}\n";
  if ($verbose eq "high" || $verbose eq "HIGH") {
  open(my $FHHIGH, '>>', "capture.high") or die $!;
          print $FHHIGH Dumper($npe, $ether, $ip, $tcp, $header);
          print $FHHIGH "------------------------------\n";
  }
  #close($FH);
}
},


udp_callback => sub {
  my ($npe, $ether, $ip, $udp, $header ) = @_;
  my $xmit = localtime( $header->{tv_sec} );

  print "$xmit UDP: $ip->{src_ip}:$udp->{src_port}"
  . " -> $ip->{dest_ip}:$udp->{dest_port}\n";


  if ($logging eq "yes" || $logging eq "YES") {
  open(my $FH, '>>', "capture") or die $!;
  print $FH "$xmit UDP: $ip->{src_ip}:$udp->{src_port}"
  . " -> $ip->{dest_ip}:$udp->{dest_port}\n";
  if ($verbose eq "high" || $verbose eq "HIGH") {
  open(my $FHHIGH, '>>', "capture.high") or die $!;
          print $FHHIGH Dumper($npe, $ether, $ip, $udp, $header);
          print $FHHIGH "------------------------------\n";
  }
  #close($FH);
  }
},

icmp_callback => sub {
  my ($npe, $ether, $ip, $icmp, $header ) = @_;
  my $xmit = localtime( $header->{tv_sec} );

  print "$xmit ICMP: $ether->{src_mac}:$ip->{src_ip}"
  . " -> $ether->{dest_mac}:$ip->{dest_ip}\n";

  if ($logging eq "yes" || $logging eq "YES") {
  open(my $FH, '>>', "capture") or die $!;
  print "$xmit ICMP: $ether->{src_mac}:$ip->{src_ip}"
  . " -> $ether->{dest_mac}:$ip->{dest_ip}\n";
  if ($verbose eq "high" || $verbose eq "HIGH") {
  open(my $FHHIGH, '>>', "capture.high") or die $!;
          print $FHHIGH Dumper($npe, $ether, $ip, $icmp, $header);
          print $FHHIGH "------------------------------\n";
  }
  #close($FH);
  }
},

igmp_callback => sub {
  my ($npe, $ether, $ip, $igmp, $header ) = @_;
  my $xmit = localtime( $header->{tv_sec} );

  print "$xmit IGMP: $ether->{src_mac}:$ip->{src_ip}"
  . " -> $ether->{dest_mac}:$ip->{dest_ip}\n";

  if ($logging eq "yes" || $logging eq "YES") {
  open(my $FH, '>>', "capture") or die $!;
  print "$xmit IGMP: $ether->{src_mac}:$ip->{src_ip}"
  . " -> $ether->{dest_mac}:$ip->{dest_ip}\n";
  if ($verbose eq "high" || $verbose eq "HIGH") {
  open(my $FHHIGH, '>>', "capture.high") or die $!;
          print $FHHIGH Dumper($npe, $ether, $ip, $igmp, $header);
          print $FHHIGH "------------------------------\n";
  }
  #close($FH);
  }
},






);

print "beginning packet capture
Device: $npe->{dev}\n";

while (1) {
        $npe->loop;
 }
