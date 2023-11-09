#!/usr/bin/perl
use strict;
use warnings;
use Net::Pcap::Easy;

# all arguments to new are optoinal
my $npe = Net::Pcap::Easy->new(
    dev              => "ens3",
    filter           => "not port 22",
    packets_per_loop => 10,
    bytes_to_capture => 1024,
    promiscuous      => 0, # true or false

    tcp_callback => sub {
        my ($npe, $ether, $ip, $tcp, $header ) = @_;
        my $xmit = localtime( $header->{tv_sec} );

        print "$xmit TCP: $ip->{src_ip}:$tcp->{src_port}"
         . " -> $ip->{dest_ip}:$tcp->{dest_port}\n";

    ,

    icmp_callback => sub {
        my ($npe, $ether, $ip, $icmp, $header ) = @_;
        my $xmit = localtime( $header->{tv_sec} );

        print "$xmit ICMP: $ether->{src_mac}:$ip->{src_ip}"
         . " -> $ether->{dest_mac}:$ip->{dest_ip}\n";
    },
);

 while (1) {
         $npe->loop;
 }
