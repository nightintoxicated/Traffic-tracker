cd /usr/local/src/
dnf install -y perl
dnf install -y perl-Net-Pcap
dnf install -y wget
wget https://cpan.metacpan.org/authors/id/J/JE/JETTERO/Net-Pcap-Easy-1.4210.tar.gz
tar xvf Net-Pcap-Easy-1.4210.tar.gz
rm Net-Pcap-Easy-1.4210.tar.gz
cd Net-Pcap-Easy-1.4210/

dnf install -y perl-ExtUtils-MakeMaker
perl Makefile.PL
make
make install
dnf install -y perl-Net-Netmask

cd ..
wget https://cpan.metacpan.org/authors/id/Y/YA/YANICK/NetPacket-1.7.2.tar.gz
tar xf NetPacket-1.7.2.tar.gz

rm NetPacket-1.7.2.tar.gz

cd NetPacket-1.7.2/
perl Makefile.PL
make
make install

cd ..
