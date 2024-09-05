CWD=$(pwd)
dnf install -y perl
dnf install -y perl-Net-Pcap
dnf install -y wget
dnf install -y perl-ExtUtils-MakeMaker
dnf install -y perl-Net-Netmask

cd /usr/local/src/
wget https://cpan.metacpan.org/authors/id/J/JE/JETTERO/Net-Pcap-Easy-1.4210.tar.gz
tar xvf Net-Pcap-Easy-1.4210.tar.gz
rm -f Net-Pcap-Easy-1.4210.tar.gz

cd Net-Pcap-Easy-1.4210/
perl Makefile.PL
make
make install

cd ..
wget https://cpan.metacpan.org/authors/id/Y/YA/YANICK/NetPacket-1.7.2.tar.gz
tar xf NetPacket-1.7.2.tar.gz
rm -f NetPacket-1.7.2.tar.gz

cd NetPacket-1.7.2/
perl Makefile.PL
make
make install

#cd ..
mkdir -p /etc/traffictracker/
cp $CWD/* /etc/traffictracker/

ln -s /etc/traffictracker/monitor.pm /usr/local/sbin/monitor
chmod +x /usr/local/sbin/monitor

echo "finished, use monitor to start the program, files are under /etc/traffictracker"
