#!/bin/bash
clear
echo "====================================================="
echo "            Auto Insstaller Tunneling"
echo "Mproxy - UDPGW"
echo "                  Ubuntu OS"
echo "====================================================="
echo "         Quick install script"
echo "====================================================="



sleep 5

# install wget, curl and nano
apt-get update
apt-get -y upgrade
apt-get -y install wget curl
apt-get -y install nano

echo "Installing mproxy"
wget -O /usr/bin/mproxy-cli https://github.com/CLOUDSERVERS/mproxy-mod/blob/mproxy-mod/mproxy?raw=true
chmod +x /usr/bin/mproxy-cli
echo "#!/bin/bash
if [ "'$1'" == start ]
then
mproxy-cli -l 80 -m Lbxx: -r 127.0.0.1:22 > /dev/null &
echo 'mproxy started'
fi
if [ "'$1'" == stop ]
then
mproxypid="'$(ps x |grep mproxy |grep -v grep |awk '"{'"'print $1'"'})
kill -9 "'"$mproxypid" >/dev/null 2>/dev/null
kill $mproxypid > /dev/null 2> /dev/null
kill "$mproxypid" > /dev/null 2>/dev/null''
kill $(ps x |grep mproxy |grep -v grep |awk '"{'"'print $1'"'})
killall mproxy-cli
fi" > /bin/mproxy
chmod +x /bin/mproxy
echo "Install completed" 
echo "usage: mproxy stop/start"
sleep 5s
mproxy start
echo "--------------------------------"
echo "Mproxy Installed..."
echo "--------------------------------"
sleep 5

#install badvpn-udpgw
echo "#!/bin/bash
if [ "'$1'" == start ]
then
badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10 > /dev/null &
echo 'Badvpn rodando na porta 7300'
fi
if [ "'$1'" == stop ]
then
badvpnpid="'$(ps x |grep badvpn |grep -v grep |awk '"{'"'print $1'"'})
kill -9 "'"$badvpnpid" >/dev/null 2>/dev/null
kill $badvpnpid > /dev/null 2> /dev/null
kill "$badvpnpid" > /dev/null 2>/dev/null''
kill $(ps x |grep badvpn |grep -v grep |awk '"{'"'print $1'"'})
killall badvpn-udpgw
fi" > /bin/badvpn
chmod +x /bin/badvpn
if [ -f /usr/bin/badvpn-udpgw ]; then
echo -e "Badvpn installed"
exit
else
#
fi
echo "Installing Badvpn"
echo "download do Badvpn"
wget -O /usr/bin/badvpn-udpgw https://github.com/CLOUDSERVERS/badvpn/blob/master/badvpn-udpgw?raw=true -o /dev/null
chmod +x /usr/bin/badvpn-udpgw
echo "Install completed" 
echo "usage: badvpn stop/start"
sleep 5s
badvpn start
echo "--------------------------------"
echo "UDPGW Installed..."
echo "--------------------------------"
sleep 3s

#informasi
clear
echo "---------- Informasi --------"
echo "-----------------------------"
echo "Mproxy          : 80"
echo "-----------------------------"
