clear
echo "====================================================="
echo "            Auto Insstaller Tunneling"
echo "SSH- SSL - Squid - UDPGW"
echo "                  Ubuntu OS"
echo "====================================================="
echo "              Quick install script"
echo "====================================================="



sleep 5

# install wget, curl and nano
apt-get update
apt-get -y upgrade
apt-get -y install wget curl
apt-get -y install nano

#membuat banner
cat > /etc/issue.net <<-END
PREMIUM SSH  \n
TERMS OF SERVICE:  \n
-NO SHARE ACCOUNT  \n
-NO DDOS  \n
-NO HACKING,CRACKING AND CARDING  \n
-NO TORRENT  \n
-NO SPAM  \n
-NO PLAYSTATION SITE  \n
THANKS.
END

#set banner openssh
sed -i 's/#Banner/Banner/g' /etc/ssh/sshd_config
service ssh restart

sleep 5

#install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=80/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 143"/g' /etc/default/dropbear
sed -i 's/DROPBEAR_BANNER=""/DROPBEAR_BANNER="\/etc\/issue.net"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
service dropbear restart

echo "--------------------------------"
echo "Dropbear Installed..."
echo "--------------------------------"

sleep 5

#instalasi squid
apt-get install squid -y
mv /etc/squid/squid.conf /etc/squid/squid.conf.bak
#ip=$(ifconfig | awk -F':' '/inet addr/&&!/127.0.0.1/&&!/127.0.0.2/{split($2,_," ");print _[1]}')
ip=$(curl "https://api.ipify.org")
cat > /etc/squid/squid.conf <<-END
acl SSL_ports port 443
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 22
acl Safe_ports port 80
acl Safe_ports port 143
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
acl SSH dst $ip/32
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 8080
coredump_dir /var/spool/squid
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
reply_header_access X-Squid-Error deny all
reply_header_access Server deny all
reply_header_access Via deny all
reply_header_access X-Cache-Lookup deny all
reply_header_access X-Cache deny all
reply_header_access Vary deny all
reply_header_access Mime-Version deny all
via off
forwarded_for off
follow_x_forwarded_for deny all
request_header_access X-Forwarded-For deny all
visible_hostname Via
httpd_suppress_version_string on
END

service squid restart

echo "--------------------------------"
echo "Squid Installed..."
echo "--------------------------------"
sleep 5

#informasi SSL
country=US
state=NewYork
locality=Purwokerto
organization=QWCLOUD
organizationalunit=QWCLOUD
commanname=qwcloud.com
email=sales@qwcloud.com

#update repository
apt-get install stunnel4 -y
cat > /etc/stunnel/stunnel.conf <<-END
pid = /var/run/stunnel4.pid
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
[dropbear]
accept = 443
connect = 127.0.0.1:143
END

#membuat sertifikat
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

#konfigurasi stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart

echo "--------------------------------"
echo "Stunnel Installed..."
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
echo -e "\033[1;32mBadvpn installed\033[0m"
rm -rf easyinstall >/dev/null 2>/dev/null
exit
else
#
fi
echo "Installing Badvpn"
echo "download do Badvpn"
wget -O /usr/bin/badvpn-udpgw https://github.com/CLOUDSERVERS/badvpn/blob/master/badvpn-udpgw?raw=true -o /dev/null
chmod +x /usr/bin/badvpn-udpgw
echo "Install completed" 
echo "badvpn stop/start"
rm -rf easyinstall >/dev/null 2>/dev/null
sleep 5s
badvpn start
echo "--------------------------------"
echo "UDPGW Installed..."
echo "--------------------------------"
sleep 3s

#informasi
clear
echo "---------- Informasi --------"
echo "Installer Stunnel4 Berhasil"
echo "-----------------------------"
echo "OpenSSH             : 22"
echo "Dropbear          : 80 / 143"
echo "Dropbear + SSL    : 443"
echo "Squid               : 8080"
echo "-----------------------------"
