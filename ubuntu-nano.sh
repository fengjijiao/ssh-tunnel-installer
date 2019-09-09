#!/bin/bash
clear
echo "====================================================="
echo "            Auto Insstaller Tunneling"
echo "SSH- SSL - Squid - Shadowsocks - UDPGW"
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
cat > /etc/banner.txt <<-END
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
sed -i 's/DROPBEAR_BANNER=""/DROPBEAR_BANNER="\/etc\/banner.txt"/g' /etc/default/dropbear
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
http_port 3128
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


# Update system repositories
apt update && apt upgrade -yuf
apt install -y --no-install-recommends gettext build-essential autoconf libtool libpcre3-dev \
                                       asciidoc xmlto libev-dev libudns-dev automake libmbedtls-dev \
                                       libsodium-dev git python-m2crypto libc-ares-dev
# download the Shadowsocks Git module
cd /opt
git clone https://github.com/shadowsocks/shadowsocks-libev.git
cd shadowsocks-libev
git submodule update --init --recursive
# Install Shadowsocks-libev
./autogen.sh
./configure
make && make install
# Create a new system user for Shadowsocks
adduser --system --no-create-home --group shadowsocks
# Create a new directory for the configuration file
mkdir -m 755 /etc/shadowsocks
# Create the Shadowsocks config
cat >> /etc/shadowsocks/shadowsocks.json <<-END
{
    "server":"0.0.0.0",
    "server_port":8388,
    "password":"freeguest",
    "timeout":300,
    "method":"aes-256-cfb",
    "fast_open": true
}
END
# Optimize Shadowsocks
cat >> /etc/sysctl.d/local.conf <<-END
# max open files
fs.file-max = 51200
# max read buffer
net.core.rmem_max = 67108864
# max write buffer
net.core.wmem_max = 67108864
# default read buffer
net.core.rmem_default = 65536
# default write buffer
net.core.wmem_default = 65536
# max processor input queue
net.core.netdev_max_backlog = 4096
# max backlog
net.core.somaxconn = 4096
# resist SYN flood attacks
net.ipv4.tcp_syncookies = 1
# reuse timewait sockets when safe
net.ipv4.tcp_tw_reuse = 1
# turn off fast timewait sockets recycling
net.ipv4.tcp_tw_recycle = 0
# short FIN timeout
net.ipv4.tcp_fin_timeout = 30
# short keepalive time
net.ipv4.tcp_keepalive_time = 1200
# outbound port range
net.ipv4.ip_local_port_range = 10000 65000
# max SYN backlog
net.ipv4.tcp_max_syn_backlog = 4096
# max timewait sockets held by system simultaneously
net.ipv4.tcp_max_tw_buckets = 5000
# turn on TCP Fast Open on both client and server side
net.ipv4.tcp_fastopen = 3
# TCP receive buffer
net.ipv4.tcp_rmem = 4096 87380 67108864
# TCP write buffer
net.ipv4.tcp_wmem = 4096 65536 67108864
# turn on path MTU discovery
net.ipv4.tcp_mtu_probing = 1
# for high-latency network
#net.ipv4.tcp_congestion_control = hybla
# for low-latency network, use cubic instead
net.ipv4.tcp_congestion_control = cubic
END
# Apply optimizations
sysctl --system
# Create a Shadowsocks Systemd Service
cat >> /etc/systemd/system/shadowsocks.service <<-END
[Unit]
Description=Shadowsocks proxy server

[Service]
User=root
Group=root
Type=simple
ExecStart=/usr/local/bin/ss-server -c /etc/shadowsocks/shadowsocks.json -a shadowsocks -v start
ExecStop=/usr/local/bin/ss-server -c /etc/shadowsocks/shadowsocks.json -a shadowsocks -v stop

[Install]
WantedBy=multi-user.target
END
# Enable and start
systemctl daemon-reload
systemctl enable shadowsocks
systemctl start shadowsocks

echo "--------------------------------"
echo "Shadowsocks Installed..."
echo "--------------------------------"
sleep 5

#install webmin
#cat >> /etc/apt/sources.list <<-END
#deb http://download.webmin.com/download/repository sarge contrib
#deb http://webmin.mirror.somersettechsolutions.co.uk/repository sarge contrib
#END

#wget -q http://www.webmin.com/jcameron-key.asc -O- | sudo apt-key add -
#apt-get update
#apt-get -y install webmin

#echo "--------------------------------"
#echo "Webmin Installed..."
#echo "--------------------------------"
#sleep 5

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
[squid]
accept = 8000
connect = 127.0.0.1:8080
[dropbear]
accept = 443
connect = 127.0.0.1:143
[openssh]
accept = 444
connect = 127.0.0.1:22
[shadowsocks]
accept = 8399
connect = 127.0.0.1:8388
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
echo "Installer Stunnel4 Berhasil"
echo "-----------------------------"
echo "OpenSSH             : 22"
echo "OpenSSH + SSL     : 444"
echo "Dropbear          : 80 / 143"
echo "Dropbear + SSL    : 443"
echo "Squid               : 3128 / 8080"
echo "Squid     + SSL     : 8000"
echo "Shadowsocks       : 8388"
echo "Shadowsocks + SSL : 8399"
#echo "webmin            : https://$ip:10000"
echo "-----------------------------"
