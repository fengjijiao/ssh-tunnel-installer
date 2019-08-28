clear
echo "Auto installer SSH,SSL,Squid,OpenVPN,UDPGW di ubuntu"
echo "Tunggu proses instalasi selesai"
sleep 5

# install wget, curl and nano
apt-get update
apt-get -y upgrade
apt-get -y install wget curl
apt-get -y install nano

#membuat banner
cat > /etc/issue.net <<-END
PREMIUM SSH SINGAPORE

TERMS OF SERVICE:
-NO SHARE ACCOUNT
-NO DDOS
-NO HACKING,CRACKING AND CARDING
-NO TORRENT
-NO SPAM
-NO PLAYSTATION SITE

THANKS.
END

#set banner openssh
sed -i 's/#Banner/Banner/g' /etc/ssh/sshd_config
service ssh restart

#install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=80/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 143"/g' /etc/default/dropbear
sed -i 's/DROPBEAR_BANNER=""/DROPBEAR_BANNER="\/etc\/issue.net"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
service dropbear restart

#instalasi squid3
apt-get install squid3 -y
mv /etc/squid3/squid.conf /etc/squid3/squid.conf.bak
ip=$(ifconfig | awk -F':' '/inet addr/&&!/127.0.0.1/&&!/127.0.0.2/{split($2,_," ");print _[1]}')
cat > /etc/squid3/squid.conf <<-END
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
http_port 8000
http_port 3128
coredump_dir /var/spool/squid3
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
visible_hostname globalssh.net
END

service squid3 restart

#install webmin
cat >> /etc/apt/sources.list <<-END
deb http://download.webmin.com/download/repository sarge contrib
deb http://webmin.mirror.somersettechsolutions.co.uk/repository sarge contrib
END

wget -q http://www.webmin.com/jcameron-key.asc -O- | sudo apt-key add -
apt-get update
apt-get -y install webmin

#informasi SSL
country=ID
state=JawaTengah
locality=Purwokerto
organization=GlobalSSH
organizationalunit=Provider
commanname=globalssh.net
email=admin@globalssh.net

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
accept = 8080
connect = $ip:8000
[dropbear]
accept = 443
connect = $ip:143
[openssh]
accept = 444
connect = $ip:22
END

#membuat sertifikat
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

#konfigurasi stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart

#informasi
clear
echo "---------- Informasi --------"
echo ""
echo "Installer Stunnel4 Berhasil"
echo ""
echo "OpenSSH	        : 22"
echo "OpenSSH + SSL   : 22"
echo "Dropbear        : 80 / 143"
echo "Dropbear + SSL  : 443"
echo "Squid	        : 3128"
echo "Squid	+ SSL   : 3128"
echo "webmin	: https://$ip:10000"
echo "-----------------------------"
