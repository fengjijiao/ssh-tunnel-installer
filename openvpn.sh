#install vpn
apt-get -y install openvpn easy-rsa
cat > /etc/openvpn/server.conf <<-END
port 1194
proto tcp
dev tun
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
plugin /etc/openvpn/openvpn-plugin-auth-pam.so /etc/pam.d/login
client-cert-not-required
username-as-common-name
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
push "route-method exe"
push "route-delay 2"
keepalive 5 30
cipher AES-128-CBC
comp-lzo
persist-key
persist-tun
status server-vpn.log
verb 3
END
cp -r /usr/share/easy-rsa/ /etc/openvpn
mkdir /etc/openvpn/easy-rsa/keys
wget -O /etc/openvpn/easy-rsa/vars "https://github.com/malikshi/elora/raw/master/vars"
openssl dhparam -out /etc/openvpn/dh2048.pem 2048
cd /etc/openvpn/easy-rsa
. ./vars
./clean-all
# Buat Sertifikat
export EASY_RSA="${EASY_RSA:-.}"
"$EASY_RSA/pkitool" --initca $*
# buat key server
export EASY_RSA="${EASY_RSA:-.}"
"$EASY_RSA/pkitool" --server server
# seting KEY CN
export EASY_RSA="${EASY_RSA:-.}"
"$EASY_RSA/pkitool" client
#copy to openvpn folder
cp /etc/openvpn/easy-rsa/keys/{server.crt,server.key,ca.crt} /etc/openvpn
ls /etc/openvpn
sed -i 's/#AUTOSTART="all"/AUTOSTART="all"/g' /etc/default/openvpn
service openvpn restart
ip=$(ifconfig | awk -F':' '/inet addr/&&!/127.0.0.1/&&!/127.0.0.2/{split($2,_," ");print _[1]}')
cat > /etc/openvpn/globalssh.ovpn <<-END
# OpenVPN Configuration GlobalSSH Server
# (Official @www.globalssh.net & www.readyssh.com)
client
dev tun
proto tcp
#for tcp 1194
remote $ip 1194
#for tcp ssl 1195
#remote $ip 1195
resolv-retry infinite
route-method exe
resolv-retry infinite
cipher AES-128-CBC
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3
END
echo '<ca>' >> /etc/openvpn/globalssh.ovpn
cat /etc/openvpn/ca.crt >> /etc/openvpn/globalssh.ovpn
echo '</ca>' >> /etc/openvpn/globalssh.ovpn
sed -i $ip /etc/openvpn/globalssh.ovpn
cp /usr/lib/openvpn/openvpn-plugin-auth-pam.so /etc/openvpn/

#set iptables openvz
#iptables -t nat -I POSTROUTING -s 10.8.0.0/24 -o venet0 -j MASQUERADE
#iptables -t nat -I POSTROUTING -s 10.9.0.0/24 -o venet0 -j MASQUERADE
#iptables -t nat -I POSTROUTING -s 10.10.0.0/24 -o venet0 -j MASQUERADE
#set iptables kvm
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE

#allow forwarding
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf

service openvpn restart
