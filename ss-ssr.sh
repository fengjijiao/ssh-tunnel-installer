#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#=================================================
#	System Required: CentOS 6+/Debian 6+/Ubuntu 14.04+
#	Description: Install the ShadowsocksR mudbjson server
#	Version: 1.0.26
#	Author: Toyo
#	Blog: https://doub.io/ss-jc60/
#=================================================

sh_ver="1.0.26"
filepath=$(cd "$(dirname "$0")"; pwd)
file=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')
ssr_folder="/usr/local/shadowsocksr"
config_file="${ssr_folder}/config.json"
config_user_file="${ssr_folder}/user-config.json"
config_user_api_file="${ssr_folder}/userapiconfig.py"
config_user_mudb_file="${ssr_folder}/mudb.json"
ssr_log_file="${ssr_folder}/ssserver.log"
Libsodiumr_file="/usr/local/lib/libsodium.so"
Libsodiumr_ver_backup="1.0.15"
Server_Speeder_file="/serverspeeder/bin/serverSpeeder.sh"
LotServer_file="/appex/bin/serverSpeeder.sh"
BBR_file="${file}/bbr.sh"
jq_file="${ssr_folder}/jq"

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[Informasi]${Font_color_suffix}"
Error="${Red_font_prefix}[Error]${Font_color_suffix}"
Tip="${Green_font_prefix}[Tips]${Font_color_suffix}"
Separator_1="——————————————————————————————"

check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} akun bukan ROOT (Tidak ada izin ROOT)，tidak dapat melanjutkan，silahkan gunakan${Green_background_prefix} sudo su ${Font_color_suffix}Untuk memperoleh izin root sementara (Anda akan diminta memasukan kata sandi untuk ROOT)" && exit 1
}
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
	bit=`uname -m`
}
check_pid(){
	PID=`ps -ef |grep -v grep | grep server.py |awk '{print $2}'`
}
check_crontab(){
	[[ ! -e "/usr/bin/crontab" ]] && echo -e "${Error} Kurangnya ketergantungan pada Crontab, coba instal CentOS secara manual: yum install crond -y, Debian / Ubuntu: apt-get install cron -y!" && exit 1
}
SSR_installation_status(){
	[[ ! -e ${ssr_folder} ]] && echo -e "${Error} Tidak Ditemukan ShadowsocksR harap periksa folder !" && exit 1
}
Server_Speeder_installation_status(){
	[[ ! -e ${Server_Speeder_file} ]] && echo -e "${Error} Tidak Terpasang Kecepatan tajam(Server Speeder)，Silakan periksa !" && exit 1
}
LotServer_installation_status(){
	[[ ! -e ${LotServer_file} ]] && echo -e "${Error} Tidak Terpasang LotServer，Silakan periksa !" && exit 1
}
BBR_installation_status(){
	if [[ ! -e ${BBR_file} ]]; then
		echo -e "${Error} Tidak Ditemukan Script BBR, mulai mengunduh..."
		cd "${file}"
		if ! wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/bbr.sh; then
			echo -e "${Error} BBR Unduhan skrip gagal !" && exit 1
		else
			echo -e "${Info} BBR Pengunduhan skrip selesai !"
			chmod +x bbr.sh
		fi
	fi
}
# Set Firewall
Add_iptables(){
	if [[ ! -z "${ssr_port}" ]]; then
		iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
		iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
	fi
}
Del_iptables(){
	if [[ ! -z "${port}" ]]; then
		iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
	fi
}
Save_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
	fi
}
Set_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
		chkconfig --level 2345 iptables on
		chkconfig --level 2345 ip6tables on
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
		echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules' > /etc/network/if-pre-up.d/iptables
		chmod +x /etc/network/if-pre-up.d/iptables
	fi
}
# informasi konfigurasi
Get_IP(){
	ip=$(wget -qO- -t1 -T2 ipinfo.io/ip)
	if [[ -z "${ip}" ]]; then
		ip=$(wget -qO- -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ip}" ]]; then
			ip=$(wget -qO- -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ip}" ]]; then
				ip="VPS_IP"
			fi
		fi
	fi
}
Get_User_info(){
	Get_user_port=$1
	user_info_get=$(python mujson_mgr.py -l -p "${Get_user_port}")
	match_info=$(echo "${user_info_get}"|grep -w "### user ")
	if [[ -z "${match_info}" ]]; then
		echo -e "${Error} Akuisisi informasi pengguna gagal ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	fi
	user_name=$(echo "${user_info_get}"|grep -w "user :"|awk -F "user : " '{print $NF}')
	port=$(echo "${user_info_get}"|grep -w "port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	password=$(echo "${user_info_get}"|grep -w "passwd :"|awk -F "passwd : " '{print $NF}')
	method=$(echo "${user_info_get}"|grep -w "method :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol=$(echo "${user_info_get}"|grep -w "protocol :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol_param=$(echo "${user_info_get}"|grep -w "protocol_param :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	[[ -z ${protocol_param} ]] && protocol_param="0(unlimited)"
	obfs=$(echo "${user_info_get}"|grep -w "obfs :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	#transfer_enable=$(echo "${user_info_get}"|grep -w "transfer_enable :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}'|awk -F "ytes" '{print $1}'|sed 's/KB/ KB/;s/MB/ MB/;s/GB/ GB/;s/TB/ TB/;s/PB/ PB/')
	#u=$(echo "${user_info_get}"|grep -w "u :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	#d=$(echo "${user_info_get}"|grep -w "d :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	forbidden_port=$(echo "${user_info_get}"|grep -w "forbidden_port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	[[ -z ${forbidden_port} ]] && forbidden_port="Unlimited"
	speed_limit_per_con=$(echo "${user_info_get}"|grep -w "speed_limit_per_con :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	speed_limit_per_user=$(echo "${user_info_get}"|grep -w "speed_limit_per_user :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	Get_User_transfer "${port}"
}
Get_User_transfer(){
	transfer_port=$1
	#echo "transfer_port=${transfer_port}"
	all_port=$(${jq_file} '.[]|.port' ${config_user_mudb_file})
	#echo "all_port=${all_port}"
	port_num=$(echo "${all_port}"|grep -nw "${transfer_port}"|awk -F ":" '{print $1}')
	#echo "port_num=${port_num}"
	port_num_1=$(echo $((${port_num}-1)))
	#echo "port_num_1=${port_num_1}"
	transfer_enable_1=$(${jq_file} ".[${port_num_1}].transfer_enable" ${config_user_mudb_file})
	#echo "transfer_enable_1=${transfer_enable_1}"
	u_1=$(${jq_file} ".[${port_num_1}].u" ${config_user_mudb_file})
	#echo "u_1=${u_1}"
	d_1=$(${jq_file} ".[${port_num_1}].d" ${config_user_mudb_file})
	#echo "d_1=${d_1}"
	transfer_enable_Used_2_1=$(echo $((${u_1}+${d_1})))
	#echo "transfer_enable_Used_2_1=${transfer_enable_Used_2_1}"
	transfer_enable_Used_1=$(echo $((${transfer_enable_1}-${transfer_enable_Used_2_1})))
	#echo "transfer_enable_Used_1=${transfer_enable_Used_1}"
	
	if [[ ${transfer_enable_1} -lt 1024 ]]; then
		transfer_enable="${transfer_enable_1} B"
	elif [[ ${transfer_enable_1} -lt 1048576 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1024'}')
		transfer_enable="${transfer_enable} KB"
	elif [[ ${transfer_enable_1} -lt 1073741824 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1048576'}')
		transfer_enable="${transfer_enable} MB"
	elif [[ ${transfer_enable_1} -lt 1099511627776 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1073741824'}')
		transfer_enable="${transfer_enable} GB"
	elif [[ ${transfer_enable_1} -lt 1125899906842624 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1099511627776'}')
		transfer_enable="${transfer_enable} TB"
	fi
	#echo "transfer_enable=${transfer_enable}"
	if [[ ${u_1} -lt 1024 ]]; then
		u="${u_1} B"
	elif [[ ${u_1} -lt 1048576 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1024'}')
		u="${u} KB"
	elif [[ ${u_1} -lt 1073741824 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1048576'}')
		u="${u} MB"
	elif [[ ${u_1} -lt 1099511627776 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1073741824'}')
		u="${u} GB"
	elif [[ ${u_1} -lt 1125899906842624 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1099511627776'}')
		u="${u} TB"
	fi
	#echo "u=${u}"
	if [[ ${d_1} -lt 1024 ]]; then
		d="${d_1} B"
	elif [[ ${d_1} -lt 1048576 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1024'}')
		d="${d} KB"
	elif [[ ${d_1} -lt 1073741824 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1048576'}')
		d="${d} MB"
	elif [[ ${d_1} -lt 1099511627776 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1073741824'}')
		d="${d} GB"
	elif [[ ${d_1} -lt 1125899906842624 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1099511627776'}')
		d="${d} TB"
	fi
	#echo "d=${d}"
	if [[ ${transfer_enable_Used_1} -lt 1024 ]]; then
		transfer_enable_Used="${transfer_enable_Used_1} B"
	elif [[ ${transfer_enable_Used_1} -lt 1048576 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1024'}')
		transfer_enable_Used="${transfer_enable_Used} KB"
	elif [[ ${transfer_enable_Used_1} -lt 1073741824 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1048576'}')
		transfer_enable_Used="${transfer_enable_Used} MB"
	elif [[ ${transfer_enable_Used_1} -lt 1099511627776 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1073741824'}')
		transfer_enable_Used="${transfer_enable_Used} GB"
	elif [[ ${transfer_enable_Used_1} -lt 1125899906842624 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1099511627776'}')
		transfer_enable_Used="${transfer_enable_Used} TB"
	fi
	#echo "transfer_enable_Used=${transfer_enable_Used}"
	if [[ ${transfer_enable_Used_2_1} -lt 1024 ]]; then
		transfer_enable_Used_2="${transfer_enable_Used_2_1} B"
	elif [[ ${transfer_enable_Used_2_1} -lt 1048576 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1024'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} KB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1073741824 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1048576'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} MB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1099511627776 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1073741824'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} GB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1125899906842624 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1099511627776'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} TB"
	fi
	#echo "transfer_enable_Used_2=${transfer_enable_Used_2}"
}
Get_User_transfer_all(){
	if [[ ${transfer_enable_Used_233} -lt 1024 ]]; then
		transfer_enable_Used_233_2="${transfer_enable_Used_233} B"
	elif [[ ${transfer_enable_Used_233} -lt 1048576 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1024'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} KB"
	elif [[ ${transfer_enable_Used_233} -lt 1073741824 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1048576'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} MB"
	elif [[ ${transfer_enable_Used_233} -lt 1099511627776 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1073741824'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} GB"
	elif [[ ${transfer_enable_Used_233} -lt 1125899906842624 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1099511627776'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} TB"
	fi
}
urlsafe_base64(){
	date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
	echo -e "${date}"
}
ss_link_qr(){
	SSbase64=$(urlsafe_base64 "${method}:${password}@${ip}:${port}")
	SSurl="ss://${SSbase64}"
	SSQRcode="https://chart.googleapis.com/chart?cht=qr&chl=${SSurl}&chs=160x160"
	ss_link=" SS    link : ${Green_font_prefix}${SSurl}${Font_color_suffix} \n SS  QR code : ${Green_font_prefix}${SSQRcode}${Font_color_suffix}"
}
ssr_link_qr(){
	SSRprotocol=$(echo ${protocol} | sed 's/_compatible//g')
	SSRobfs=$(echo ${obfs} | sed 's/_compatible//g')
	SSRPWDbase64=$(urlsafe_base64 "${password}")
	SSRbase64=$(urlsafe_base64 "${ip}:${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}")
	SSRurl="ssr://${SSRbase64}"
	SSRQRcode="https://chart.googleapis.com/chart?cht=qr&chl=${SSRurl}&chs=160x160"
	ssr_link=" SSR   link : ${Red_font_prefix}${SSRurl}${Font_color_suffix} \n SSR QR code : ${Red_font_prefix}${SSRQRcode}${Font_color_suffix} \n "
}
ss_ssr_determine(){
	protocol_suffix=`echo ${protocol} | awk -F "_" '{print $NF}'`
	obfs_suffix=`echo ${obfs} | awk -F "_" '{print $NF}'`
	if [[ ${protocol} = "origin" ]]; then
		if [[ ${obfs} = "plain" ]]; then
			ss_link_qr
			ssr_link=""
		else
			if [[ ${obfs_suffix} != "compatible" ]]; then
				ss_link=""
			else
				ss_link_qr
			fi
		fi
	else
		if [[ ${protocol_suffix} != "compatible" ]]; then
			ss_link=""
		else
			if [[ ${obfs_suffix} != "compatible" ]]; then
				if [[ ${obfs_suffix} = "plain" ]]; then
					ss_link_qr
				else
					ss_link=""
				fi
			else
				ss_link_qr
			fi
		fi
	fi
	ssr_link_qr
}
# Tampilkan informasi konfigurasi
View_User(){
	SSR_installation_status
	List_port_user
	while true
	do
		echo -e "Silakan masukkan port pengguna untuk melihat informasi akun."
		read -e -p "(Default: Cancel):" View_user_port
		[[ -z "${View_user_port}" ]] && echo -e "Batalkan..." && exit 1
		View_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${View_user_port}"',')
		if [[ ! -z ${View_user} ]]; then
			Get_User_info "${View_user_port}"
			View_User_info
			break
		else
			echo -e "${Error} Silakan masukkan port yang benar!"
		fi
	done
}
View_User_info(){
	ip=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
	[[ -z "${ip}" ]] && Get_IP
	ss_ssr_determine
	clear && echo "===================================================" && echo
	echo -e " User [${user_name}] 的Konfigurasi信息：" && echo
	echo -e " I  P\t    : ${Green_font_prefix}${ip}${Font_color_suffix}"
	echo -e " port\t    : ${Green_font_prefix}${port}${Font_color_suffix}"
	echo -e " Password\t    : ${Green_font_prefix}${password}${Font_color_suffix}"
	echo -e " Encryption\t    : ${Green_font_prefix}${method}${Font_color_suffix}"
	echo -e " Protocol\t    : ${Red_font_prefix}${protocol}${Font_color_suffix}"
	echo -e " OBFS\t    : ${Red_font_prefix}${obfs}${Font_color_suffix}"
	echo -e " Device limit : ${Green_font_prefix}${protocol_param}${Font_color_suffix}"
	echo -e " Single thread speed limit : ${Green_font_prefix}${speed_limit_per_con} KB/S${Font_color_suffix}"
	echo -e " User total speed limit : ${Green_font_prefix}${speed_limit_per_user} KB/S${Font_color_suffix}"
	echo -e " Block Port : ${Green_font_prefix}${forbidden_port} ${Font_color_suffix}"
	echo
	echo -e " Used traffic : 上传: ${Green_font_prefix}${u}${Font_color_suffix} + download: ${Green_font_prefix}${d}${Font_color_suffix} = ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix}"
	echo -e " Remaining traffic : ${Green_font_prefix}${transfer_enable_Used} ${Font_color_suffix}"
	echo -e " Total user traffic : ${Green_font_prefix}${transfer_enable} ${Font_color_suffix}"
	echo -e "${ss_link}"
	echo -e "${ssr_link}"
	echo -e " ${Green_font_prefix} prompt: ${Font_color_suffix}
 Di browser, buka tautan kode QR dan Anda akan melihat gambar kode QR.
 [_compatible] setelah Protokol dan OBFS mengacu pada kompatibilitas dengan Protokol asli / OBFS."
	echo && echo "==================================================="
}
# Pengaturan informasi konfigurasi
Set_config_user(){
	echo "Silakan masukkan user yang akan ditetapkan Username(Harus beda, Untuk Membedakan, Bahasa Cina, spasi tidak didukung, akan menampilkan error !)"
	read -e -p "(Default: doubi):" ssr_user
	[[ -z "${ssr_user}" ]] && ssr_user="doubi"
	ssr_user=$(echo "${ssr_user}"|sed 's/ //g')
	echo && echo ${Separator_1} && echo -e "	Username : ${Green_font_prefix}${ssr_user}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_port(){
	while true
	do
	echo -e "Silakan masukkan user yang akan ditetapkan port(Harus beda, Untuk Membedakan)"
	read -e -p "(Default: 2333):" ssr_port
	[[ -z "$ssr_port" ]] && ssr_port="2333"
	echo $((${ssr_port}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_port} -ge 1 ]] && [[ ${ssr_port} -le 65535 ]]; then
			echo && echo ${Separator_1} && echo -e "	port : ${Green_font_prefix}${ssr_port}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Silakan masukkan nomor yang benar(1-65535)"
		fi
	else
		echo -e "${Error} Silakan masukkan nomor yang benar(1-65535)"
	fi
	done
}
Set_config_password(){
	echo "Silakan masukkan user yang akan ditetapkan Password"
	read -e -p "(Default: doub.io):" ssr_password
	[[ -z "${ssr_password}" ]] && ssr_password="doub.io"
	echo && echo ${Separator_1} && echo -e "	Password : ${Green_font_prefix}${ssr_password}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_method(){
	echo -e "Silakan pilih user yang akan ditetapkan Encryption Mode
	
 ${Green_font_prefix} 1.${Font_color_suffix} none
 ${Tip} Jika menggunakan auth_chain_* Seri Protokol, direkomendasikan agar Mode Enkripsi tidak memilih (protokol seri dilengkapi dengan Enkripsi RC4), bebas OBFS
 
 ${Green_font_prefix} 2.${Font_color_suffix} rc4
 ${Green_font_prefix} 3.${Font_color_suffix} rc4-md5
 ${Green_font_prefix} 4.${Font_color_suffix} rc4-md5-6
 
 ${Green_font_prefix} 5.${Font_color_suffix} aes-128-ctr
 ${Green_font_prefix} 6.${Font_color_suffix} aes-192-ctr
 ${Green_font_prefix} 7.${Font_color_suffix} aes-256-ctr
 
 ${Green_font_prefix} 8.${Font_color_suffix} aes-128-cfb
 ${Green_font_prefix} 9.${Font_color_suffix} aes-192-cfb
 ${Green_font_prefix}10.${Font_color_suffix} aes-256-cfb
 
 ${Green_font_prefix}11.${Font_color_suffix} aes-128-cfb8
 ${Green_font_prefix}12.${Font_color_suffix} aes-192-cfb8
 ${Green_font_prefix}13.${Font_color_suffix} aes-256-cfb8
 
 ${Green_font_prefix}14.${Font_color_suffix} salsa20
 ${Green_font_prefix}15.${Font_color_suffix} chacha20
 ${Green_font_prefix}16.${Font_color_suffix} chacha20-ietf
 ${Tip} Mode Enkripsi Salsa20 / chacha20- * seri, perlu menginstal libsodium tambahan, jika tidak maka tidak akan memulai ShadowsocksR !" && echo
	read -e -p "(Default: 5. aes-128-ctr):" ssr_method
	[[ -z "${ssr_method}" ]] && ssr_method="5"
	if [[ ${ssr_method} == "1" ]]; then
		ssr_method="none"
	elif [[ ${ssr_method} == "2" ]]; then
		ssr_method="rc4"
	elif [[ ${ssr_method} == "3" ]]; then
		ssr_method="rc4-md5"
	elif [[ ${ssr_method} == "4" ]]; then
		ssr_method="rc4-md5-6"
	elif [[ ${ssr_method} == "5" ]]; then
		ssr_method="aes-128-ctr"
	elif [[ ${ssr_method} == "6" ]]; then
		ssr_method="aes-192-ctr"
	elif [[ ${ssr_method} == "7" ]]; then
		ssr_method="aes-256-ctr"
	elif [[ ${ssr_method} == "8" ]]; then
		ssr_method="aes-128-cfb"
	elif [[ ${ssr_method} == "9" ]]; then
		ssr_method="aes-192-cfb"
	elif [[ ${ssr_method} == "10" ]]; then
		ssr_method="aes-256-cfb"
	elif [[ ${ssr_method} == "11" ]]; then
		ssr_method="aes-128-cfb8"
	elif [[ ${ssr_method} == "12" ]]; then
		ssr_method="aes-192-cfb8"
	elif [[ ${ssr_method} == "13" ]]; then
		ssr_method="aes-256-cfb8"
	elif [[ ${ssr_method} == "14" ]]; then
		ssr_method="salsa20"
	elif [[ ${ssr_method} == "15" ]]; then
		ssr_method="chacha20"
	elif [[ ${ssr_method} == "16" ]]; then
		ssr_method="chacha20-ietf"
	else
		ssr_method="aes-128-ctr"
	fi
	echo && echo ${Separator_1} && echo -e "	Encryption : ${Green_font_prefix}${ssr_method}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_protocol(){
	echo -e "Silakan pilih user yang akan ditetapkan Plugin Protocol
	
 ${Green_font_prefix}1.${Font_color_suffix} origin
 ${Green_font_prefix}2.${Font_color_suffix} auth_sha1_v4
 ${Green_font_prefix}3.${Font_color_suffix} auth_aes128_md5
 ${Green_font_prefix}4.${Font_color_suffix} auth_aes128_sha1
 ${Green_font_prefix}5.${Font_color_suffix} auth_chain_a
 ${Green_font_prefix}6.${Font_color_suffix} auth_chain_b
 ${Tip} Jika menggunakan protokol seri auth_chain_ *, disarankan agar Mode Enkripsi tidak memilih satu pun (protokol seri dilengkapi dengan Enkripsi RC4), bebas OBFS" && echo
	read -e -p "(Default: 3. auth_aes128_md5):" ssr_protocol
	[[ -z "${ssr_protocol}" ]] && ssr_protocol="3"
	if [[ ${ssr_protocol} == "1" ]]; then
		ssr_protocol="origin"
	elif [[ ${ssr_protocol} == "2" ]]; then
		ssr_protocol="auth_sha1_v4"
	elif [[ ${ssr_protocol} == "3" ]]; then
		ssr_protocol="auth_aes128_md5"
	elif [[ ${ssr_protocol} == "4" ]]; then
		ssr_protocol="auth_aes128_sha1"
	elif [[ ${ssr_protocol} == "5" ]]; then
		ssr_protocol="auth_chain_a"
	elif [[ ${ssr_protocol} == "6" ]]; then
		ssr_protocol="auth_chain_b"
	else
		ssr_protocol="auth_aes128_md5"
	fi
	echo && echo ${Separator_1} && echo -e "	Protocol : ${Green_font_prefix}${ssr_protocol}${Font_color_suffix}" && echo ${Separator_1} && echo
	if [[ ${ssr_protocol} != "origin" ]]; then
		if [[ ${ssr_protocol} == "auth_sha1_v4" ]]; then
			read -e -p "Apakah akan akan mengatur Protokol Plugin asli yang kompatibel(_compatible)？[Y/n]" ssr_protocol_yn
			[[ -z "${ssr_protocol_yn}" ]] && ssr_protocol_yn="y"
			[[ $ssr_protocol_yn == [Yy] ]] && ssr_protocol=${ssr_protocol}"_compatible"
			echo
		fi
	fi
}
Set_config_obfs(){
	echo -e "Silakan pilih user yang akan ditetapkan Plugin OBFS
	
 ${Green_font_prefix}1.${Font_color_suffix} plain
 ${Green_font_prefix}2.${Font_color_suffix} http_simple
 ${Green_font_prefix}3.${Font_color_suffix} http_post
 ${Green_font_prefix}4.${Font_color_suffix} random_head
 ${Green_font_prefix}5.${Font_color_suffix} tls1.2_ticket_auth
 ${Tip} Jika menggunakan ShadowsocksR untuk bermain game, maka disarankan menggunakan OBFS kompatibel dengan yang asli atau plain OBFS，lalu seleksi client plain，jika tidak maka akan meningkatkan PING !
 Jiga, jika anda memilih tls1.2_ticket_auth，maka klien dapat memilih tls1.2_ticket_fastauth，Ini bisa disamarkan tanpa meningkatkan PING. !
 Jika Anda membangun di area populer seperti Jepang dan Amerika Serikat, maka pilih plain OBFS mungkin lebih kecil kemungkinannya untuk didindingi !" && echo
	read -e -p "(Default: 1. plain):" ssr_obfs
	[[ -z "${ssr_obfs}" ]] && ssr_obfs="1"
	if [[ ${ssr_obfs} == "1" ]]; then
		ssr_obfs="plain"
	elif [[ ${ssr_obfs} == "2" ]]; then
		ssr_obfs="http_simple"
	elif [[ ${ssr_obfs} == "3" ]]; then
		ssr_obfs="http_post"
	elif [[ ${ssr_obfs} == "4" ]]; then
		ssr_obfs="random_head"
	elif [[ ${ssr_obfs} == "5" ]]; then
		ssr_obfs="tls1.2_ticket_auth"
	else
		ssr_obfs="plain"
	fi
	echo && echo ${Separator_1} && echo -e "	OBFS : ${Green_font_prefix}${ssr_obfs}${Font_color_suffix}" && echo ${Separator_1} && echo
	if [[ ${ssr_obfs} != "plain" ]]; then
			read -e -p "Apakah akan diatur Plugin OBFS compatible original(_compatible)？[Y/n]" ssr_obfs_yn
			[[ -z "${ssr_obfs_yn}" ]] && ssr_obfs_yn="y"
			[[ $ssr_obfs_yn == [Yy] ]] && ssr_obfs=${ssr_obfs}"_compatible"
			echo
	fi
}
Set_config_protocol_param(){
	while true
	do
	echo -e "Silakan masukkan user yang akan ditetapkan Jumlah perangkat yang akan dibatasi (${Green_font_prefix} auth_* Series Protocol Tidak kompatibel dengan versi asli yang valid ${Font_color_suffix})"
	echo -e "${Tip} Device limit： Jumlah klien yang dapat menautkan setiap port pada saat yang sama (mode multi-port, setiap port dihitung secara independen), disarankan untuk setidaknya 2."
	read -e -p "(Default: unlimited):" ssr_protocol_param
	[[ -z "$ssr_protocol_param" ]] && ssr_protocol_param="" && echo && break
	echo $((${ssr_protocol_param}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_protocol_param} -ge 1 ]] && [[ ${ssr_protocol_param} -le 9999 ]]; then
			echo && echo ${Separator_1} && echo -e "	Device limit : ${Green_font_prefix}${ssr_protocol_param}${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Silakan masukkan nomor yang benar(1-9999)"
		fi
	else
		echo -e "${Error} Silakan masukkan nomor yang benar(1-9999)"
	fi
	done
}
Set_config_speed_limit_per_con(){
	while true
	do
	echo -e "Silakan masukkan user yang akan ditetapkan Single thread speed limit(Satuan：KB/S)"
	echo -e "${Tip} Single thread speed limit： Batas kecepatan maksimum untuk setiap port, multi-threading tidak valid."
	read -e -p "(Default: unlimited):" ssr_speed_limit_per_con
	[[ -z "$ssr_speed_limit_per_con" ]] && ssr_speed_limit_per_con=0 && echo && break
	echo $((${ssr_speed_limit_per_con}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_con} -ge 1 ]] && [[ ${ssr_speed_limit_per_con} -le 131072 ]]; then
			echo && echo ${Separator_1} && echo -e "	Single thread speed limit : ${Green_font_prefix}${ssr_speed_limit_per_con} KB/S${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Silakan masukkan nomor yang benar(1-131072)"
		fi
	else
		echo -e "${Error} Silakan masukkan nomor yang benar(1-131072)"
	fi
	done
}
Set_config_speed_limit_per_user(){
	while true
	do
	echo
	echo -e "Silakan masukkan user yang akan ditetapkan Kecepatan total(Satuan：KB/S)"
	echo -e "${Tip} Port total speed limit: setiap port Kecepatan total, batas kecepatan keseluruhan dari satu port."
	read -e -p "(Default: unlimited):" ssr_speed_limit_per_user
	[[ -z "$ssr_speed_limit_per_user" ]] && ssr_speed_limit_per_user=0 && echo && break
	echo $((${ssr_speed_limit_per_user}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_user} -ge 1 ]] && [[ ${ssr_speed_limit_per_user} -le 131072 ]]; then
			echo && echo ${Separator_1} && echo -e "	User total speed limit : ${Green_font_prefix}${ssr_speed_limit_per_user} KB/S${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Silakan masukkan nomor yang benar(1-131072)"
		fi
	else
		echo -e "${Error} Silakan masukkan nomor yang benar(1-131072)"
	fi
	done
}
Set_config_transfer(){
	while true
	do
	echo
	echo -e "Silakan masukkan user yang akan ditetapkan Batas Kuota(Satuan: GB, 1-838868 GB)"
	read -e -p "(Default: unlimited):" ssr_transfer
	[[ -z "$ssr_transfer" ]] && ssr_transfer="838868" && echo && break
	echo $((${ssr_transfer}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_transfer} -ge 1 ]] && [[ ${ssr_transfer} -le 838868 ]]; then
			echo && echo ${Separator_1} && echo -e "	Total user traffic : ${Green_font_prefix}${ssr_transfer} GB${Font_color_suffix}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Silakan masukkan nomor yang benar(1-838868)"
		fi
	else
		echo -e "${Error} Silakan masukkan nomor yang benar(1-838868)"
	fi
	done
}
Set_config_forbid(){
	echo "Silakan masukkan user yang akan ditetapkan Port yang dilarang"
	echo -e "${Tip} Block Port: Misalnya, jika Anda tidak mengizinkan akses ke port, Pengguna tidak akan dapat mengakses port mail 25 melalui proksi SSR. Jika 80.443 dinonaktifkan, Pengguna tidak akan dapat mengakses situs web http / https secara normal.
Block a single port format: 25
Block a Multi port format: 23,465
Block a Range port format: 233-266
Block a multiple port format: 25,465,233-666 (Tanpa titik dua:)"
	read -e -p "(Default kosong. Jangan memblokir akses ke port apa pun.):" ssr_forbid
	[[ -z "${ssr_forbid}" ]] && ssr_forbid=""
	echo && echo ${Separator_1} && echo -e "	Block Port : ${Green_font_prefix}${ssr_forbid}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_enable(){
	user_total=$(echo $((${user_total}-1)))
	for((integer = 0; integer <= ${user_total}; integer++))
	do
		echo -e "integer=${integer}"
		port_jq=$(${jq_file} ".[${integer}].port" "${config_user_mudb_file}")
		echo -e "port_jq=${port_jq}"
		if [[ "${ssr_port}" == "${port_jq}" ]]; then
			enable=$(${jq_file} ".[${integer}].enable" "${config_user_mudb_file}")
			echo -e "enable=${enable}"
			[[ "${enable}" == "null" ]] && echo -e "${Error} Get the current port[${ssr_port}]Status dinonaktifkan gagal !" && exit 1
			ssr_port_num=$(cat "${config_user_mudb_file}"|grep -n '"port": '${ssr_port}','|awk -F ":" '{print $1}')
			echo -e "ssr_port_num=${ssr_port_num}"
			[[ "${ssr_port_num}" == "null" ]] && echo -e "${Error} Get the current port[${ssr_port}]Jumlah baris gagal !" && exit 1
			ssr_enable_num=$(echo $((${ssr_port_num}-5)))
			echo -e "ssr_enable_num=${ssr_enable_num}"
			break
		fi
	done
	if [[ "${enable}" == "1" ]]; then
		echo -e "port [${ssr_port}] Status akun adalah:${Green_font_prefix}Aktifkan${Font_color_suffix} , Apakah akan beralih ke ${Red_font_prefix}Nonaktifkan${Font_color_suffix} ?[Y/n]"
		read -e -p "(Default: Y):" ssr_enable_yn
		[[ -z "${ssr_enable_yn}" ]] && ssr_enable_yn="y"
		if [[ "${ssr_enable_yn}" == [Yy] ]]; then
			ssr_enable="0"
		else
			echo "Cancel..." && exit 0
		fi
	elif [[ "${enable}" == "0" ]]; then
		echo -e "port [${ssr_port}] Status akun adalah:${Green_font_prefix}Nonaktifkan${Font_color_suffix} , Apakah akan beralih ke ${Red_font_prefix}Aktifkan${Font_color_suffix} ?[Y/n]"
		read -e -p "(Default: Y):" ssr_enable_yn
		[[ -z "${ssr_enable_yn}" ]] && ssr_enable_yn = "y"
		if [[ "${ssr_enable_yn}" == [Yy] ]]; then
			ssr_enable="1"
		else
			echo "Cancel..." && exit 0
		fi
	else
		echo -e "${Error} Status Nonaktifkan port saat ini tidak normal.[${enable}] !" && exit 1
	fi
}
Set_user_api_server_pub_addr(){
	addr=$1
	if [[ "${addr}" == "Modify" ]]; then
		server_pub_addr=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
		if [[ -z ${server_pub_addr} ]]; then
			echo -e "${Error} Gagal mendapatkan IP server atau nama domain yang saat ini dikonfigurasi!" && exit 1
		else
			echo -e "${Info} IP server atau nama domain yang saat ini dikonfigurasi adalah: ${Green_font_prefix}${server_pub_addr}${Font_color_suffix}"
		fi
	fi
	echo "Silakan masukkan IP server atau nama domain yang akan ditampilkan dalam konfigurasi user. (Ketika server memiliki beberapa IP, Anda dapat menentukan IP atau nama domain yang ditampilkan dalam konfigurasi Pengguna.)"
	read -e -p "(Default secara otomatis mendeteksi IP jaringan eksternal):" ssr_server_pub_addr
	if [[ -z "${ssr_server_pub_addr}" ]]; then
		Get_IP
		if [[ ${ip} == "VPS_IP" ]]; then
			while true
			do
			read -e -p "${Error} Deteksi otomatis dari IP jaringan eksternal gagal. Harap masukkan IP server atau nama domain secara manual." ssr_server_pub_addr
			if [[ -z "$ssr_server_pub_addr" ]]; then
				echo -e "${Error} Tidak boleh kosong!"
			else
				break
			fi
			done
		else
			ssr_server_pub_addr="${ip}"
		fi
	fi
	echo && echo ${Separator_1} && echo -e "	IP atau nama domain : ${Green_font_prefix}${ssr_server_pub_addr}${Font_color_suffix}" && echo ${Separator_1} && echo
}
Set_config_all(){
	lal=$1
	if [[ "${lal}" == "Modify" ]]; then
		Set_config_password
		Set_config_method
		Set_config_protocol
		Set_config_obfs
		Set_config_protocol_param
		Set_config_speed_limit_per_con
		Set_config_speed_limit_per_user
		Set_config_transfer
		Set_config_forbid
	else
		Set_config_user
		Set_config_port
		Set_config_password
		Set_config_method
		Set_config_protocol
		Set_config_obfs
		Set_config_protocol_param
		Set_config_speed_limit_per_con
		Set_config_speed_limit_per_user
		Set_config_transfer
		Set_config_forbid
	fi
}
# Ubah informasi konfigurasi
Modify_config_password(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -k "${ssr_password}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Modifikasi UserPassword gagal ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} UserPassword berhasil diubah ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (Catatan: Diperlukan waktu sekitar sepuluh detik untuk menerapkan konfigurasi terbaru.)"
	fi
}
Modify_config_method(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -m "${ssr_method}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} UserEncryption Modifikasi mode gagal ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} UserEncryption Mode berhasil diubah ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (Catatan: Diperlukan waktu sekitar sepuluh detik untuk menerapkan konfigurasi terbaru.)"
	fi
}
Modify_config_protocol(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -O "${ssr_protocol}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Modifikasi UserProtocol gagal ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} UserProtocol berhasil dimodifikasi ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (Catatan: Diperlukan waktu sekitar sepuluh detik untuk menerapkan konfigurasi terbaru.)"
	fi
}
Modify_config_obfs(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -o "${ssr_obfs}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Modifikasi UserOBFS gagal ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} UserOBFS berhasil dimodifikasi ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (Catatan: Diperlukan waktu sekitar sepuluh detik untuk menerapkan konfigurasi terbaru.)"
	fi
}
Modify_config_protocol_param(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -G "${ssr_protocol_param}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Parameter UserProtocol(Device limit)Modifikasi gagal ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Argumen pengguna(Device limit)Dimodifikasi dengan sukses ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (Catatan: Diperlukan waktu sekitar sepuluh detik untuk menerapkan konfigurasi terbaru.)"
	fi
}
Modify_config_speed_limit_per_con(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -s "${ssr_speed_limit_per_con}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} UserSingle thread speed limit gagal diubah ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} UserSingle thread speed limit berhasil diubah ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (Catatan: Diperlukan waktu sekitar sepuluh detik untuk menerapkan konfigurasi terbaru.)"
	fi
}
Modify_config_speed_limit_per_user(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -S "${ssr_speed_limit_per_user}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Modifikasi batas kecepatan total Userport gagal ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Modifikasi batas kecepatan total Userport berhasil ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (Catatan: Diperlukan waktu sekitar sepuluh detik untuk menerapkan konfigurasi terbaru.)"
	fi
}
Modify_config_connect_verbose_info(){
	sed -i 's/"connect_verbose_info": '"$(echo ${connect_verbose_info})"',/"connect_verbose_info": '"$(echo ${ssr_connect_verbose_info})"',/g' ${config_user_file}
}
Modify_config_transfer(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -t "${ssr_transfer}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Total user kuota gagal diubah ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Total user kuota berhasil diubah ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (Catatan: Diperlukan waktu sekitar sepuluh detik untuk menerapkan konfigurasi terbaru.)"
	fi
}
Modify_config_forbid(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -f "${ssr_forbid}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Block port user gagal ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} " && exit 1
	else
		echo -e "${Info} Block port user sukses ${Green_font_prefix}[port: ${ssr_port}]${Font_color_suffix} (Catatan: Diperlukan waktu sekitar sepuluh detik untuk menerapkan konfigurasi terbaru.)"
	fi
}
Modify_config_enable(){
	sed -i "${ssr_enable_num}"'s/"enable": '"$(echo ${enable})"',/"enable": '"$(echo ${ssr_enable})"',/' ${config_user_mudb_file}
}
Modify_user_api_server_pub_addr(){
	sed -i "s/SERVER_PUB_ADDR = '${server_pub_addr}'/SERVER_PUB_ADDR = '${ssr_server_pub_addr}'/" ${config_user_api_file}
}
Modify_config_all(){
	Modify_config_password
	Modify_config_method
	Modify_config_protocol
	Modify_config_obfs
	Modify_config_protocol_param
	Modify_config_speed_limit_per_con
	Modify_config_speed_limit_per_user
	Modify_config_transfer
	Modify_config_forbid
}
Check_python(){
	python_ver=`python -h`
	if [[ -z ${python_ver} ]]; then
		echo -e "${Info} Tidak TerpasangPython，Mulai instalasi..."
		if [[ ${release} == "centos" ]]; then
			yum install -y python
		else
			apt-get install -y python
		fi
	fi
}
Centos_yum(){
	yum update
	cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
	if [[ $? = 0 ]]; then
		yum install -y vim unzip crond net-tools
	else
		yum install -y vim unzip crond
	fi
}
Debian_apt(){
	apt-get update
	cat /etc/issue |grep 9\..*>/dev/null
	if [[ $? = 0 ]]; then
		apt-get install -y vim unzip cron net-tools
	else
		apt-get install -y vim unzip cron
	fi
}
# Download ShadowsocksR
Download_SSR(){
	cd "/usr/local"
	wget -N --no-check-certificate "https://github.com/ToyoDAdoubiBackup/shadowsocksr/archive/manyuser.zip"
	#git config --global http.sslVerify false
	#env GIT_SSL_NO_VERIFY=true git clone -b manyuser https://github.com/ToyoDAdoubi/shadowsocksr.git
	#[[ ! -e ${ssr_folder} ]] && echo -e "${Error} Server ShadowsocksR Pengunduhan gagal !" && exit 1
	[[ ! -e "manyuser.zip" ]] && echo -e "${Error} Server ShadowsocksR Pengunduhan paket terkompresi gagal !" && rm -rf manyuser.zip && exit 1
	unzip "manyuser.zip"
	[[ ! -e "/usr/local/shadowsocksr-manyuser/" ]] && echo -e "${Error} Server ShadowsocksR Dekompresi gagal !" && rm -rf manyuser.zip && exit 1
	mv "/usr/local/shadowsocksr-manyuser/" "/usr/local/shadowsocksr/"
	[[ ! -e "/usr/local/shadowsocksr/" ]] && echo -e "${Error} Server ShadowsocksR Ganti nama gagal !" && rm -rf manyuser.zip && rm -rf "/usr/local/shadowsocksr-manyuser/" && exit 1
	rm -rf manyuser.zip
	cd "shadowsocksr"
	cp "${ssr_folder}/config.json" "${config_user_file}"
	cp "${ssr_folder}/mysql.json" "${ssr_folder}/usermysql.json"
	cp "${ssr_folder}/apiconfig.py" "${config_user_api_file}"
	[[ ! -e ${config_user_api_file} ]] && echo -e "${Error} Server ShadowsocksR apiconfig.py Replikasi gagal !" && exit 1
	sed -i "s/API_INTERFACE = 'sspanelv2'/API_INTERFACE = 'mudbjson'/" ${config_user_api_file}
	server_pub_addr="127.0.0.1"
	Modify_user_api_server_pub_addr
	#sed -i "s/SERVER_PUB_ADDR = '127.0.0.1'/SERVER_PUB_ADDR = '${ip}'/" ${config_user_api_file}
	sed -i 's/ \/\/ only works under multi-user mode//g' "${config_user_file}"
	echo -e "${Info} Server ShadowsocksR Pengunduhan selesai !"
}
Service_SSR(){
	if [[ ${release} = "centos" ]]; then
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/service/ssrmu_centos -O /etc/init.d/ssrmu; then
			echo -e "${Error} ShadowsocksR服务 管理Unduhan skrip gagal !" && exit 1
		fi
		chmod +x /etc/init.d/ssrmu
		chkconfig --add ssrmu
		chkconfig ssrmu on
	else
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/service/ssrmu_debian -O /etc/init.d/ssrmu; then
			echo -e "${Error} ShadowsocksR服务 管理Unduhan skrip gagal !" && exit 1
		fi
		chmod +x /etc/init.d/ssrmu
		update-rc.d -f ssrmu defaults
	fi
	echo -e "${Info} ShadowsocksR服务 管理Pengunduhan skrip selesai !"
}
# Install JQ
JQ_install(){
	if [[ ! -e ${jq_file} ]]; then
		cd "${ssr_folder}"
		if [[ ${bit} = "x86_64" ]]; then
			mv "jq-linux64" "jq"
			#wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64" -O ${jq_file}
		else
			mv "jq-linux32" "jq"
			#wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux32" -O ${jq_file}
		fi
		[[ ! -e ${jq_file} ]] && echo -e "${Error} Parser JQ Ganti nama gagal, Silakan periksa !" && exit 1
		chmod +x ${jq_file}
		echo -e "${Info} Parser JQ Instalasi selesai, lanjutkan..." 
	else
		echo -e "${Info} Parser JQ Dipasang, lanjutkan..."
	fi
}
# Instalasi
Installation_dependency(){
	if [[ ${release} == "centos" ]]; then
		Centos_yum
	else
		Debian_apt
	fi
	[[ ! -e "/usr/bin/unzip" ]] && echo -e "${Error} Bergantung pada instalasi unzip (tarball yang dibongkar) gagal, sebagian besar masalah sumber paket，Silakan periksa !" && exit 1
	Check_python
	#echo "nameserver 8.8.8.8" > /etc/resolv.conf
	#echo "nameserver 8.8.4.4" >> /etc/resolv.conf
	\cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	if [[ ${release} == "centos" ]]; then
		/etc/init.d/crond restart
	else
		/etc/init.d/cron restart
	fi
}
Install_SSR(){
	check_root
	[[ -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR Folder sudah ada，Silakan periksa( Jika instalasi gagal atau ada versi lama, silakan hapus dulu. ) !" && exit 1
	echo -e "${Info} Mulai pengaturan Konfigurasi akun ShadowsocksR..."
	Set_user_api_server_pub_addr
	Set_config_all
	echo -e "${Info} Mulai instalasi/Konfigurasi ShadowsocksR dependency..."
	Installation_dependency
	echo -e "${Info} start download/installation ShadowsocksR file..."
	Download_SSR
	echo -e "${Info} start download/installation ShadowsocksR service script(init)..."
	Service_SSR
	echo -e "${Info} start download/installation JSNO parser JQ..."
	JQ_install
	echo -e "${Info} Mulai menambahkan Pengguna awal..."
	Add_port_user "install"
	echo -e "${Info} Mulai pengaturan Firewall iptables..."
	Set_iptables
	echo -e "${Info} Mulai menambahkan Aturan firewall Iptables..."
	Add_iptables
	echo -e "${Info} Mulai mengeset Aturan firewall Iptables..."
	Save_iptables
	echo -e "${Info} Semua langkah Instalasi selesai, mulai untuk mengaktifkan Server ShadowsocksR..."
	Start_SSR
	Get_User_info "${ssr_port}"
	View_User_info
}
Update_SSR(){
	SSR_installation_status
	echo -e "Fitur ini untuk sementara Nonaktifkan karena penangguhan Server ShadowsocksR."
	#cd ${ssr_folder}
	#git pull
	#Restart_SSR
}
Uninstall_SSR(){
	[[ ! -e ${ssr_folder} ]] && echo -e "${Error} Tidak Terpasang ShadowsocksR，Silakan periksa !" && exit 1
	echo "Anda yakin ingin menghapus ShadowsocksR?[y/N]" && echo
	read -e -p "(Default: n):" unyn
	[[ -z ${unyn} ]] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		check_pid
		[[ ! -z "${PID}" ]] && kill -9 ${PID}
		user_info=$(python mujson_mgr.py -l)
		user_total=$(echo "${user_info}"|wc -l)
		if [[ ! -z ${user_info} ]]; then
			for((integer = 1; integer <= ${user_total}; integer++))
			do
				port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
				Del_iptables
			done
			Save_iptables
		fi
		if [[ ! -z $(crontab -l | grep "ssrmu.sh") ]]; then
			crontab_monitor_ssr_cron_stop
			Clear_transfer_all_cron_stop
		fi
		if [[ ${release} = "centos" ]]; then
			chkconfig --del ssrmu
		else
			update-rc.d -f ssrmu remove
		fi
		rm -rf ${ssr_folder} && rm -rf /etc/init.d/ssrmu
		echo && echo " ShadowsocksR Penghapusan instalasi selesai !" && echo
	else
		echo && echo " Copot pemasangan Batalkan..." && echo
	fi
}
Check_Libsodium_ver(){
	echo -e "${Info} Mulai dapatkan libsodium versi terbaru..."
	Libsodiumr_ver=$(wget -qO- "https://github.com/jedisct1/libsodium/tags"|grep "/jedisct1/libsodium/releases/tag/"|head -1|sed -r 's/.*tag\/(.+)\">.*/\1/')
	[[ -z ${Libsodiumr_ver} ]] && Libsodiumr_ver=${Libsodiumr_ver_backup}
	echo -e "${Info} libsodium Versi terbaru adalah ${Green_font_prefix}${Libsodiumr_ver}${Font_color_suffix} !"
}
Install_Libsodium(){
	if [[ -e ${Libsodiumr_file} ]]; then
		echo -e "${Error} Libsodium telah diinstal, apakah akan menimpa instalasi(Perbarui)？[y/N]"
		read -e -p "(Default: n):" yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Nn] ]]; then
			echo "Batalkan..." && exit 1
		fi
	else
		echo -e "${Info} Libsodium tidak diinstal, Mulai instalasi..."
	fi
	Check_Libsodium_ver
	if [[ ${release} == "centos" ]]; then
		yum update
		echo -e "${Info} Installation dependence..."
		yum -y groupinstall "Development Tools"
		echo -e "${Info} download..."
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} Decompression..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} Compile installation..."
		./configure --disable-maintainer-mode && make -j2 && make install
		echo /usr/local/lib > /etc/ld.so.conf.d/usr_local_lib.conf
	else
		apt-get update
		echo -e "${Info} Installation dependence..."
		apt-get install -y build-essential
		echo -e "${Info} download..."
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} Decompression..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} Compile installation..."
		./configure --disable-maintainer-mode && make -j2 && make install
	fi
	ldconfig
	cd .. && rm -rf libsodium-${Libsodiumr_ver}.tar.gz && rm -rf libsodium-${Libsodiumr_ver}
	[[ ! -e ${Libsodiumr_file} ]] && echo -e "${Error} libsodium Installation failed !" && exit 1
	echo && echo -e "${Info} libsodium Successful installation !" && echo
}
# Tampilkan informasi koneksi
debian_View_user_connection_info(){
	format_1=$1
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Tidak Ditemukan User，Silakan periksa !" && exit 1
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |grep ":${user_port} " |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
		if [[ -z ${user_IP_1} ]]; then
			user_IP_total="0"
		else
			user_IP_total=`echo -e "${user_IP_1}"|wc -l`
			if [[ ${format_1} == "IP_address" ]]; then
				get_IP_address
			else
				user_IP=`echo -e "\n${user_IP_1}"`
			fi
		fi
		user_info_233=$(python mujson_mgr.py -l|grep -w "${user_port}"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		user_list_all=${user_list_all}"Username: ${Green_font_prefix}"${user_info_233}"${Font_color_suffix}\t port: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t Jumlah total tautan IP: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t Tautan saat ini IP: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		user_IP=""
	done
	echo -e "Jumlah total pengguna: ${Green_background_prefix} "${user_total}" ${Font_color_suffix} Jumlah total tautan IP: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix} "
	echo -e "${user_list_all}"
}
centos_View_user_connection_info(){
	format_1=$1
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Tidak Ditemukan User，Silakan periksa !" && exit 1
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' | grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' |grep ":${user_port} "|grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
		if [[ -z ${user_IP_1} ]]; then
			user_IP_total="0"
		else
			user_IP_total=`echo -e "${user_IP_1}"|wc -l`
			if [[ ${format_1} == "IP_address" ]]; then
				get_IP_address
			else
				user_IP=`echo -e "\n${user_IP_1}"`
			fi
		fi
		user_info_233=$(python mujson_mgr.py -l|grep -w "${user_port}"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		user_list_all=${user_list_all}"Username: ${Green_font_prefix}"${user_info_233}"${Font_color_suffix}\t port: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t Jumlah total tautan IP: ${Green_font_prefix}"${user_IP_total}"${Font_color_suffix}\t Tautan saat ini IP: ${Green_font_prefix}${user_IP}${Font_color_suffix}\n"
		user_IP=""
	done
	echo -e "Jumlah total pengguna: ${Green_background_prefix} "${user_total}" ${Font_color_suffix} Jumlah total tautan IP: ${Green_background_prefix} "${IP_total}" ${Font_color_suffix} "
	echo -e "${user_list_all}"
}
View_user_connection_info(){
	SSR_installation_status
	echo && echo -e "Silakan pilih format untuk ditampilkan:
 ${Green_font_prefix}1.${Font_color_suffix} Tampilan IP Format
 ${Green_font_prefix}2.${Font_color_suffix} Tampilan IP+Format atribusi IP" && echo
	read -e -p "(Default: 1):" ssr_connection_info
	[[ -z "${ssr_connection_info}" ]] && ssr_connection_info="1"
	if [[ ${ssr_connection_info} == "1" ]]; then
		View_user_connection_info_1 ""
	elif [[ ${ssr_connection_info} == "2" ]]; then
		echo -e "${Tip} Mendeteksi atribusi IP(ipip.net), Jika IP lebih, mungkin butuh waktu lama...."
		View_user_connection_info_1 "IP_address"
	else
		echo -e "${Error} Silakan masukkan nomor yang benar(1-2)" && exit 1
	fi
}
View_user_connection_info_1(){
	format=$1
	if [[ ${release} = "centos" ]]; then
		cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
		if [[ $? = 0 ]]; then
			debian_View_user_connection_info "$format"
		else
			centos_View_user_connection_info "$format"
		fi
	else
		debian_View_user_connection_info "$format"
	fi
}
get_IP_address(){
	#echo "user_IP_1=${user_IP_1}"
	if [[ ! -z ${user_IP_1} ]]; then
	#echo "user_IP_total=${user_IP_total}"
		for((integer_1 = ${user_IP_total}; integer_1 >= 1; integer_1--))
		do
			IP=`echo "${user_IP_1}" |sed -n "$integer_1"p`
			#echo "IP=${IP}"
			IP_address=`wget -qO- -t1 -T2 http://freeapi.ipip.net/${IP}|sed 's/\"//g;s/,//g;s/\[//g;s/\]//g'`
			#echo "IP_address=${IP_address}"
			user_IP="${user_IP}\n${IP}(${IP_address})"
			#echo "user_IP=${user_IP}"
			sleep 1s
		done
	fi
}
# Ubah Konfigurasi Pengguna
Modify_port(){
	List_port_user
	while true
	do
		echo -e "Silakan masukkan port user untuk diubah"
		read -e -p "(Default: Cancel):" ssr_port
		[[ -z "${ssr_port}" ]] && echo -e "Batalkan..." && exit 1
		Modify_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${ssr_port}"',')
		if [[ ! -z ${Modify_user} ]]; then
			break
		else
			echo -e "${Error} Silakan masukkan port yang benar !"
		fi
	done
}
Modify_Config(){
	SSR_installation_status
	echo && echo -e "SIlahkan pilih menu dibawah ini?
 ${Green_font_prefix}1.${Font_color_suffix}  Tambah User
 ${Green_font_prefix}2.${Font_color_suffix}  Hapus User
————— Ubah Konfigurasi Pengguna —————
 ${Green_font_prefix}3.${Font_color_suffix}  Ubah UserPassword
 ${Green_font_prefix}4.${Font_color_suffix}  Ubah Encryption Mode
 ${Green_font_prefix}5.${Font_color_suffix}  Ubah Plugin Protocol
 ${Green_font_prefix}6.${Font_color_suffix}  Ubah Plugin OBFS
 ${Green_font_prefix}7.${Font_color_suffix}  Ubah Device limit
 ${Green_font_prefix}8.${Font_color_suffix}  Ubah Single thread speed limit
 ${Green_font_prefix}9.${Font_color_suffix}  Ubah User total speed limit
 ${Green_font_prefix}10.${Font_color_suffix} Ubah Total user traffic
 ${Green_font_prefix}11.${Font_color_suffix} Ubah UserNonaktifkanport
 ${Green_font_prefix}12.${Font_color_suffix} Ubah Semua konfigurasi
————— Lainnya —————
 ${Green_font_prefix}13.${Font_color_suffix} Ubah Konfigurasi User, Tampilan IP atau nama domain
 
 ${Tip} Nama pengguna dan port pengguna tidak dapat Ubah, jika Anda perlu Ubah, silakan gunakan fungsi Ubah manual skrip. !" && echo
	read -e -p "(Default: Cancel):" ssr_modify
	[[ -z "${ssr_modify}" ]] && echo "Batalkan..." && exit 1
	if [[ ${ssr_modify} == "1" ]]; then
		Add_port_user
	elif [[ ${ssr_modify} == "2" ]]; then
		Del_port_user
	elif [[ ${ssr_modify} == "3" ]]; then
		Modify_port
		Set_config_password
		Modify_config_password
	elif [[ ${ssr_modify} == "4" ]]; then
		Modify_port
		Set_config_method
		Modify_config_method
	elif [[ ${ssr_modify} == "5" ]]; then
		Modify_port
		Set_config_protocol
		Modify_config_protocol
	elif [[ ${ssr_modify} == "6" ]]; then
		Modify_port
		Set_config_obfs
		Modify_config_obfs
	elif [[ ${ssr_modify} == "7" ]]; then
		Modify_port
		Set_config_protocol_param
		Modify_config_protocol_param
	elif [[ ${ssr_modify} == "8" ]]; then
		Modify_port
		Set_config_speed_limit_per_con
		Modify_config_speed_limit_per_con
	elif [[ ${ssr_modify} == "9" ]]; then
		Modify_port
		Set_config_speed_limit_per_user
		Modify_config_speed_limit_per_user
	elif [[ ${ssr_modify} == "10" ]]; then
		Modify_port
		Set_config_transfer
		Modify_config_transfer
	elif [[ ${ssr_modify} == "11" ]]; then
		Modify_port
		Set_config_forbid
		Modify_config_forbid
	elif [[ ${ssr_modify} == "12" ]]; then
		Modify_port
		Set_config_all "Modify"
		Modify_config_all
	elif [[ ${ssr_modify} == "13" ]]; then
		Set_user_api_server_pub_addr "Modify"
		Modify_user_api_server_pub_addr
	else
		echo -e "${Error} Silakan masukkan nomor yang benar(1-13)" && exit 1
	fi
}
List_port_user(){
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Tidak Ditemukan User，Silakan periksa !" && exit 1
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_username=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		Get_User_transfer "${user_port}"
		transfer_enable_Used_233=$(echo $((${transfer_enable_Used_233}+${transfer_enable_Used_2_1})))
		user_list_all=${user_list_all}"Username: ${Green_font_prefix} "${user_username}"${Font_color_suffix}\t port: ${Green_font_prefix}"${user_port}"${Font_color_suffix}\t Penggunaan Kuota(Digunakan + Sisa = Total): ${Green_font_prefix}${transfer_enable_Used_2}${Font_color_suffix} + ${Green_font_prefix}${transfer_enable_Used}${Font_color_suffix} = ${Green_font_prefix}${transfer_enable}${Font_color_suffix}\n"
	done
	Get_User_transfer_all
	echo && echo -e "=== Jumlah total pengguna ${Green_background_prefix} "${user_total}" ${Font_color_suffix}"
	echo -e ${user_list_all}
	echo -e "=== Jumlah saat ini dari semua kuota yang Digunakan Pengguna: ${Green_background_prefix} ${transfer_enable_Used_233_2} ${Font_color_suffix}\n"
}
Add_port_user(){
	lalal=$1
	if [[ "$lalal" == "install" ]]; then
		match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
	else
		while true
		do
			Set_config_all
			match_port=$(python mujson_mgr.py -l|grep -w "port ${ssr_port}$")
			[[ ! -z "${match_port}" ]] && echo -e "${Error} Port [${ssr_port}] Sudah ada, Harus Beda menambahkan !" && exit 1
			match_username=$(python mujson_mgr.py -l|grep -w "user \[${ssr_user}]")
			[[ ! -z "${match_username}" ]] && echo -e "${Error} Username [${ssr_user}] Sudah ada, Harus Beda menambahkan !" && exit 1
			match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
			if [[ -z "${match_add}" ]]; then
				echo -e "${Error} Penambahan user gagal ${Green_font_prefix}[Username: ${ssr_user} , port: ${ssr_port}]${Font_color_suffix} "
				break
			else
				Add_iptables
				Save_iptables
				echo -e "${Info} User berhasil ditambahkan ${Green_font_prefix}[Username: ${ssr_user} , port: ${ssr_port}]${Font_color_suffix} "
				echo
				read -e -p "Lanjutkan untuk menambahkan konfigurasi Pengguna?[Y/n]:" addyn
				[[ -z ${addyn} ]] && addyn="y"
				if [[ ${addyn} == [Nn] ]]; then
					Get_User_info "${ssr_port}"
					View_User_info
					break
				else
					echo -e "${Info} Lanjutkan untuk menambahkan konfigurasi Pengguna..."
				fi
			fi
		done
	fi
}
Del_port_user(){
	List_port_user
	while true
	do
		echo -e "Silakan masukkan user untuk dihapus port"
		read -e -p "(Default: Cancel):" del_user_port
		[[ -z "${del_user_port}" ]] && echo -e "Batalkan..." && exit 1
		del_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${del_user_port}"',')
		if [[ ! -z ${del_user} ]]; then
			port=${del_user_port}
			match_del=$(python mujson_mgr.py -d -p "${del_user_port}"|grep -w "delete user ")
			if [[ -z "${match_del}" ]]; then
				echo -e "${Error} User gagal dihapus ${Green_font_prefix}[port: ${del_user_port}]${Font_color_suffix} "
			else
				Del_iptables
				Save_iptables
				echo -e "${Info} User berhasil dihapus ${Green_font_prefix}[port: ${del_user_port}]${Font_color_suffix} "
			fi
			break
		else
			echo -e "${Error} Silakan masukkan port yang benar !"
		fi
	done
}
Manually_Modify_Config(){
	SSR_installation_status
	vi ${config_user_mudb_file}
	echo "Apakah Anda ingin memulai ulang ShadowsocksR sekarang?[Y/n]" && echo
	read -e -p "(Default: y):" yn
	[[ -z ${yn} ]] && yn="y"
	if [[ ${yn} == [Yy] ]]; then
		Restart_SSR
	fi
}
Clear_transfer(){
	SSR_installation_status
	echo && echo -e "Apa yang akan kamu lakukan?
 ${Green_font_prefix}1.${Font_color_suffix}  Bersihkan lalu lintas UserUsed tunggal
 ${Green_font_prefix}2.${Font_color_suffix}  Hapus semua lalu lintas yang Digunakan Pengguna (tidak dapat dipulihkan)
 ${Green_font_prefix}3.${Font_color_suffix}  Mulai Jangka waktu semua lalu lintas Pengguna jelas
 ${Green_font_prefix}4.${Font_color_suffix}  Hentikan Jangka waktu semua lalu lintas Pengguna dihapus
 ${Green_font_prefix}5.${Font_color_suffix}  Ubah waktu semua lalu lintas Pengguna dihapus" && echo
	read -e -p "(Default: Cancel):" ssr_modify
	[[ -z "${ssr_modify}" ]] && echo "Batalkan..." && exit 1
	if [[ ${ssr_modify} == "1" ]]; then
		Clear_transfer_one
	elif [[ ${ssr_modify} == "2" ]]; then
		echo "Apakah Anda yakin ingin menghapus semua lalu lintas yang Digunakan Pengguna?[y/N]" && echo
		read -e -p "(Default: n):" yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Yy] ]]; then
			Clear_transfer_all
		else
			echo "Cancel..."
		fi
	elif [[ ${ssr_modify} == "3" ]]; then
		check_crontab
		Set_crontab
		Clear_transfer_all_cron_start
	elif [[ ${ssr_modify} == "4" ]]; then
		check_crontab
		Clear_transfer_all_cron_stop
	elif [[ ${ssr_modify} == "5" ]]; then
		check_crontab
		Clear_transfer_all_cron_modify
	else
		echo -e "${Error} Silakan masukkan nomor yang benar(1-5)" && exit 1
	fi
}
Clear_transfer_one(){
	List_port_user
	while true
	do
		echo -e "Silakan masukkan port Pengguna untuk menghapus lalu lintas yang Digunakan."
		read -e -p "(Default: Cancel):" Clear_transfer_user_port
		[[ -z "${Clear_transfer_user_port}" ]] && echo -e "Batalkan..." && exit 1
		Clear_transfer_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${Clear_transfer_user_port}"',')
		if [[ ! -z ${Clear_transfer_user} ]]; then
			match_clear=$(python mujson_mgr.py -c -p "${Clear_transfer_user_port}"|grep -w "clear user ")
			if [[ -z "${match_clear}" ]]; then
				echo -e "${Error} UserUsed Pembersihan lalu lintas gagal ${Green_font_prefix}[port: ${Clear_transfer_user_port}]${Font_color_suffix} "
			else
				echo -e "${Info} UserUsed Lalu lintas berhasil diselesaikan ${Green_font_prefix}[port: ${Clear_transfer_user_port}]${Font_color_suffix} "
			fi
			break
		else
			echo -e "${Error} Silakan masukkan port yang benar !"
		fi
	done
}
Clear_transfer_all(){
	cd "${ssr_folder}"
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Tidak Ditemukan User，Silakan periksa !" && exit 1
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		match_clear=$(python mujson_mgr.py -c -p "${user_port}"|grep -w "clear user ")
		if [[ -z "${match_clear}" ]]; then
			echo -e "${Error} UserUsed Pembersihan lalu lintas gagal ${Green_font_prefix}[port: ${user_port}]${Font_color_suffix} "
		else
			echo -e "${Info} UserUsed Lalu lintas berhasil diselesaikan ${Green_font_prefix}[port: ${user_port}]${Font_color_suffix} "
		fi
	done
	echo -e "${Info} Semua lalu lintas Pengguna dihapus !"
}
Clear_transfer_all_cron_start(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh/d" "$file/crontab.bak"
	echo -e "\n${Crontab_time} /bin/bash $file/ssrmu.sh clearall" >> "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} Pengaturan waktu semua lalu lintas Pengguna jelas gagal untuk memulai !" && exit 1
	else
		echo -e "${Info} Pengaturan waktu semua lalu lintas Pengguna berhasil. !"
	fi
}
Clear_transfer_all_cron_stop(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh/d" "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} Mengatur waktu semua Pembersihan lalu lintas pengguna berhenti gagal !" && exit 1
	else
		echo -e "${Info} Pengaturan waktu semua lalu lintas Pengguna dihapus untuk berhenti dengan sukses !"
	fi
}
Clear_transfer_all_cron_modify(){
	Set_crontab
	Clear_transfer_all_cron_stop
	Clear_transfer_all_cron_start
}
Set_crontab(){
		echo -e "Silakan masukkan interval pembersihan lalu lintas
 === Deskripsi format ===
 * * * * * Sesuai dengan menit, jam, hari, bulan, minggu
 ${Green_font_prefix} 0 2 1 * * ${Font_color_suffix} Perwakilan 2: 0 pada tanggal 1 setiap bulan Bersihkan Lalu Lintas yang Digunakan
 ${Green_font_prefix} 0 2 15 * * ${Font_color_suffix} Perwakilan 2: 0 pada tanggal 15 setiap bulan Bersihkan Lalu Lintas yang Digunakan
 ${Green_font_prefix} 0 2 */7 * * ${Font_color_suffix} Perwakilan 2: 0 setiap 7 hari Hapus Lalu Lintas yang Digunakan
 ${Green_font_prefix} 0 2 * * 0 ${Font_color_suffix} Mewakili Setiap Minggu (7) Membersihkan Lalu Lintas Bekas
 ${Green_font_prefix} 0 2 * * 3 ${Font_color_suffix} Representative Every Wednesday (3) Hapus Lalu Lintas yang Digunakan" && echo
	read -e -p "(Default: 0 2 1 * * 2:00 pada tanggal 1 setiap bulan):" Crontab_time
	[[ -z "${Crontab_time}" ]] && Crontab_time="0 2 1 * *"
}
Start_SSR(){
	SSR_installation_status
	check_pid
	[[ ! -z ${PID} ]] && echo -e "${Error} ShadowsocksR sedang berjalan !" && exit 1
	/etc/init.d/ssrmu start
}
Stop_SSR(){
	SSR_installation_status
	check_pid
	[[ -z ${PID} ]] && echo -e "${Error} ShadowsocksR tidak berjalan !" && exit 1
	/etc/init.d/ssrmu stop
}
Restart_SSR(){
	SSR_installation_status
	check_pid
	[[ ! -z ${PID} ]] && /etc/init.d/ssrmu stop
	/etc/init.d/ssrmu start
}
View_Log(){
	SSR_installation_status
	[[ ! -e ${ssr_log_file} ]] && echo -e "${Error} File log ShadowsocksR tidak ada !" && exit 1
	echo && echo -e "${Tip} Tekan ${Red_font_prefix}Ctrl+C${Font_color_suffix} Hentikan log tampilan" && echo -e "Jika Anda perlu melihat konten log lengkap, silakan gunakan ${Red_font_prefix}cat ${ssr_log_file}${Font_color_suffix} Perintah." && echo
	tail -f ${ssr_log_file}
}
# Kecepatan tajam
Configure_Server_Speeder(){
	echo && echo -e "Apa yang akan kamu lakukan?
 ${Green_font_prefix}1.${Font_color_suffix} installation Kecepatan tajam
 ${Green_font_prefix}2.${Font_color_suffix} Copot pemasangan Kecepatan tajam
————————
 ${Green_font_prefix}3.${Font_color_suffix} Mulai Kecepatan tajam
 ${Green_font_prefix}4.${Font_color_suffix} Berhenti Kecepatan tajam
 ${Green_font_prefix}5.${Font_color_suffix} Mulai ulang Kecepatan tajam
 ${Green_font_prefix}6.${Font_color_suffix} Lihat status Kecepatan tajam
 
 Catatan: Kecepatan tajam dan LotServer tidak dapat diinstal / dimulai pada saat yang sama!" && echo
	read -e -p "(Default: Cancel):" server_speeder_num
	[[ -z "${server_speeder_num}" ]] && echo "Batalkan..." && exit 1
	if [[ ${server_speeder_num} == "1" ]]; then
		Install_ServerSpeeder
	elif [[ ${server_speeder_num} == "2" ]]; then
		Server_Speeder_installation_status
		Uninstall_ServerSpeeder
	elif [[ ${server_speeder_num} == "3" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} start
		${Server_Speeder_file} status
	elif [[ ${server_speeder_num} == "4" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} stop
	elif [[ ${server_speeder_num} == "5" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} restart
		${Server_Speeder_file} status
	elif [[ ${server_speeder_num} == "6" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} status
	else
		echo -e "${Error} Silakan masukkan nomor yang benar(1-6)" && exit 1
	fi
}
Install_ServerSpeeder(){
	[[ -e ${Server_Speeder_file} ]] && echo -e "${Error} Kecepatan tajam(Server Speeder) Installed !" && exit 1
	#Pinjam versi bahagia dari 91yun.rog Kecepatan tajam
	wget --no-check-certificate -qO /tmp/serverspeeder.sh https://raw.githubusercontent.com/91yun/serverspeeder/master/serverspeeder.sh
	[[ ! -e "/tmp/serverspeeder.sh" ]] && echo -e "${Error} Kecepatan tajaminstallationUnduhan skrip gagal !" && exit 1
	bash /tmp/serverspeeder.sh
	sleep 2s
	PID=`ps -ef |grep -v grep |grep "serverspeeder" |awk '{print $2}'`
	if [[ ! -z ${PID} ]]; then
		rm -rf /tmp/serverspeeder.sh
		rm -rf /tmp/91yunserverspeeder
		rm -rf /tmp/91yunserverspeeder.tar.gz
		echo -e "${Info} Kecepatan tajam(Server Speeder) Instalasi selesai !" && exit 1
	else
		echo -e "${Error} Kecepatan tajam(Server Speeder) Instalasi gagal !" && exit 1
	fi
}
Uninstall_ServerSpeeder(){
	echo "Oke untuk uninstall Kecepatan tajam(Server Speeder)？[y/N]" && echo
	read -e -p "(Default: n):" unyn
	[[ -z ${unyn} ]] && echo && echo "Batalkan..." && exit 1
	if [[ ${unyn} == [Yy] ]]; then
		chattr -i /serverspeeder/etc/apx*
		/serverspeeder/bin/serverSpeeder.sh uninstall -f
		echo && echo "Kecepatan tajam(Server Speeder) Penghapusan instalasi selesai !" && echo
	fi
}
# LotServer
Configure_LotServer(){
	echo && echo -e "Apa yang akan kamu lakukan?
 ${Green_font_prefix}1.${Font_color_suffix} installation LotServer
 ${Green_font_prefix}2.${Font_color_suffix} Copot pemasangan LotServer
————————
 ${Green_font_prefix}3.${Font_color_suffix} Mulai LotServer
 ${Green_font_prefix}4.${Font_color_suffix} Berhenti LotServer
 ${Green_font_prefix}5.${Font_color_suffix} Mulai ulang LotServer
 ${Green_font_prefix}6.${Font_color_suffix} Lihat status LotServer
 
 Catatan: Kecepatan tajam dan LotServer tidak dapat diinstal / dimulai pada saat yang sama!" && echo
	read -e -p "(Default: Cancel):" lotserver_num
	[[ -z "${lotserver_num}" ]] && echo "Batalkan..." && exit 1
	if [[ ${lotserver_num} == "1" ]]; then
		Install_LotServer
	elif [[ ${lotserver_num} == "2" ]]; then
		LotServer_installation_status
		Uninstall_LotServer
	elif [[ ${lotserver_num} == "3" ]]; then
		LotServer_installation_status
		${LotServer_file} start
		${LotServer_file} status
	elif [[ ${lotserver_num} == "4" ]]; then
		LotServer_installation_status
		${LotServer_file} stop
	elif [[ ${lotserver_num} == "5" ]]; then
		LotServer_installation_status
		${LotServer_file} restart
		${LotServer_file} status
	elif [[ ${lotserver_num} == "6" ]]; then
		LotServer_installation_status
		${LotServer_file} status
	else
		echo -e "${Error} Silakan masukkan nomor yang benar(1-6)" && exit 1
	fi
}
Install_LotServer(){
	[[ -e ${LotServer_file} ]] && echo -e "${Error} LotServer Installed !" && exit 1
	#Github: https://github.com/0oVicero0/serverSpeeder_Install
	wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh"
	[[ ! -e "/tmp/appex.sh" ]] && echo -e "${Error} LotServer installationUnduhan skrip gagal !" && exit 1
	bash /tmp/appex.sh 'install'
	sleep 2s
	PID=`ps -ef |grep -v grep |grep "appex" |awk '{print $2}'`
	if [[ ! -z ${PID} ]]; then
		echo -e "${Info} LotServer Instalasi selesai !" && exit 1
	else
		echo -e "${Error} LotServer Instalasi gagal !" && exit 1
	fi
}
Uninstall_LotServer(){
	echo "Oke untuk uninstall LotServer？[y/N]" && echo
	read -e -p "(Default: n):" unyn
	[[ -z ${unyn} ]] && echo && echo "Batalkan..." && exit 1
	if [[ ${unyn} == [Yy] ]]; then
		wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh" && bash /tmp/appex.sh 'uninstall'
		echo && echo "LotServer Penghapusan instalasi selesai !" && echo
	fi
}
# BBR
Configure_BBR(){
	echo && echo -e "  Apa yang akan kamu lakukan?
	
 ${Green_font_prefix}1.${Font_color_suffix} installation BBR
————————
 ${Green_font_prefix}2.${Font_color_suffix} Mulai BBR
 ${Green_font_prefix}3.${Font_color_suffix} Berhenti BBR
 ${Green_font_prefix}4.${Font_color_suffix} Lihat status BBR" && echo
echo -e "${Green_font_prefix} [Sebelum instalasi, harap diperhatikan] ${Font_color_suffix}
1. Instalasi memulai BBR, kernel perlu diganti, dan ada risiko kegagalan penggantian.(Tidak dapat boot setelah reboot)
2. Skrip ini hanya mendukung kernel pengganti sistem Debian / Ubuntu, OpenVZ dan Docker tidak mendukung penggantian kernel
3. Debian akan meminta selama proses penggantian kernel [Apakah Anda ingin menghentikan penghapusan kernel], silakan pilih ${Green_font_prefix} NO ${Font_color_suffix}" && echo
	read -e -p "(Default: Cancel):" bbr_num
	[[ -z "${bbr_num}" ]] && echo "Batalkan..." && exit 1
	if [[ ${bbr_num} == "1" ]]; then
		Install_BBR
	elif [[ ${bbr_num} == "2" ]]; then
		Start_BBR
	elif [[ ${bbr_num} == "3" ]]; then
		Stop_BBR
	elif [[ ${bbr_num} == "4" ]]; then
		Status_BBR
	else
		echo -e "${Error} Silakan masukkan nomor yang benar(1-4)" && exit 1
	fi
}
Install_BBR(){
	[[ ${release} = "centos" ]] && echo -e "${Error} Skrip ini tidak mendukung instalasi sistem CentOS BBR !" && exit 1
	BBR_installation_status
	bash "${BBR_file}"
}
Start_BBR(){
	BBR_installation_status
	bash "${BBR_file}" start
}
Stop_BBR(){
	BBR_installation_status
	bash "${BBR_file}" stop
}
Status_BBR(){
	BBR_installation_status
	bash "${BBR_file}" status
}
# Fungsi lainnya
Other_functions(){
	echo && echo -e "  Apa yang akan kamu lakukan?
	
  ${Green_font_prefix}1.${Font_color_suffix} Konfigurasi BBR
  ${Green_font_prefix}2.${Font_color_suffix} Konfigurasi Kecepatan tajam(ServerSpeeder)
  ${Green_font_prefix}3.${Font_color_suffix} Konfigurasi LotServer(Perusahaan induk Kecepatan tajam)
  ${Tip} Kecepatan tajam/LotServer/BBR Tidak didukung OpenVZ！
  ${Tip} Kecepatan Tajam dan LotServer tidak bisa hidup berdampingan!
————————————
  ${Green_font_prefix}4.${Font_color_suffix} 一Larangan satu tombol BT/PT/SPAM (iptables)
  ${Green_font_prefix}5.${Font_color_suffix} 一Satu tombol membuka blokir BT/PT/SPAM (iptables)
————————————
  ${Green_font_prefix}6.${Font_color_suffix} Beralih ke mode keluaran log ShadowsocksR
  —— Catatan: SSRDefault hanya menampilkan log kesalahan. Item ini dapat dialihkan ke keluaran log akses terperinci.
  ${Green_font_prefix}7.${Font_color_suffix} Monitor status Server ShadowsocksR berjalan
  —— Deskripsi: Fungsi ini cocok untuk server SSR untuk mengakhiri proses. Setelah fungsi dimulai, ia akan terdeteksi setiap menit. Ketika proses tidak ada, server SSR akan dimulai secara otomatis." && echo
	read -e -p "(Default: Cancel):" other_num
	[[ -z "${other_num}" ]] && echo "Batalkan..." && exit 1
	if [[ ${other_num} == "1" ]]; then
		Configure_BBR
	elif [[ ${other_num} == "2" ]]; then
		Configure_Server_Speeder
	elif [[ ${other_num} == "3" ]]; then
		Configure_LotServer
	elif [[ ${other_num} == "4" ]]; then
		BanBTPTSPAM
	elif [[ ${other_num} == "5" ]]; then
		UnBanBTPTSPAM
	elif [[ ${other_num} == "6" ]]; then
		Set_config_connect_verbose_info
	elif [[ ${other_num} == "7" ]]; then
		Set_crontab_monitor_ssr
	else
		echo -e "${Error} Silakan masukkan nomor yang benar [1-7]" && exit 1
	fi
}
# Dilarang BT PT SPAM
BanBTPTSPAM(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ban_iptables.sh && chmod +x ban_iptables.sh && bash ban_iptables.sh banall
	rm -rf ban_iptables.sh
}
# Buka blokir BT PT SPAM
UnBanBTPTSPAM(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ban_iptables.sh && chmod +x ban_iptables.sh && bash ban_iptables.sh unbanall
	rm -rf ban_iptables.sh
}
Set_config_connect_verbose_info(){
	SSR_installation_status
	[[ ! -e ${jq_file} ]] && echo -e "${Error} Parser JQ Tidak ada, Silakan periksa !" && exit 1
	connect_verbose_info=`${jq_file} '.connect_verbose_info' ${config_user_file}`
	if [[ ${connect_verbose_info} = "0" ]]; then
		echo && echo -e "Mode log saat ini: ${Green_font_prefix}Mode sederhana (hanya log kesalahan keluaran)${Font_color_suffix}" && echo
		echo -e "OK untuk beralih ke ${Green_font_prefix}Mode terperinci (keluaran detail log koneksi + log kesalahan)${Font_color_suffix}？[y/N]"
		read -e -p "(Default: n):" connect_verbose_info_ny
		[[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
		if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
			ssr_connect_verbose_info="1"
			Modify_config_connect_verbose_info
			Restart_SSR
		else
			echo && echo "	Batalkan..." && echo
		fi
	else
		echo && echo -e "Mode log saat ini: ${Green_font_prefix}Mode terperinci (keluaran detail log koneksi + log kesalahan)${Font_color_suffix}" && echo
		echo -e "OK untuk beralih ke ${Green_font_prefix}Mode sederhana (hanya log kesalahan keluaran)${Font_color_suffix}？[y/N]"
		read -e -p "(Default: n):" connect_verbose_info_ny
		[[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
		if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
			ssr_connect_verbose_info="0"
			Modify_config_connect_verbose_info
			Restart_SSR
		else
			echo && echo "	Batalkan..." && echo
		fi
	fi
}
Set_crontab_monitor_ssr(){
	SSR_installation_status
	crontab_monitor_ssr_status=$(crontab -l|grep "ssrmu.sh monitor")
	if [[ -z "${crontab_monitor_ssr_status}" ]]; then
		echo && echo -e "Mode pemantauan saat ini: ${Green_font_prefix}Tidak terbuka${Font_color_suffix}" && echo
		echo -e "Pastikan Anda ingin menyalakannya ${Green_font_prefix}Server ShadowsocksR menjalankan pemantauan status${Font_color_suffix} Fungsi? (Server SSR secara otomatis dimulai ketika proses ditutup)[Y/n]"
		read -e -p "(Default: y):" crontab_monitor_ssr_status_ny
		[[ -z "${crontab_monitor_ssr_status_ny}" ]] && crontab_monitor_ssr_status_ny="y"
		if [[ ${crontab_monitor_ssr_status_ny} == [Yy] ]]; then
			crontab_monitor_ssr_cron_start
		else
			echo && echo "	Batalkan..." && echo
		fi
	else
		echo && echo -e "Mode pemantauan saat ini: ${Green_font_prefix}已开启${Font_color_suffix}" && echo
		echo -e "OK untuk mematikan ${Green_font_prefix}Server ShadowsocksR menjalankan pemantauan status${Font_color_suffix} Fungsi? (Server SSR secara otomatis dimulai ketika proses ditutup)[y/N]"
		read -e -p "(Default: n):" crontab_monitor_ssr_status_ny
		[[ -z "${crontab_monitor_ssr_status_ny}" ]] && crontab_monitor_ssr_status_ny="n"
		if [[ ${crontab_monitor_ssr_status_ny} == [Yy] ]]; then
			crontab_monitor_ssr_cron_stop
		else
			echo && echo "	Batalkan..." && echo
		fi
	fi
}
crontab_monitor_ssr(){
	SSR_installation_status
	check_pid
	if [[ -z ${PID} ]]; then
		echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Terdeteksi Server ShadowsocksR Tidak berjalan, mulai untuk memulai..." | tee -a ${ssr_log_file}
		/etc/init.d/ssrmu start
		sleep 1s
		check_pid
		if [[ -z ${PID} ]]; then
			echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Server ShadowsocksR Kegagalan startup..." | tee -a ${ssr_log_file} && exit 1
		else
			echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Server ShadowsocksR Startup yang sukses..." | tee -a ${ssr_log_file} && exit 1
		fi
	else
		echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Server ShadowsocksR Proses berjalan normal..." exit 0
	fi
}
crontab_monitor_ssr_cron_start(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh monitor/d" "$file/crontab.bak"
	echo -e "\n* * * * * /bin/bash $file/ssrmu.sh monitor" >> "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh monitor")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} Server ShadowsocksR menjalankan pemantauan Fungsi status gagal memulai !" && exit 1
	else
		echo -e "${Info} Server ShadowsocksR menjalankan pemantauan Fungsi status mulai berhasil !"
	fi
}
crontab_monitor_ssr_cron_stop(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh monitor/d" "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh monitor")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} Server ShadowsocksR menjalankan pemantauan Berhenti fungsi status gagal !" && exit 1
	else
		echo -e "${Info} Server ShadowsocksR menjalankan pemantauan Fungsi status berhenti dengan sukses !"
	fi
}
Update_Shell(){
	sh_new_ver=$(wget --no-check-certificate -qO- -t1 -T3 "https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ssrmu.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1) && sh_new_type="github"
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} Tidak dapat ditautkan ke Github !" && exit 0
	if [[ -e "/etc/init.d/ssrmu" ]]; then
		rm -rf /etc/init.d/ssrmu
		Service_SSR
	fi
	cd "${file}"
	wget -N --no-check-certificate "https://raw.githubusercontent.com/ToyoDAdoubi/doubi/master/ssrmu.sh" && chmod +x ssrmu.sh
	echo -e "Skrip telah diperbarui ke versi terbaru [$ {sh_new_ver}]! (Catatan: Karena metode pembaruan adalah untuk langsung menimpa skrip yang sedang berjalan, mungkin salah untuk melaporkan beberapa kesalahan di bawah ini, abaikan saja)" && exit 0
}
# Tampilan 菜单状态
menu_status(){
	if [[ -e ${ssr_folder} ]]; then
		check_pid
		if [[ ! -z "${PID}" ]]; then
			echo -e " Kondisi saat ini: ${Green_font_prefix}Installed${Font_color_suffix} 并 ${Green_font_prefix}Mulai${Font_color_suffix}"
		else
			echo -e " Kondisi saat ini: ${Green_font_prefix}Installed${Font_color_suffix} 但 ${Red_font_prefix}Belum dimulai${Font_color_suffix}"
		fi
		cd "${ssr_folder}"
	else
		echo -e " Kondisi saat ini: ${Red_font_prefix}Tidak terpasang${Font_color_suffix}"
	fi
}
check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} Skrip ini tidak mendukung sistem saat ini ${release} !" && exit 1
action=$1
if [[ "${action}" == "clearall" ]]; then
	Clear_transfer_all
elif [[ "${action}" == "monitor" ]]; then
	crontab_monitor_ssr
else
	echo -e "  ShadowsocksR MuJSON skrip manajemen sekali klik ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
  ---- GlobalSSH | globalssh.net ----

  ${Green_font_prefix}1.${Font_color_suffix} installation ShadowsocksR
  ${Green_font_prefix}2.${Font_color_suffix} Perbarui ShadowsocksR
  ${Green_font_prefix}3.${Font_color_suffix} Copot pemasangan ShadowsocksR
  ${Green_font_prefix}4.${Font_color_suffix} installation libsodium(chacha20)
————————————
  ${Green_font_prefix}5.${Font_color_suffix} Lihat informasi akun
  ${Green_font_prefix}6.${Font_color_suffix} Tampilkan Informasi koneksi
  ${Green_font_prefix}7.${Font_color_suffix} Pengaturan UserKonfigurasi
  ${Green_font_prefix}8.${Font_color_suffix} Manual UbahKonfigurasi
  ${Green_font_prefix}9.${Font_color_suffix} Konfigurasi Kosongkan lalu lintas
————————————
 ${Green_font_prefix}10.${Font_color_suffix} Mulai ShadowsocksR
 ${Green_font_prefix}11.${Font_color_suffix} Berhenti ShadowsocksR
 ${Green_font_prefix}12.${Font_color_suffix} Mulai ulang ShadowsocksR
 ${Green_font_prefix}13.${Font_color_suffix} Lihat log ShadowsocksR
————————————
 ${Green_font_prefix}14.${Font_color_suffix} Fungsi lainnya
 ${Green_font_prefix}15.${Font_color_suffix} Perbarui skrip
 "
	menu_status
	echo && read -e -p "Silakan masukkan nomor [1-15]：" num
case "$num" in
	1)
	Install_SSR
	;;
	2)
	Update_SSR
	;;
	3)
	Uninstall_SSR
	;;
	4)
	Install_Libsodium
	;;
	5)
	View_User
	;;
	6)
	View_user_connection_info
	;;
	7)
	Modify_Config
	;;
	8)
	Manually_Modify_Config
	;;
	9)
	Clear_transfer
	;;
	10)
	Start_SSR
	;;
	11)
	Stop_SSR
	;;
	12)
	Restart_SSR
	;;
	13)
	View_Log
	;;
	14)
	Other_functions
	;;
	15)
	Update_Shell
	;;
	*)
	echo -e "${Error} Silakan masukkan nomor yang benar [1-15]"
	;;
esac
fi
