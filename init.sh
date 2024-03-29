#!/bin/bash

########################################################################################
########################## Init script - run by root ###################################
########################################################################################

# Variables - script d'initialisation

DIRECTORY=$(cd `dirname $0` && pwd)
SUDOERS='/etc/sudoers'
BACKUP='/etc/sudoers.backup'
USER='sgauguet'
ALIAS="/home/$USER/.bash_aliases"

# Couleurs

GREEN='\033[32m'
YL='\033[1;33m'
INT='\033[1;30m'
RED='\033[1;31m'
RES='\033[0m'

# Verification - le script doit etre lance par root

if (($EUID != 0)); then
	echo -e "${RED}Please run as root${RES}"
	exit 1;
fi

echo -e "${INT}**************
**   INIT  ***
**************$RES"

apt-get update && apt-get upgrade

echo -e "${GREEN}Gestion des utilisateurs - installation des paquets necessaires$RES"
if [ $(dpkg-query -W -f='${Status}' sudo 2> /dev/null | grep -c "ok installed") -eq 0 ]; then
	apt-get install -y sudo
fi
if [ $(dpkg-query -W -f='${Status}' vim 2> /dev/null | grep -c "ok installed") -eq 0 ]; then
	apt-get install -y vim
fi
echo  -e "${GREEN}Parametrage des droits de l'utilisateur non root$RES"
if [ ! -f $BACKUP ]
then
	echo  -e "${GREEN}Sauvegarde des parametres initiaux : $BACKUP $RES"
	cp $SUDOERS $BACKUP
fi
echo "$USER ALL=(ALL:ALL) ALL" >> $SUDOERS

# Configuration de l'acces SSH de l'utilisateur

mkdir -p /home/$USER/.ssh
touch /home/$USER/.ssh/authorized_keys
chmod 700 /home/$USER/.ssh
chmod 600 /home/$USER/.ssh/authorized_keys
chown -R $USER /home/$USER/.ssh

# Creation des alias / necessite source ~./bashrc pour etre active
	# -> rs1-edit = modifier le script d'installation
	# -> rs1-exec = lancer le script d'installation
	# -> rs1-logs = consulter les logs

echo  -e "${GREEN}Creation des alias$RES"
if [ ! -f $ALIAS ]
then
	touch $ALIAS
	echo "alias rs1-exec=\"sudo $DIRECTORY/deployment.sh\"" >> $ALIAS
	echo "alias rs1-edit=\"sudo vim $DIRECTORY/init.sh\"" >> $ALIAS
	echo "alias rs1-logs=\"sudo tail -n 20 /var/log/messages\"" >> $ALIAS
	
	# Configuration de vim
	
	echo "set number
	syntax on" > /home/$USER/.vimrc
	echo "set number
	syntax on" > /root/.vimrc
fi

rm -f $DIRECTORY/deployment.sh

########################################################################################
########################## Configuration script  - run by user #########################
########################################################################################

echo "#!/bin/bash

# Variables - script de configuration

NI='/etc/network'
RESOLV='/etc/resolv.conf'
SSH='/etc/ssh/sshd_config'
F2B='/etc/fail2ban'
USER='sgauguet'
IP='10.177.42.221'
IP_B='10.11.200.131'
GATE_B='10.11.254.254'
PORT_SSH='59112'

# Couleurs

GREEN='\033[32m'
RED='\033[1;31m'
RES='\033[0m'

# Verification - le script doit etre lance avec sudo

if ((\$EUID != 0)); then
	echo -e \"\${RED}Please run with sudo\${RES}\"
	exit 1;
fi

# Installation des paquets

install() {
for package in \"\$@\"
do
	if [ \$(dpkg-query -W -f='\${Status}' \$package 2>/dev/null | grep -c \"ok installed\") -eq \"0\" ]
	then
		echo -e \"\${GREEN}Installation de \${package} \${RES}\";
		apt-get -y install \$package
		if [ \$? -ne \"0\" ]; then
			echo -e \"\${RED}échec de l'installation de \${package}\${RES}\";
		fi
	else
		echo -e \"\${GREEN}\${package} déjà installé\${RES}\";
	fi
done
}

install vim git sudo net-tools fail2ban nmap ssh openssh-server iptables-persistent curl gnupg2 ca-certificates lsb-release resolvconf portsentry

if [ ! -f /etc/apt/sources.list.d/nginx.list ]
then
	echo \"deb http://nginx.org/packages/debian/ `lsb_release -cs` nginx
	deb-src http://nginx.org/packages/debian/ stretch nginx\" > /etc/apt/sources.list.d/nginx.list
	curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add -
	apt-key fingerprint ABF5BD827BD9BF62
	apt update
	apt install -y nginx
fi

#apt-get -y remove exim4 exim4-base exim4-config exim4-daemon-light

#adduser test
#adduser test sudo

# Configuration de l'adresse IP

echo -e \"\${GREEN}Configuration du réseau - IP fixe\${RES}\";

if [ ! -f \$NI/interfaces.backup ]
then
	echo  -e \"\${GREEN}Sauvegarde des parametres initiaux : \$NI/interfaces.backup \$RES\"
	cp \$NI/interfaces \$NI/interfaces.backup
	cp \$RESOLV \$RESOLV.backup
	read -p \"bridge or NAT network ?:  \"  type;
	if [ \"\$type\"  == \"bridge\" ]
	then
		echo -e \"\${GREEN}Mise en place de la nouvelle configuration\${RES}\"
		sed -i '11,\$d' \$NI/interfaces
		echo \"auto enp0s3
		iface enp0s3 inet static
		address \$IP_B
		netmask 255.255.255.252
		gateway \$GATE_B
		dns-search 42.fr
		dns-nameserver 10.51.1.42
		dns-nameserver 10.51.1.43
		dns-nameserver 10.188.0.1\" >> /\$NI/interfaces
	else
		echo -e \"\${GREEN}Mise en place de la nouvelle configuration\${RES}\"
		sed -i '11,\$d' \$NI/interfaces
		echo \"auto enp0s3
		iface enp0s3 inet static
		address \$IP
		netmask 255.255.255.252
		broadcast 10.177.42.223
		network 10.177.42.220
		gateway 10.177.42.222
		dns-search 42.fr
		dns-nameserver 10.51.1.42
		dns-nameserver 10.51.1.43
		dns-nameserver 10.188.0.1\" >> /\$NI/interfaces
	fi
	# Mise a jour et test de la configuration du reseau
	ifdown enp0s3 &>/dev/null
	ifup enp0s3 &>/dev/null
	/etc/init.d/networking restart
	if [ \"\$type\" == \"bridge\" ]
	then
		echo -e \"\${GREEN}Eteindre la VM et activer le mode bridge,puis rs1-exec\${RES}\"
	else
		echo -e \"\${GREEN}Eteindre la VM et activer le réseau NAT avec CIDR Réseau 10.177.42.220/30,puis rs1-exec\${RES}\"
	fi
	exit 0;
fi

echo -e \"\${GREEN}Test de la nouvelle configuration\${RES}\"
if [ ping -c4 www.google.fr &> /dev/null ]
then
	echo -e \"\${RED}Echec\$RES\"
	exit 1;
else
	echo -e \"\${GREEN}Success\${RES}\"
fi

# Configuration de l'acces SSH

echo -e \"\${GREEN}Configuration SSH\${RES}\";

if [ ! -f \$SSH.backup ]
then
	echo  -e \"\${GREEN}Sauvegarde de la configuration ssh : \$SSH.backup\$RES\"
	cp \$SSH \$SSH.backup
fi

echo  -e \"\${GREEN}Modification du port SSH\$RES\"

cat \$SSH.backup > \$SSH
echo \"Port \$PORT_SSH
PermitRootLogin no
PermitEmptyPasswords yes
#AuthentificationMethods password
\" >> \$SSH

service sshd restart

# Mise en place de l'acces par publickeys

echo -e \"\${GREEN}Publikeys SSH\${RES}\"
cp $DIRECTORY/config/publickey /home/\$USER/.ssh/authorized_keys
#ssh-keygen -t rsa -f /home/\$USER/.ssh/id_rsa -P \"\"
#ssh-copy-id -f -i /home/\$USER/.ssh/id_rsa.pub -p \$PORT_SSH \$USER@\$IP

cat \$SSH.backup > \$SSH
echo \"Port \$PORT_SSH
PermitRootLogin no
PermitEmptyPasswords no
AuthenticationMethods publickey
\" >> \$SSH

service sshd restart

# Test de la configuration SSH

#echo -e \"\${GREEN}Test de la nouvelle configuration\${RES}\"
#if [[ \$(nmap -A -p 59112 --open 10.177.42.221 | grep -c open ) -eq 0 && \$(nmap -A -p 59112 --open \$IP_B | grep -c open ) -eq 0]];
#then
#	echo -e \"\${RED}Echec\$RES\"
#	exit 1;
#else
#	echo -e \"\${GREEN}Success\${RES}\"
#fi

########################## Script de configuration d'iptables ##########################

echo \"#!/bin/bash

# Variables
IP=\\\$(/sbin/ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/')
IPT=\\\"/sbin/iptables\\\"

# Reinitialisation
\\\$IPT -F
\\\$IPT -X
\\\$IPT -t nat -F
\\\$IPT -t nat -X
\\\$IPT -t mangle -F
\\\$IPT -t mangle -X

# Blocage par defaut du trafic entrant
\\\$IPT -P INPUT DROP

# Blocage par defaut du forward
\\\$IPT -P FORWARD DROP

# Autorisation par defaut du trafic sortant
\\\$IPT -P OUTPUT ACCEPT

# Blocage des scans XMAS et NULL
\\\$IPT -A INPUT -p tcp --tcp-flags FIN,URG,PSH FIN,URG,PSH -j DROP
\\\$IPT -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
\\\$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
\\\$IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

# Permettre à une connexion ouverte de recevoir du trafic en entrée.
\\\$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Pas de filtrage sur la boucle locale
#\\\$IPT -A INPUT -i lo -j ACCEPT

# Ping
\\\$IPT -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
\\\$IPT -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
\\\$IPT -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT

# SSH
\\\$IPT -A INPUT -p tcp --dport 59112 -j ACCEPT

# NTP
#\\\$IPT -A INPUT -p udp --dport 123 -j ACCEPT

# imap(s)
#\\\$IPT -A INPUT -p tcp --dport 143 -j ACCEPT
#\\\$IPT -A INPUT -p tcp --dport 993 -j ACCEPT

# dns
\\\$IPT -A INPUT -p tcp --dport domain -j ACCEPT
\\\$IPT -A INPUT -p udp --dport domain -j ACCEPT

# http
\\\$IPT -A INPUT -p tcp --dport http -j ACCEPT

# https
\\\$IPT -A INPUT -p tcp --dport https -j ACCEPT

# Logs
\\\$IPT -A INPUT -j LOG --log-prefix \\\"-- IPv4 packet rejected -- \\\"
\" > /etc/network/iptables.rules

########################################################################################

# Activation du pare-feu

echo  -e \"\${GREEN}Mise en place du parefeu\$RES\"
if [ ! -f /etc/network/iptables.rules ]
then
	echo  -e \"\${RED}Erreur\$RES\"
	exit 1
else
	chmod +x /etc/network/iptables.rules
	/etc/network/iptables.rules
fi

if [ \$(lsmod | grep -c conntrack) -eq 0 ]
then
	modprob ip_conntrack
fi

# Enregistrement des regles du pare-feu

iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

# Configuration du kernel

# -> protection contre l’usurpation d’adresse IP / antispoofing
# -> journalisation des paquets ayant une adresse IP mal formée 
# -> refus des redirections ICMP
# -> refus des paquets dont la source a été routée
# -> protection contre les dénis de service
# -> ignore les broadcast ICMP
# -> ignore les erreurs ICMP bogus
# -> désactive la réponse aux ICMP redirects.
# -> désactiver l’envoi de ICMP redirects.
# -> limite a 1 jour le delai maximum d'une connexion
# -> desactive la recuperation des connexions etablies
# -> active les timestamps
# -> fixe le nombre de connexions simultanees

if [ ! -f /etc/sysctl.conf.backup ]
then
	echo  -e \"\${GREEN}Sauvegarde de systctl.conf\$RES\"
	cp /etc/sysctl.conf /etc/sysctl.conf.backup
fi

echo \"net.ipv4.conf.all.rp_filter = 1
net/ipv4/conf/all/log_martians = 1
net/ipv4/conf/all/send_redirects = 0
net/ipv4/conf/all/accept_redirects = 0
net/ipv4/conf/all/accept_source_route = 0
net/ipv4/tcp_syncookies = 1
net/ipv4/icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects= 0
net.netfilter.nf_conntrack_tcp_timeout_established = 86400
net.netfilter.nf_conntrack_tcp_loose = 0
net.ipv4.tcp_timestamps = 1
net.netfilter.nf_conntrack_max = 65536\" >> /etc/sysctl.conf

sysctl -p &>/dev/null

# Détection et blocage des \"scans de ports\" 

echo  -e \"\${GREEN}Configuration de portsentry\$RES\"
sed -i '9,\$d' /etc/default/portsentry
echo \"
TCP_MODE=\\\"atcp\\\"
UDP_MODE=\\\"audp\\\"\" >> /etc/default/portsentry

cp $DIRECTORY/config/portsentry /etc/portsentry/portsentry.conf

service portsentry restart

# Arrêt des services non utilisés (systemctl list-unit-files --type=service --state=enabled)

echo  -e \"\${GREEN}Arrêt des services non utiles\$RES\"
#systemctl disable autovt@.service                          
systemctl disable console-setup.service          
#systemctl disable dbus-org.bluez.service         
#systemctl disable getty@.service                 
systemctl disable keyboard-setup.service
#systemctl disable sshd.service 
#systemctl disable networking.service                               
#systemctl disable resolvconf.service             
systemctl disable rsync.service                  
#systemctl disable rsyslog.service                                   
#systemctl disable syslog.service                 
systemctl disable systemd-timesyncd.service                       

# Parametrage de fail2ban

if [ ! -f /etc/nginx/nginx.backup ]
then
cp /etc/nginx/nginx.conf /etc/nginx/nginx.backup
sed -i \"15a #Requete maximun par ip\nlimit_req_zone \\\$binary_remote_addr zone=flood:10m rate=1r/s;\n#Connexions maximum par ip\nlimit_conn_zone \\\$binary_remote_addr zone=ddos:10m;\n\" /etc/nginx/nginx.conf
fi

echo \"
# Fail2Ban configuration file 
# 
# supports: ngx_http_limit_conn_module 

[Definition] 

failregex = limiting connections by zone.*client: <HOST> 

# Option: ignoreregex 
# Notes.: regex to ignore. If this regex matches, the line is ignored. 
# Values: TEXT 
# 
ignoreregex = 
\" > \$F2B/filter.d/nginx-conn-limit.conf

echo \"
# Fail2Ban configuration file 
# 
# supports: ngx_http_limit_req_module 

[Definition] 

failregex = ^<HOST> -.*\\\"(GET|POST).*HTTP.*\\\"$

# Option: ignoreregex 
# Notes.: regex to ignore. If this regex matches, the line is ignored. 
# Values: TEXT 
# 
ignoreregex =
\" > \$F2B/filter.d/nginx-req-limit.conf

echo \"
# If you want to protect OpenSSH from being bruteforced by password
# authentication then get public key authentication working before disabling
# PasswordAuthentication in sshd_config.
#
#
# \\\"Connection from <HOST> port \\\\d+\\\" requires LogLevel VERBOSE in sshd_config
#

[INCLUDES]

# Read common prefixes. If any customizations available -- read them from
# common.local


before = common.conf

[Definition]

 _daemon = sshd
 
failregex = Bad protocol version identification .* from <HOST> .*
            ^%(__prefix_line)s(?:error: PAM: )?[aA]uthentication (?:failure|error|failed) for .* from <HOST>( via \\\\S+)?\\\\s*$
            ^%(__prefix_line)s(?:error: PAM: )?User not known to the underlying authentication module for .* from <HOST>\\\\s*$
            ^%(__prefix_line)sFailed \\\\S+ for (?P<cond_inv>invalid user )?(?P<user>(?P<cond_user>\\\\S+)|(?(cond_inv)(?:(?! from ).)*?|[^:]+)) from <HOS    T>(?: port \\\\d+)?(?: ssh\\\\d*)?(?(cond_user):|(?:(?:(?! from ).)*)$)
            ^%(__prefix_line)sROOT LOGIN REFUSED.* FROM <HOST>\\\\s*$
            ^%(__prefix_line)s[iI](?:llegal|nvalid) user .*? from <HOST>(?: port \\\\d+)?\\\\s*$
            ^%(__prefix_line)sUser .+ from <HOST> not allowed because not listed in AllowUsers\\\\s*$
            ^%(__prefix_line)sUser .+ from <HOST> not allowed because listed in DenyUsers\\\\s*$
            ^%(__prefix_line)sUser .+ from <HOST> not allowed because not in any group\\\\s*$
            ^%(__prefix_line)srefused connect from \\\\S+ \\\\(<HOST>\\\\)\\\\s*$
            ^%(__prefix_line)s(?:error: )?Received disconnect from <HOST>: 3: .*: Auth fail(?: \\\\[preauth\\\\])?$
            ^%(__prefix_line)sUser .+ from <HOST> not allowed because a group is listed in DenyGroups\\\\s*$
            ^%(__prefix_line)sUser .+ from <HOST> not allowed because none of user\\x27s groups are listed in AllowGroups\\\\s*$
            ^(?P<__prefix>%(__prefix_line)s)User .+ not allowed because account is locked<SKIPLINES>(?P=__prefix)(?:error: )?Received disconnect fro    m <HOST>: 11: .+ \\\\[preauth\\\\]$
            ^(?P<__prefix>%(__prefix_line)s)Disconnecting: Too many authentication failures for .+? \\\\[preauth\\\\]<SKIPLINES>(?P=__prefix)(?:error: )?C    onnection closed by <HOST> \\\\[preauth\\\\]$
            ^(?P<__prefix>%(__prefix_line)s)Connection from <HOST> port \\\\d+(?: on \\\\S+ port \\\\d+)?<SKIPLINES>(?P=__prefix)Disconnecting: Too many auth    entication failures for .+? \\\\[preauth\\\\]$
            ^%(__prefix_line)s(error: )?maximum authentication attempts exceeded for .* from <HOST>(?: port \\\\d*)?(?: ssh\\\\d*)? \\\\[preauth\\\\]$
            ^%(__prefix_line)spam_unix\\\\(sshd:auth\\\\):\\\\s+authentication failure;\\\\s*logname=\\\\S*\\\\s*uid=\\\\d*\\\\s*euid=\\\\d*\\\\s*tty=\\\\S*\\\\s*ruser=\\\\S*\\\\s*rhost=<HOS    T>\\\\s.*$
 
ignoreregex =
 
[Init]
 
 # \\\"maxlines\\\" is number of log lines to buffer for multi-line regex searches
 maxlines = 10
\" > \$F2B/filter.d/sshd.conf

echo  -e \"\${GREEN}Configuration de fail2ban\$RES\"
cp \$F2B/jail.conf \$F2B/jail.local
sed -i '224,229d' \$F2B/jail.local
echo \"
destemail = \\$USER@student.42.fr
sender = sgauguet@roger-skyline-1.fr

ignoreip = 127.0.0.1/8, \$IP

[sshd]
enabled  = true
port     = 59112
filter   = sshd
logpath = /var/log/auth.log
backend = %(sshd_backend)s
maxretry = 2
findtime = 180
bantime = 60
action = iptables-multiport[name=SSH, port=59112, protocol=tcp]

[nginx-req-limit] 
enabled = true 
filter = nginx-req-limit
action = iptables-multiport[name=nginx-req-limit, port=\"http,https\", protocol=tcp] 
logpath = /var/log/nginx/access.log 
findtime = 600 
bantime = 7200 
maxretry = 10 

[nginx-conn-limit] 
enabled = true 
filter = nginx-conn-limit 
action = iptables-multiport[name=ConnLimit, port=\"http,https\", protocol=tcp] 
logpath = /var/log/nginx/*error.log 
findtime = 300 
bantime = 7200 
maxretry = 100

\" >> \$F2B/jail.local

systemctl enable fail2ban
systemctl start fail2ban

############## Script de mise a jour des sources et des packages #######################

echo  -e \"\${GREEN}Mise a jour des sources et des paquets\$RES\"
if [ ! -f \$NI/update.rules ]
then
echo \"#!/bin/bash

dpkg --configure -a
apt-get install -f

echo -e \\\"
\\\$(date) - Mise à jour des dépôts -----\\\" >> /var/log/update_script.log
apt-get update -y >> /var/log/update_script.log

if [[ \\\$? != 0 ]]; then
echo -e \\\"Erreur de mise à jour des dépôts\\\" >> /var/log/update_script.log
fi

echo -e \\\"
\\\$(date) - Mise à jour des paquets -----\\\" >> /var/log/update_script.log
apt-get upgrade -y >> /var/log/update_script.log

if [[ \\\$? != 0 ]]; then
echo -e \\\"Erreur de mise à jour des paquets\\\" >> /var/log/update_script.log
fi

apt-get --purge autoremove
apt-get autoclean
exit 0;

\" >> \$NI/update.rules
chmod +x \$NI/update.rules

if [ ! -d /etc/systemd/system.save ]; then
mkdir -p /etc/systemd/system.save
cp -r /etc/systemd/system /etc/systemd/system.save
fi

echo -e \"[Unit]
Description=Update packages

[Service]
ExecStart=\$NI/update.rules
TimeoutSec=30
Restart=on-failure
RestartSec=30
StartLimitInterval=350
StartLimitBurst=10

[Install]
WantedBy=multi-user.target
\" > /lib/systemd/system/update.service

systemctl start update.service
systemctl enable update.service

# Creation de la mise a jour planifiee

echo -e \"${GREEN}Modification de la crontab\${RES}\"
crontab -l > cron_list
echo \"0 4 * * 0 root \$NI/update.rules\" >> cron_list
crontab cron_list
rm -rf cron_list

fi

# Veille sur les modifications du fichier /etc/crontab

echo  -e \"\${GREEN}Mise en place du suivi des modifications du fichier crontab\$RES\"

if [ ! -f /usr/local/sbin/crontab-updates ]
then

echo \"#!/bin/bash

# Variables
CRONTAB='/etc/crontab'
CRONTAB_LAST_MODIF=\\\$(date -r \\\${CRONTAB} '+%d/%m/%Y %H:%M:%S')
MAIL_ROOT='root'
CRONTAB_LOGS='/var/log/crontab.log'
CRONTAB_REGISTRATION_DATE=\\\$(cat \\\$CRONTAB_LOGS)
MESSAGE=\\\"Le fichier \\\${CRONTAB} a été modifié le \\\${CRONTAB_LAST_MODIF}\\\";
RED='\033[1;31m'
RES='\033[0m'

if [ ! -f \\\$CRONTAB_LOGS ]
then
	echo \\\$CRONTAB_LAST_MODIF > \\\$CRONTAB_LOGS
fi

if [ \\\"\\\${CRONTAB_REGISTRATION_DATE}\\\" != \\\"\\\${CRONTAB_LAST_MODIF}\\\" ]; then
	if [ ! -z \\\"\\\${CRONTAB_REGISTRATION_DATE}\\\" ]; then
	   echo \\\"\\\$MESSAGE\\\" | mail -s \\\"Modification du fichier \\\${CRONTAB}\\\" \\\"\\\${MAIL_ROOT}\\\";
	fi
	rm -rf \\\$CRONTAB_LOGS && touch \\\$CRONTAB_LOGS
   	echo \\\$CRONTAB_LAST_MODIF > \\\$CRONTAB_LOGS
fi\" > /usr/local/sbin/crontab-updates

chmod +x /usr/local/sbin/crontab-updates

echo -e \"${GREEN}Modification de la crontab\${RES}\"
crontab -l > cron_list
echo \"0 0 * * * root /usr/local/sbin/crontab-updates\" >> cron_list
crontab cron_list
rm -rf cron_list
fi
service cron start

######################### Mise en place du serveur nginx ###############################

WEB_DIR='/data/www'
HOST_NAME='roger-skyline-1'

echo  -e \"\${GREEN}Création d'un certificat SSL\$RES\"
cd /etc/ssl
openssl genrsa -out roger-skyline.key 2048
openssl req -new -key roger-skyline.key -out roger-skyline.csr
openssl x509 -req -days 365 -in roger-skyline.csr -signkey roger-skyline.key -out roger-skyline.crt


echo  -e \"\${GREEN}Configuration de nginx\$RES\"

mkdir -p \$WEB_DIR/\$HOST_NAME/{html,css,js,logs}
chown -R nginx:nginx \$WEB_DIR/\$HOST_NAME
chmod -R 755 \$WEB_DIR

cat > /etc/nginx/conf.d/default.conf <<EOF

server {
    listen 80;
    server_name roger-skyline-1 www.roger-skyline-1 localhost;
    limit_req zone=flood burst=100 nodelay;
    limit_conn ddos 100;

    return 301 https://\\\$server_name:8081\\\$request_uri;
}
server {
    listen 80;
    server_name \$IP_B;
    limit_req zone=flood burst=100 nodelay;
    limit_conn ddos 100;

    return 301 https://\\\$host\\\$request_uri;
}
EOF

cat > /etc/nginx/conf.d/\$HOST_NAME.conf <<EOF

server {
	listen 443 ssl;
    	ssl_certificate /etc/ssl/roger-skyline.crt;
    	ssl_certificate_key /etc/ssl/roger-skyline.key;
	ssl_session_timeout 5m;
	ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;
	ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:AES128:AES256:RC4-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK;
	ssl_prefer_server_ciphers   on;
	ssl_session_cache           shared:SSL:10m;
	limit_req zone=flood burst=100 nodelay;
    	limit_conn ddos 100;
	
	server_name \$HOST_NAME www.\$HOST_NAME \$IP_B;
	location / {
		root        /data/www/\$HOST_NAME/html;
		try_files \\\$uri \\\$uri/ = 404;
	}

	location ~* \.(css) {
		root        /data/www/\$HOST_NAME/css;
		try_files \\\$uri \\\$uri/ = 404;
	}

	location ~* \.(js) {
		root        /data/www/\$HOST_NAME/js;
		try_files \\\$uri \\\$uri/ = 404;
	}

	error_page 404 500 501 /error.html;

    # Logs
    access_log \$WEB_DIR/\$HOST_NAME/logs/access.log;
    error_log  \$WEB_DIR/\$HOST_NAME/logs/error.log;

    # Includes
    #include global/common.conf;
}
EOF

cat > \$WEB_DIR/\$HOST_NAME/html/index.html <<EOF
<link href='https://fonts.googleapis.com/css?family=Open+Sans:700,600' rel='stylesheet' type='text/css'>
<link href='index.css' rel='stylesheet' type='text/css'>
<form method='post' action='success.html'>
<div class='box'>
<h1>ROGER-SKYLINE-1</h1>
<input type='email' name='email' value='email' class='email' />
<input type='password' name='email' value='email' class='email' />
  
<a href='success.html'><div class='btn'>Sign In</div></a> <!-- End Btn -->

<a href='#'><div id='btn2'>Sign Up</div></a> <!-- End Btn2 -->
  
</div> <!-- End Box -->
  
</form>

<p>Forgot your password? <u style='color:#f1c40f;'>Click Here!</u></p>
  
<script src='//ajax.googleapis.com/ajax/libs/jquery/1.9.0/jquery.min.js' type='text/javascript'></script>
<script src='index.js' type='text/javascript'></script>
EOF

cat > \$WEB_DIR/\$HOST_NAME/html/success.html <<EOF
<link href='https://fonts.googleapis.com/css?family=Open+Sans:700,600' rel='stylesheet' type='text/css'>
<link href='index.css' rel='stylesheet' type='text/css'>
<div class='box'>
<h1>SUCCESS</h1>
</div>
  
<script src='index.js' type='text/javascript'></script>
EOF

cat > \$WEB_DIR/\$HOST_NAME/html/error.html <<EOF
<link href='https://fonts.googleapis.com/css?family=Open+Sans:700,600' rel='stylesheet' type='text/css'>
<link href='error.css' rel='stylesheet' type='text/css'>
 <div id='clouds'>
            <div class='cloud x1'></div>
            <div class='cloud x1_5'></div>
            <div class='cloud x3'></div>
            <div class='cloud x4'></div>
            <div class='cloud x5'></div>
        </div>
        <div class='c'>
            <div class='_404'>404</div>
            <hr>
            <div class='_1'>THE PAGE</div>
            <div class='_2'>WAS NOT FOUND</div>
            <a class='btn' href='index.html'>BACK TO MARS</a>
        </div>
EOF

cat > \$WEB_DIR/\$HOST_NAME/css/index.css <<EOF
body{
  font-family: 'Open Sans', sans-serif;
  background:#3498db;
  margin: 0 auto 0 auto;  
  width:100%; 
  text-align:center;
  margin: 20px 0px 20px 0px;   
}

p{
  font-size:12px;
  text-decoration: none;
  color:#ffffff;
}

h1{
  font-size:1.5em;
  color:#525252;
}

.box{
  background:white;
  width:300px;
  border-radius:6px;
  margin: 0 auto 0 auto;
  padding:0px 0px 70px 0px;
  border: #2980b9 4px solid; 
}

.email{
  background:#ecf0f1;
  border: #ccc 1px solid;
  border-bottom: #ccc 2px solid;
  padding: 8px;
  width:250px;
  color:#AAAAAA;
  margin-top:10px;
  font-size:1em;
  border-radius:4px;
}

.password{
  border-radius:4px;
  background:#ecf0f1;
  border: #ccc 1px solid;
  padding: 8px;
  width:250px;
  font-size:1em;
}

.btn{
  background:#2ecc71;
  width:125px;
  padding-top:5px;
  padding-bottom:5px;
  color:white;
  border-radius:4px;
  border: #27ae60 1px solid;
  
  margin-top:20px;
  margin-bottom:20px;
  float:left;
  margin-left:16px;
  font-weight:800;
  font-size:0.8em;
}

.btn:hover{
  background:#2CC06B; 
}

#btn2{
  float:left;
  background:#3498db;
  width:125px;  padding-top:5px;
  padding-bottom:5px;
  color:white;
  border-radius:4px;
  border: #2980b9 1px solid;
  
  margin-top:20px;
  margin-bottom:20px;
  margin-left:10px;
  font-weight:800;
  font-size:0.8em;
}

#btn2:hover{ 
background:#3594D2; 
}
EOF

cat > \$WEB_DIR/\$HOST_NAME/css/error.css <<EOF
@import url(https://fonts.googleapis.com/css?family=opensans:500);
body{
                background: #33cc99;
                color:#fff;
                font-family: 'Open Sans', sans-serif;
                max-height:700px;
                overflow: hidden;
            }
            .c{
                text-align: center;
                display: block;
                position: relative;
                width:80%;
                margin:100px auto;
            }
            ._404{
                font-size: 220px;
                position: relative;
                display: inline-block;
                z-index: 2;
                height: 250px;
                letter-spacing: 15px;
            }
            ._1{
                text-align:center;
                display:block;
                position:relative;
                letter-spacing: 12px;
                font-size: 4em;
                line-height: 80%;
            }
            ._2{
                text-align:center;
                display:block;
                position: relative;
                font-size: 20px;
            }
            .text{
                font-size: 70px;
                text-align: center;
                position: relative;
                display: inline-block;
                margin: 19px 0px 0px 0px;
                /* top: 256.301px; */
                z-index: 3;
                width: 100%;
                line-height: 1.2em;
                display: inline-block;
            }
           

            .btn{
                background-color: rgb( 255, 255, 255 );
                position: relative;
                display: inline-block;
                width: 358px;
                padding: 5px;
                z-index: 5;
                font-size: 25px;
                margin:0 auto;
                color:#33cc99;
                text-decoration: none;
                margin-right: 10px
            }
            .right{
                float:right;
                width:60%;
            }
            
            hr{
                padding: 0;
                border: none;
                border-top: 5px solid #fff;
                color: #fff;
                text-align: center;
                margin: 0px auto;
                width: 420px;
                height:10px;
                z-index: -10;
            }
            
            hr:after {
                content: \"\2022\";
                display: inline-block;
                position: relative;
                top: -0.75em;
                font-size: 2em;
                padding: 0 0.2em;
                background: #33cc99;
            }
            
            .cloud {
                width: 350px; height: 120px;

                background: #FFF;
                background: linear-gradient(top, #FFF 100%);
                background: -webkit-linear-gradient(top, #FFF 100%);
                background: -moz-linear-gradient(top, #FFF 100%);
                background: -ms-linear-gradient(top, #FFF 100%);
                background: -o-linear-gradient(top, #FFF 100%);

                border-radius: 100px;
                -webkit-border-radius: 100px;
                -moz-border-radius: 100px;

                position: absolute;
                margin: 120px auto 20px;
                z-index:-1;
                transition: ease 1s;
            }

            .cloud:after, .cloud:before {
                content: '';
                position: absolute;
                background: #FFF;
                z-index: -1
            }

            .cloud:after {
                width: 100px; height: 100px;
                top: -50px; left: 50px;

                border-radius: 100px;
                -webkit-border-radius: 100px;
                -moz-border-radius: 100px;
            }

            .cloud:before {
                width: 180px; height: 180px;
                top: -90px; right: 50px;

                border-radius: 200px;
                -webkit-border-radius: 200px;
                -moz-border-radius: 200px;
            }
            
            .x1 {
                top:-50px;
                left:100px;
                -webkit-transform: scale(0.3);
                -moz-transform: scale(0.3);
                transform: scale(0.3);
                opacity: 0.9;
                -webkit-animation: moveclouds 15s linear infinite;
                -moz-animation: moveclouds 15s linear infinite;
                -o-animation: moveclouds 15s linear infinite;
            }
            
            .x1_5{
                top:-80px;
                left:250px;
                -webkit-transform: scale(0.3);
                -moz-transform: scale(0.3);
                transform: scale(0.3);
                -webkit-animation: moveclouds 17s linear infinite;
                -moz-animation: moveclouds 17s linear infinite;
                -o-animation: moveclouds 17s linear infinite; 
            }

            .x2 {
                left: 250px;
                top:30px;
                -webkit-transform: scale(0.6);
                -moz-transform: scale(0.6);
                transform: scale(0.6);
                opacity: 0.6; 
                -webkit-animation: moveclouds 25s linear infinite;
                -moz-animation: moveclouds 25s linear infinite;
                -o-animation: moveclouds 25s linear infinite;
            }

            .x3 {
                left: 250px; bottom: -70px;

                -webkit-transform: scale(0.6);
                -moz-transform: scale(0.6);
                transform: scale(0.6);
                opacity: 0.8; 

                -webkit-animation: moveclouds 25s linear infinite;
                -moz-animation: moveclouds 25s linear infinite;
                -o-animation: moveclouds 25s linear infinite;
            }

            .x4 {
                left: 470px; botttom: 20px;

                -webkit-transform: scale(0.75);
                -moz-transform: scale(0.75);
                transform: scale(0.75);
                opacity: 0.75;

                -webkit-animation: moveclouds 18s linear infinite;
                -moz-animation: moveclouds 18s linear infinite;
                -o-animation: moveclouds 18s linear infinite;
            }

            .x5 {
                left: 200px; top: 300px;

                -webkit-transform: scale(0.5);
                -moz-transform: scale(0.5);
                transform: scale(0.5);
                opacity: 0.8; 

                -webkit-animation: moveclouds 20s linear infinite;
                -moz-animation: moveclouds 20s linear infinite;
                -o-animation: moveclouds 20s linear infinite;
            }

            @-webkit-keyframes moveclouds {
                0% {margin-left: 1000px;}
                100% {margin-left: -1000px;}
            }
            @-moz-keyframes moveclouds {
                0% {margin-left: 1000px;}
                100% {margin-left: -1000px;}
            }
            @-o-keyframes moveclouds {
                0% {margin-left: 1000px;}
                100% {margin-left: -1000px;}
            }
EOF


/usr/local/nginx/sbin/nginx -t 2>/dev/null > /dev/null
if [[ $? == 0 ]]; then
 echo \"success\"
 service nginx restart
else
 echo \"fail\"
fi

cat > \$WEB_DIR/\$HOST_NAME/js/index.js <<EOF
function field_focus(field, email)
  {
    if(field.value == email)
    {
      field.value = '';
    }
  }

  function field_blur(field, email)
  {
    if(field.value == '')
    {
      field.value = email;
    }
  }

//Fade in dashboard box
\\\$(document).ready(function(){
    \\\$('.box').hide().fadeIn(1000);
    });

//Stop click event
\\\$('a').click(function(event){
    window.location.href='success.html';
});

\\\$('u').click(function(event){
    window.location.href='error.html';
});

EOF

service fail2ban restart 

" > $DIRECTORY/deployment.sh

########################################################################################

chmod +x $DIRECTORY/deployment.sh

echo -e "${YL}SUCCESS\n$USER can now launch VM configuration.
Please run \"source ~/.bashrc\", and then \"rs1-exec\"$RES"

exit 0;
