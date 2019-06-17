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

install vim git sudo net-tools fail2ban nmap ssh openssh-server iptables-persistent curl gnupg2 ca-certificates lsb-release portsentry

if [ ! -f /etc/apt/sources.list.d/nginx.list ]
then
	echo \"deb http://nginx.org/packages/mainline/debian/ `lsb_release -cs` nginx
	deb-src http://nginx.org/packages/mainline/debian/ stretch nginx\" > /etc/apt/sources.list.d/nginx.list
	curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add -
	apt-key fingerprint ABF5BD827BD9BF62
	apt update
	install nginx
fi

# Configuration de l'adresse IP

echo -e \"\${GREEN}Configuration du réseau - IP fixe\${RES}\";

if [ ! -f \$NI/interfaces.backup ]
then
	echo  -e \"\${GREEN}Sauvegarde des parametres initiaux : \$NI/interfaces.backup \$RES\"
	cp \$NI/interfaces \$NI/interfaces.backup
	cp \$RESOLV \$RESOLV.backup
fi

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

# Mise a jour et test de la configuration du reseau

ifdown enp0s3 &>/dev/null
ifup enp0s3 &>/dev/null
/etc/init.d/networking restart

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
ssh-keygen -t rsa -f /home/\$USER/.ssh/id_rsa -P \"\"
ssh-copy-id -f -i /home/\$USER/.ssh/id_rsa.pub -p \$PORT_SSH \$USER@\$IP

cat \$SSH.backup > \$SSH
echo \"Port \$PORT_SSH
PermitRootLogin no
PermitEmptyPasswords no
AuthenticationMethods publickey
\" >> \$SSH

service sshd restart

# Test de la configuration SSH

echo -e \"\${GREEN}Test de la nouvelle configuration\${RES}\"
if [ \$(nmap -A -p 59112 --open 10.177.42.220/30 | grep -c open ) -eq 0 ]
then
	echo -e \"\${RED}Echec\$RES\"
	exit 1;
else
	echo -e \"\${GREEN}Success\${RES}\"
fi

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
# Blocage par defaut du trafic sortant
\\\$IPT -P OUTPUT ACCEPT

# Blocage des scans XMAS et NULL
\\\$IPT -A INPUT -p tcp --tcp-flags FIN,URG,PSH FIN,URG,PSH -j DROP
\\\$IPT -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
\\\$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
\\\$IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

# Permettre à une connexion ouverte de recevoir du trafic en entrée.
\\\$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Pas de filtrage sur la boucle locale
\\\$IPT -A INPUT -i lo -j ACCEPT

# paquet avec SYN et FIN à la fois
#\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
# paquet avec SYN et RST à la fois
#\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
# paquet avec FIN et RST à la fois
#\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
# paquet avec FIN mais sans ACK
#\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
# paquet avec URG mais sans ACK
#\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
# paquet avec PSH mais sans ACK
#\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags PSH,ACK PSH -j DROP
# paquet avec tous les flags à 1 <=> XMAS scan dans Nmap
#\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP
# paquet avec tous les flags à 0 <=> Null scan dans Nmap
#\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
# paquet avec FIN,PSH, et URG mais sans SYN, RST ou ACK
#\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP
# paquet avec FIN,SYN,PSH,URG mais sans ACK ou RST
#\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,PSH,URG -j DROP
# paquet avec FIN,SYN,RST,ACK,URG à 1 mais pas PSH
#\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j DROP 

# Ping
\\\$IPT -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
\\\$IPT -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
\\\$IPT -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT

# SSH
\\\$IPT -A INPUT -p tcp --dport 59112 -j ACCEPT

# NTP
\\\$IPT -A INPUT -p udp --dport 123 -j ACCEPT

# smtp
\\\$IPT -A INPUT -p tcp --dport smtp -j ACCEPT

# imap(s)
\\\$IPT -A INPUT -p tcp --dport 143 -j ACCEPT
\\\$IPT -A INPUT -p tcp --dport 993 -j ACCEPT

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


# Parametrage de fail2ban

echo  -e \"\${GREEN}Configuration de fail2ban\$RES\"
cp \$F2B/jail.conf \$F2B/jail.local
echo \"ignoreip = 127.0.0.1/8, \$IP
[ssh]

enabled  = true
port     = 59112
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 6
\" >> \$F2B/jail.local

systemctl enable fail2ban
systemctl start fail2ban

############## Script de mise a jour des sources et des packages #######################

echo  -e \"\${GREEN}Mise a jour des sources et des paquets\$RES\"
if [ ! -f \$NI/update.rules ]
then
echo \"#!/bin/bash
### BEGIN INIT INFO
# Provides:          update
# Required-Start:    $all
# Required-Stop:
# Default-Start:     2 3 4 5 
# Default-Stop:
# Short-Description: your description here
### END INIT INFO

dpkg --configure -a
apt-get install -f

echo -e \\\"\\\$(date) - Mise à jour des dépôts
\\\" >> /var/log/update_script.log
apt-get update >> /var/log/update_script.log

if [[ \\\$? != 0 ]]; then
echo -e \\\"Erreur de mise à jour des dépôts\\\" >> /var/log/update_script.log
fi

echo -e \\\"\\\$(date) - Mise à jour des paquets
\\\" >> /var/log/update_script.log
apt-get upgrade >> /var/log/update_script.log

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
echo \"0 4 * * 0 \$NI/update.rules\" >> cron_list
crontab -u root cron_list
rm -rf cron_list

fi

# Veille sur les modifications du fichier /etc/crontab

echo  -e \"\${GREEN}Mise en place du suivi des modifications du fichier crontab\$RES\"

echo \"#!/bin/bash

# Variables
CRONTAB='/etc/crontab'
CRONTAB_LAST_MODIF=\\\$(date -r \\\${CRONTAB} '+%d/%m/%Y %H:%M')
MAIL_ROOT='root'
CRONTAB_LOGS='/var/log/crontab.log'
CRONTAB_REGISTRATION_DATE=\\\$(<\\\$CRONTAB_LOGS)
MESSAGE=\\\"Le fichier \\\${CRONTAB} a été modifié le \\\${CRONTAB_LAST_MODIF}\\\";
RED='\033[1;31m'
RES='\033[0m'

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
echo \"*/1 * * * * root /usr/local/sbin/crontab-updates\" >> cron_list
crontab cron_list
rm -rf cron_list
service cron start

######################### Mise en place du serveur nginx ###############################

WEB_DIR='/data/www'
HOST_NAME='roger-skyline-1.fr'

echo  -e \"\${GREEN}Configuration de nginx\$RES\"

mkdir -p \$WEB_DIR/\$HOST_NAME/{html,logs}
chown -R sgauguet:www-data \$WEB_DIR/\$HOST_NAME
chmod 755 \$WEB_DIR

# cp /etc/nginx/sites-available/default /etc/nginx/sites-available/\$HOST_NAME

cat > /etc/nginx/sites-available/\$HOST_NAME <<EOF
server {
    server_name *.\$HOST_NAME;
    return 301 \\\$scheme://\$HOST_NAME\\\$request_uri;
}
server {
    server_name \$HOST_NAME;
    root        /data/www/\$HOST_NAME/html;

    # Logs
    access_log \$WEB_DIR/\$HOST_NAME/logs/access.log;
    error_log  \$WEB_DIR/\$HOST_NAME/logs/error.log;

    # Includes
    #include global/common.conf;
}
EOF

ln -s /etc/nginx/sites-available/\$HOST_NAME /etc/nginx/sites-enabled/\$HOST_NAME 2>/dev/null

cat > \$WEB_DIR/\$HOST_NAME/html/index.html <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
        <title>$1</title>
        <meta charset="utf-8" />
</head>
<body class="container">
        <header><h1>$1<h1></header>
        <div id="wrapper">

Hello World
</div>
        <footer>© $(date +%Y)</footer>
</body>
</html>
EOF

service nginx restart

" > $DIRECTORY/deployment.sh

########################################################################################

chmod +x $DIRECTORY/deployment.sh

echo -e "${YL}SUCCESS\n$USER can now launch VM configuration.
Please run \"source ~/.bashrc\", and then \"rs1-exec\"$RES"

exit 0;
