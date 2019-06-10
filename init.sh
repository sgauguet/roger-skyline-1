#!/bin/bash

########################################################################################
########################## Init script run by root #####################################
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
chmod 700 /home/$USER/.ssh/authorized_keys
chown -R $USER /home/$USER/.ssh

# Creation des alias / necessite source ~./bashrc pour etre active
# edit = modifier le script d'installation
# script = lancer le script d'installation
# logs = consulter les logs

echo  -e "${GREEN}Creation des alias$RES"
if [ ! -f $ALIAS ]
then
	touch $ALIAS
	echo "alias script=\"sudo $DIRECTORY/deployment.sh\"" >> $ALIAS
	echo "alias edit=\"sudo vim $DIRECTORY/init.sh\"" >> $ALIAS
	echo "alias logs=\"sudo tail -n 20 /var/log/messages\"" >> $ALIAS
	
	# Configuration de vim
	
	echo "set number
	syntax on" > /home/$USER/.vimrc
	echo "set number
	syntax on" > /root/.vimrc
fi

########################################################################################
########################## Configuration script run by user ############################
########################################################################################

rm -f $DIRECTORY/deployment.sh
echo "#!/bin/bash

# Variables - script de configuration

NI='/etc/network'
RESOLV='/etc/resolv.conf'
SSH='/etc/ssh/sshd_config'
F2B='/etc/fail2ban'
USER='sgauguet'
IP='10.177.42.221'

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

install vim git sudo net-tools fail2ban nmap openssh-server iptables-persistent

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
address $IP
netmask 255.255.255.252
broadcast 10.177.42.223
network 10.177.42.220
gateway 10.0.2.2
dns-search 42.fr
dns-nameserver 10.51.1.42
dns-nameserver 10.51.1.43
dns-nameserver 10.188.0.1\" >> /\$NI/interfaces

# Mise a jour et test de la configuration du reseau

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
echo \"Port 59112
PermitRootLogin no
PermitEmptyPasswords yes
#AuthentificationMethods password
\" >> \$SSH

service sshd restart

# Acces par publickeys

echo -e \"\${GREEN}Publikeys SSH\${RES}\"
ssh-keygen -t rsa -f /home/\$USER/.ssh/id_rsa -P \"\"
ssh-copy-id -f -i /home/\$USER/.ssh/id_rsa.pub -p 59112 \$USER@10.177.42.221

cat \$SSH.backup > \$SSH
echo \"Port 59112
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
\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
# paquet avec SYN et RST à la fois
\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
# paquet avec FIN et RST à la fois
\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
# paquet avec FIN mais sans ACK
\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
# paquet avec URG mais sans ACK
\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
# paquet avec PSH mais sans ACK
\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags PSH,ACK PSH -j DROP
# paquet avec tous les flags à 1 <=> XMAS scan dans Nmap
\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP
# paquet avec tous les flags à 0 <=> Null scan dans Nmap
\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
# paquet avec FIN,PSH, et URG mais sans SYN, RST ou ACK
\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP
# paquet avec FIN,SYN,PSH,URG mais sans ACK ou RST
\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,PSH,URG -j DROP
# paquet avec FIN,SYN,RST,ACK,URG à 1 mais pas PSH
\\\$IPT -A PREROUTING -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j DROP 

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

if [ ! -f /etc/sysctl.conf.backup ]
then
	echo  -e \"\${GREEN}Sauvegarde de systctl.conf\$RES\"
	cp /etc/sysctl.conf /etc/sysctl.conf.backup
fi

echo \"net.netfilter.nf_conntrack_tcp_loose = 0
net.ipv4.tcp_timestamps = 1
net.netfilter.nf_conntrack_max = 200000\" >> /etc/sysctl.conf

sysctl -p &>/dev/null

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

#
#
#
#
" > $DIRECTORY/deployment.sh

########################################################################################

chmod +x $DIRECTORY/deployment.sh /etc/network/iptables.rules

echo -e "${YL}SUCCESS\n$USER can know launch VM configuration by running command \"script\"$RES"

exit 0;

clean() {
echo "Cleaning up..."
apt autoremove -yy
apt autoclean
}
clean
