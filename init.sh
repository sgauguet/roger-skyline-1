#!/bin/bash

# Variables 

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

if (($EUID != 0)); then
	echo -e "${RED}Please run as root${RES}"
	exit 1;
fi

echo -e "${INT}**************
**   INIT  ***
**************$RES"

mkdir -p /home/$USER/.ssh
touch /home/$USER/.ssh/authorized_keys
chmod 700 /home/$USER/.ssh
chmod 700 /home/$USER/.ssh/authorized_keys
chown -R $USER /home/$USER/.ssh
echo -e "${GREEN}Gestion des utilisateurs - installation des paquets necessaires$RES"
dpkg-query -W -f='${Status}' sudo 2> /dev/null | grep -c "ok installed" || apt-get install sudo
dpkg-query -W -f='${Status}' vim 2> /dev/null | grep -c "ok installed" || apt-get install vim
echo  -e "${GREEN}Parametrage des droits de l'utilisateur non root$RES"
if [ ! -f $BACKUP ]
then
	echo  -e "${GREEN}Sauvegarde des parametres initiaux : $BACKUP $RES"
	cp $SUDOERS $BACKUP
fi
echo "$USER ALL=(ALL:ALL) ALL" >> $SUDOERS

echo  -e "${GREEN}Creation des alias$RES"
if [ ! -f $ALIAS ]
then
	touch $ALIAS
	echo "alias script=\"sudo $DIRECTORY/deployment.sh\"" >> $ALIAS
	echo "alias edit=\"sudo vim $DIRECTORY/init.sh\"" >> $ALIAS
	echo "set number
	syntax on" > /home/$USER/.vimrc
fi
rm -f $DIRECTORY/deployment.sh
echo "#!/bin/bash

# Variables
NI='/etc/network'
RESOLV='/etc/resolv.conf'
SSH='/etc/ssh/sshd_config'
USER='sgauguet'

# Couleurs
GREEN='\033[32m'
RED='\033[1;31m'
RES='\033[0m'

if ((\$EUID != 0)); then
	echo -e \"\${RED}Please run as root\${RES}\"
	exit 1;
fi

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
install vim git sudo net-tools fail2ban nmap openssh-server

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
address 10.177.42.221
netmask 255.255.255.252
broadcast 10.177.42.223
network 10.177.42.220
gateway 10.0.2.2
dns-search 42.fr
dns-nameserver 10.51.1.42
dns-nameserver 10.51.1.43
dns-nameserver 10.188.0.1\" >> /\$NI/interfaces
/etc/init.d/networking restart
echo -e \"\${GREEN}Test de la nouvelle configuration\${RES}\"
if [ ping -c4 www.google.fr &> /dev/null ]
then
	echo -e \"\${RED}Echec\$RES\"
	exit 1;
else
	echo -e \"\${GREEN}Success\${RES}\"
fi

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
echo -e \"\${GREEN}Publikeys SSH\${RES}\"
ssh-keygen -t rsa -f /home/\$USER/.ssh/id_rsa -P \"\"
ssh-copy-id -f -i /home/\$USER/.ssh/id_rsa.pub -p 59112 \$USER@10.177.42.221
echo -e \"\${GREEN}Test de la nouvelle configuration\${RES}\"
cat \$SSH.backup > \$SSH
echo \"Port 59112
PermitRootLogin no
PermitEmptyPasswords no
AuthenticationMethods publickey
\" >> \$SSH
service sshd restart
if [ \$(nmap -A -p 59112 --open 10.177.42.220/30 | grep -c open ) -eq 0 ]
then
	echo -e \"\${RED}Echec\$RES\"
	exit 1;
else
	echo -e \"\${GREEN}Success\${RES}\"
fi
echo \"#!/bin/bash

# Variables
IP=\$(/sbin/ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/')
IPT=\\"/sbin/iptables\"

# Reinitialisation
\\$IPT -F
\\$IPT -X
\\$IPT -t nat -F
\\$IPT -t nat -X
\\$IPT -t mangle -F
\\$IPT -t mangle -X

# Blocage par defaut du trafic entrant
\\$IPT -P INPUT DROP
# Blocage par defaut du forward
\\$IPT -P FORWARD DROP
# Blocage par defaut du trafic sortant
\\$IPT -P OUTPUT DROP

# Blocage des scans XMAS et NULL
\\$IPT -A INPUT -p tcp --tcp-flags FIN,URG,PSH FIN,URG,PSH -j DROP
\\$IPT -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
\\$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
\\$IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

# Permettre à une connexion ouverte de recevoir du trafic en entrée.
\\$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Pas de filtrage sur la boucle locale
\\$IPT -A INPUT -i lo -j ACCEPT
 
# Ping
\\$IPT -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
\\$IPT -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
\\$IPT -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT

# ftp 
\\$IPT -A INPUT -p tcp --dport 20 -j ACCEPT 
\\$IPT -A INPUT -p tcp --dport 21 -j ACCEPT--dport 29700:29750 -j ACCEPT

# SSH
\$IPT -A INPUT -p tcp --dport 59112 -j ACCEPT

# NTP
\\$IPT -A INPUT -p udp --dport 123 -j ACCEPT

# smtp
\\$IPT -A INPUT -p tcp --dport smtp -j ACCEPT

# imap(s)
\\$IPT -A INPUT -p tcp --dport 143 -j ACCEPT
\\$IPT -A INPUT -p tcp --dport 993 -j ACCEPT

# dns
\\$IPT -A INPUT -p tcp --dport domain -j ACCEPT
\\$IPT -A INPUT -p udp --dport domain -j ACCEPT

# http
\\$IPT -A INPUT -p tcp --dport http -j ACCEPT

# https
\\$IPT -A INPUT -p tcp --dport https -j ACCEPT\" > /etc/network/iptables.backup

#
#
#
#
" > $DIRECTORY/deployment.sh
chmod +x $DIRECTORY/deployment.sh

echo -e "${YL}SUCCESS\n$USER can know launch VM configuration by running command \"script\"$RES"
exit 0;

clean() {
echo "Cleaning up..."
apt autoremove -yy
apt autoclean
}
clean
