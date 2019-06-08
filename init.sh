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

install vim git sudo net-tools fail2ban nmap

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
echo \"Port 59112\" >> \$SSH
service sshd restart
echo -e \"\${GREEN}Test de la nouvelle configuration\${RES}\"
if [ \$(nmap -A -p 59112 --open 10.177.42.220/30 | grep -c open ) -eq 0 ]
then
	echo -e \"\${RED}Echec\$RES\"
	exit 1;
else
	echo -e \"\${GREEN}Success\${RES}\"
fi
echo -e \"\${GREEN}Publikeys SSH\${RES}\"
ssh-keygen -t rsa
ssh-copy-id -i id id_rsa.pub \"-p 59112 \$USER@10.177.42.221\"

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
