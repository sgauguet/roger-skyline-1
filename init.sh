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
	echo "alias edit=\"sudo vim $DIRECTORY/deployment.sh\"" >> $ALIAS
fi
rm -f $DIRECTORY/deployment.sh
echo "#!/bin/bash

# Variables

install() {

}

install net-tools fail2ban

" > $DIRECTORY/deployment.sh
chmod +x $DIRECTORY/deployment.sh

echo -e "${YL}SUCCESS\n$USER can know launch VM configuration by running command \"script\"$RES"
exit 0;
