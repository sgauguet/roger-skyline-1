#!/bin/bash

# Variables 

DIRECTORY=$(cd `dirname $0` && pwd)
SUDOERS='/etc/sudoers'
BACKUP='/etc/sudoers.backup'
USER='sgauguet'
ALIAS="/home/$USER/.bash_aliases"

# Couleurs

GREEN='\033[1;32m'
RES='\033[0m'

if (($EUID != 0)); then
	echo 'Please run as root (su -)'
	exit 1;
fi

echo -e "${GREEN}Gestion des utilisateurs - installation des paquets necessaires$RES"
dpkg -l | grep -q sudo || apt-get install sudo
dpkg -l | grep -q vim || apt-get install vim 
echo  -e "${GREEN}Parametrage des droits de l'utilisateur non root"
if [ ! -f $BACKUP ]
then
	echo  -e "${GREEN}Sauvegarde des parametres initiaux : $BACKUP"
	cp $SUDOERS $BACKUP
fi
echo "$USER ALL=(ALL:ALL) ALL" >> $SUDOERS

echo  -e "${GREEN}Creation des alias"
touch $ALIAS
echo "alias script=\"sudo $DIRECTORY/deployment\"" >> $ALIAS
echo "alias edit=\"sudo vim $DIRECTORY/deployment\"" >> $ALIAS

echo -e "SUCCESS - $USER can know launch VM configuration by running command \"script\""
exit 0;
