#!/bin/bash

clear;
echo -e "\nInstall Graphite ";
####################################################################################################
validate_args() {
		# check user is ROOT or not
		if [ $EUID -ne 0 ]; 
		then
				echo -e "\nERROR: The user must be root";
				exit 0;
		fi
}
####################################################################################################
install_dependencies() {
		cd $HOME;
		apt-get update;
		apt-get -y install graphite-web graphite-carbon --force-yes;
		apt-get -y install python-django --force-yes;
		apt-get -y install postgresql libpq-dev python-psycopg2 --force-yes;
		apt-get -y -f install
		apt-get -y install apache2 libapache2-mod-wsgi --force-yes;
		apt-get -y install git nodejs devscripts debhelper --force-yes;
		apt-get update;
}
####################################################################################################
install_statsd() {
		mkdir ~/build;
		cd ~/build;
		git clone https://github.com/etsy/statsd.git;
		cd ~/build/statsd;
		dpkg-buildpackage;
		dpkg -i ~/build/statsd*.deb;
}
####################################################################################################
validate_args;
install_dependencies;
install_statsd;
