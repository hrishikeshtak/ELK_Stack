#!/bin/bash

clear;
echo -e "\nInstall Graphite ";
####################################################################################################
SCRIPT_NAME=$0;
COUNT_PARAM=$#;
GRAPHITE_LOCAL_IPADDR=$1;
GRAPHITE_WEB_PORT=$2;
DEPENDENCY_DIR=$HOME/packages/dependencies;
PACKAGE_DIR=$HOME/packages;
GRAPHITE_CONF_DIR=/opt/graphite/conf;
DJANGO_TAR_FILE=Django-1.8.4.tar.gz;
DJANGO_FILE=Django-1.8.4;
GRAPHITE_TAR_FILE=graphite-web-0.9.13.tar.gz;
GRAPHITE_FILE=graphite-web-0.9.13;
CARBON_TAR_FILE=carbon-0.9.13.tar.gz;
CARBON_FILE=carbon-0.9.13;
WHISPER_TAR_FILE=whisper-0.9.13.tar.gz;
WHISPER_FILE=whisper-0.9.13;
DJANGO_TAGGING_TAR_FILE=django-tagging-0.3.6.tar.gz;
DJANGO_TAGGING_FILE=django-tagging-0.3.6;
PYTHON_TXAMQP_TAR_FILE=python-txamqp_0.3.orig.tar.gz;
PYTHON_TXAMQP_FILE=python-txamqp-0.3;
TWISTED_TAR_FILE=Twisted-15.4.0.tar.bz2;
TWISTED_FILE=Twisted-15.4.0;
####################################################################################################
error_check() {
		echo -e "\nERROR: $SCRIPT_NAME: at Line $2 : $1";
		exit 0;
}

print_usage () {
		echo -e "\nUsage: $0 <GRAPHITE_LOCAL_IPADDR>  <GRAPHITE_WEB_PORT> "
		echo -e "    GRAPHITE_LOCAL_IPADDR - IP address where Graphite will be running"
		echo -e "                         (generally PUBLIC n/w IP of installed node)\n"
		echo -e "    GRAPHITE_WEB_PORT - Port number "
		echo -e "                         (ex 8080)\n"

}
validate_args() {
		# check user is ROOT or not
		if [ $EUID -ne 0 ]; 
		then
				echo -e "\nERROR: The user must be root";
				exit 0;
		fi
		if [ $COUNT_PARAM -eq 0 ]
		then
				echo -e "\nERROR: GRAPHITE_LOCAL_IPADDR missing";
				print_usage;
				exit 0;
		else
				if validate_IP $GRAPHITE_LOCAL_IPADDR; 
				then 
						echo -e "\nGRAPHITE_LOCAL_IPADDR $GRAPHITE_LOCAL_IPADDR is reachable";
				else 
						echo -e "\nERROR: GRAPHITE_LOCAL_IPADDR $GRAPHITE_LOCAL_IPADDR is unreachable";
						exit 0;
				fi	
		fi
		if [ $COUNT_PARAM -eq 1 ]
		then
				echo -e "\nERROR: GRAPHITE_WEB_PORT missing";
				print_usage;
				exit 0;
		fi
}
validate_IP() {
		local  ip=$1;
		local  stat=1;

		if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
				OIFS=$IFS
				IFS='.'
				ip=($ip)
				IFS=$OIFS
				[[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
						&& ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
				stat=$?;
		fi
		if [ $stat -eq 0 ]
		then			
				ping -c1 $1 &> /dev/null;
				if [ $? -eq 0 ]; 
				then 
						stat=$?;
				else 
						stat=$?;
				fi
		else
				echo -e "\n$1 is not valid IP ADDRESS";
				exit 0;
		fi

		return $stat

}

####################################################################################################
install_dependencies() {
		cd $PACKAGE_DIR;
		ls -l | grep dependencies &> /dev/null || { error_check dependencies-not-installed ${LINENO} ; };

		sudo rpm -ivh $DEPENDENCY_DIR/*.rpm ;
		sleep 2
		sudo tar -xvf $PACKAGE_DIR/$DJANGO_TAR_FILE -C $PACKAGE_DIR;
		cd $PACKAGE_DIR/$DJANGO_FILE;
		sudo python setup.py install || { error_check $DJANGO_FILE-not-installed ${LINENO} ; };
		sleep 2
		sudo tar -xvf $PACKAGE_DIR/$DJANGO_TAGGING_TAR_FILE -C $PACKAGE_DIR;
		cd $PACKAGE_DIR/$DJANGO_TAGGING_FILE;
		sudo python setup.py install || { error_check $DJANGO_TAR_FILE-not-installed ${LINENO} ; };
		sleep 2
		sudo tar -xvf $PACKAGE_DIR/$PYTHON_TXAMQP_TAR_FILE -C $PACKAGE_DIR;
		cd $PACKAGE_DIR/$PYTHON_TXAMQP_FILE;
		sudo python setup.py install || { error_check $PYTHON_TXAMQP_FILE-not-installed ${LINENO} ; };
		sleep 2
		sudo tar -xvf $PACKAGE_DIR/$TWISTED_TAR_FILE -C $PACKAGE_DIR;
		cd $PACKAGE_DIR/$TWISTED_FILE;
		sudo python setup.py install || { error_check $TWISTED_FILE-not-installed ${LINENO} ; };
		sleep 2

		cd $HOME;
  
}
####################################################################################################
install_graphite() {
		sudo tar -xf $PACKAGE_DIR/$GRAPHITE_TAR_FILE -C $PACKAGE_DIR;
		cd $PACKAGE_DIR/$GRAPHITE_FILE;
		sudo python check-dependencies.py || { error_check GRAPHITE-dependencies-not-installed ${LINENO} ; };
		sudo python setup.py install || { error_check $GRAPHITE_FILE-not-installed ${LINENO} ; };
		sleep 2
#  		sudo tar -xf $PACKAGE_DIR/$CARBON_TAR_FILE -C $PACKAGE_DIR;
#  		cd $PACKAGE_DIR/$CARBON_FILE;
#  		sudo python setup.py install || { error_check $CARBON_FILE-not-installed ${LINENO} ; };
# 		sleep 2
		cd $PACKAGE_DIR/carbon;
 		sudo python setup.py install || { error_check carbon-not-installed ${LINENO} ; };
		sleep 2

		sudo tar -xf $PACKAGE_DIR/$WHISPER_TAR_FILE	-C $PACKAGE_DIR;
		cd $PACKAGE_DIR/$WHISPER_FILE;
		sudo python setup.py install || { error_check $WHISPER_FILE-not-installed ${LINENO} ; };
		sleep 2

		cd $HOME;
}
####################################################################################################
configure_graphite() {
		sudo cp $GRAPHITE_CONF_DIR/graphite.wsgi.example $GRAPHITE_CONF_DIR/graphite.wsgi;
		sudo cp $GRAPHITE_CONF_DIR/storage-schemas.conf.example $GRAPHITE_CONF_DIR/storage-schemas.conf;
		sudo cp $GRAPHITE_CONF_DIR/carbon.conf.example $GRAPHITE_CONF_DIR/carbon.conf;
		sudo cp $GRAPHITE_CONF_DIR/storage-aggregation.conf.example $GRAPHITE_CONF_DIR/storage-aggregation.conf;
		sudo cp /opt/graphite/webapp/graphite/local_settings.py.example /opt/graphite/webapp/graphite/local_settings.py;

		echo -e "TIME_ZONE = 'Asia/Kolkata' " >> /opt/graphite/webapp/graphite/local_settings.py;
		echo -e "MEMCACHE_HOSTS = ['0.0.0.0:11211'] " >> /opt/graphite/webapp/graphite/local_settings.py;
		sed -i -e '/SECRET/ s/^#*/#/' /opt/graphite/webapp/graphite/local_settings.py; 
		sed -i -e '/USE_REMOTE/ s/^#*/#/' /opt/graphite/webapp/graphite/local_settings.py; 
		sed -i -e "s/#SECRET_KEY = 'UNSAFE_DEFAULT'/SECRET_KEY = 'a_salty_string'/" /opt/graphite/webapp/graphite/local_settings.py;
		sed -i -e "s/#USE_REMOTE_USER_AUTHENTICATION = True/USE_REMOTE_USER_AUTHENTICATION = True/" /opt/graphite/webapp/graphite/local_settings.py;

		echo -e "no\n" | sudo python /opt/graphite/webapp/graphite/manage.py syncdb || { error_check Graphite-not-configured ${LINENO} ; };

		echo -e " " > /etc/httpd/conf.d/graphite.conf;


		echo -e " " > /etc/httpd/conf.d/wsgi.conf;
		sed -i -e "1iLoadModule wsgi_module modules/mod_wsgi.so \nWSGISocketPrefix /var/run/wsgi " /etc/httpd/conf.d/wsgi.conf;
		chown -R apache:apache /opt/graphite/storage/ ;
		sudo chmod +x /etc/init.d/carbon-cache;
		service memcached start;
		service carbon-cache start;
		service httpd start;
		python /opt/graphite/webapp/graphite/manage.py runserver $GRAPHITE_LOCAL_IPADDR:$GRAPHITE_WEB_PORT  

}
####################################################################################################
install_statsd () {


}
####################################################################################################
validate_args;
install_dependencies;
install_graphite;
configure_graphite;
install_statsd;
