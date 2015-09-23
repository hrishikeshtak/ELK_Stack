#!/bin/bash

clear;
echo -e "\nInstall Graphite ";
####################################################################################################
SCRIPT_NAME=$0;
COUNT_PARAM=$#;
GRAPHITE_LOCAL_IPADDR=$1;
GRAPHITE_WEB_PORT=$2;
GRAPHITE_CONF_DIR=/etc/graphite;
CARBON_CONF_DIR=/etc/carbon;
STATSD_CONF_DIR=/etc/statsd;
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
		else
				ping -c1 google.com &> /dev/null || { error_check Internet-not-connected ${LINENO};};

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
		cd $HOME;
		apt-get update;
		apt-get -y install graphite-web graphite-carbon;
		apt-get -y install python-django;
		apt-get -y install postgresql libpq-dev python-psycopg2;
		apt-get -y install apache2 libapache2-mod-wsgi;
		apt-get -y install git nodejs devscripts debhelper;
		apt-get update;
  
}
####################################################################################################
configure_graphite() {
		sed -i -e '/SECRET/ s/^#*/#/' $GRAPHITE_CONF_DIR/local_settings.py; 
		sed -i -e '/USE_REMOTE/ s/^#*/#/' $GRAPHITE_CONF_DIR/local_settings.py; 
		sed -i -e '/TIME_ZONE/ s/^#*/#/' $GRAPHITE_CONF_DIR/local_settings.py; 

		sed -i -e "s/#SECRET_KEY = 'UNSAFE_DEFAULT'/SECRET_KEY = 'a_salty_string'/" $GRAPHITE_CONF_DIR/local_settings.py;
		sed -i -e "s/#TIME_ZONE = 'America\/Los_Angeles'/TIME_ZONE = 'Asia\/Kolkata'/" $GRAPHITE_CONF_DIR/local_settings.py
		sed -i -e "s/#USE_REMOTE_USER_AUTHENTICATION = True/USE_REMOTE_USER_AUTHENTICATION = True/" $GRAPHITE_CONF_DIR/local_settings.py;

		cat >> $GRAPHITE_CONF_DIR/local_settings.py << EOF
		DATABASES = {
			'default': {
				'NAME': 'graphite',
				'ENGINE': 'django.db.backends.postgresql_psycopg2',
				'USER': '',
				'PASSWORD': '',
				'HOST': '0.0.0.0',
				'PORT': ''
			}
		}
EOF
		
		echo -e "no\n" | graphite-manage.py syncdb || { error_check Graphite-not-configured ${LINENO} ; };
		sed -i -e '/CARBON_CACHE/ s/^#*/#/' /etc/default/graphite-carbon;
		sed -i -e '$aCARBON_CACHE_ENABLED=true' /etc/default/graphite-carbon;
		sed -i -e '/ENABLE_LOGROTATION/ s/^#*/#/' $CARBON_CONF_DIR/carbon.conf;
#  		sed -i -e '' $CARBON_CONF_DIR/carbon.conf;
		sed -i -e "10i[test] \
				\npattern = ^test/\. \
				\nretentions = 10s:10m,1m:1h,10m:1d" $CARBON_CONF_DIR/storage-schemas.conf;
		sed -i -e "10i[statsd] \
				\npattern = ^stats.* \
				\nretentions = 10s:1d,1m:7d,10m:1y" $CARBON_CONF_DIR/storage-schemas.conf;
		cp /usr/share/doc/graphite-carbon/examples/storage-aggregation.conf.example $CARBON_CONF_DIR/storage-aggregation.conf;
		service carbon-cache start;
}
####################################################################################################
configure_apache () {
		a2dissite 000-default;
		cp /usr/share/graphite-web/apache2-graphite.conf /etc/apache2/sites-available;
		a2ensite apache2-graphite || { error_check not-enable-apache-server %{LINENO};};
		service apache2 reload || { error_check not-enable-apache-server %{LINENO};};
}
####################################################################################################
install_statsd () {
		mkdir ~/build;
		cd ~/build;
		git clone https://github.com/etsy/statsd.git;
		cd ~/build/statsd;
		dpkg-buildpackage;
		service carbon-cache stop;
		dpkg -i ~/build/statsd*.deb;
		service statsd stop;
		service carbon-cache start;
		echo -e " " > $STATSD_CONF_DIR/localConfig.js;
		cat > $STATSD_CONF_DIR/localConfig.js << EOF
		{
				graphitePort: 2003
				, graphiteHost: "localhost"
				, port: 8125
				, graphite: {
				legacyNamespace: false
		}
}
EOF
		service carbon-cache stop;
		service carbon-cache start;
		service statsd start;
}
####################################################################################################
validate_args;
install_dependencies;
configure_graphite;
configure_apache;
install_statsd;
