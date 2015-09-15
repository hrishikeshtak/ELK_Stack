#!/bin/bash

clear;
echo -e "\n\n\t\tInstall Elasticsearch, Logstash, and Kibana 4\n";
####################################################################################################
# Variable Declaration 
ES_LOCAL_IPADDR=$1;
LF_LOCAL_IPADDR=$2;
NODE_ID=$3;
COUNT_PARAM=$#;
PACKAGE_DIR=$HOME/packages;
JDK_TAR_FILE=jdk-8u60-linux-x64.tar.gz;
JAVA_HOME=/usr/local/java;
JAVA_FILE=jdk1.8.0_60;
ELASTICSEARCH_RPM=elasticsearch-1.7.1.noarch.rpm;
ELASTICSEARCH_RPM_PACKAGE=elasticsearch-1.7.1-1.noarch;
KIBANA_TAR_FILE=kibana-4.0.1-linux-x64.tar.gz;
KIBANA_FILE=kibana-4.0.1-linux-x64;
LOGSTASH_RPM=logstash-1.5.4-1.noarch.rpm;
LOGSTASH_RPM_PACKAGE=logstash-1.5.4-1.noarch;
LOGSTASH_FORWARDER_RPM=logstash-forwarder-0.4.0-1.x86_64.rpm;
LOGSTASH_FORWARDER_RPM_PACKAGE=logstash-forwarder-0.4.0-1;
ES_CONF_FILE=/etc/elasticsearch/elasticsearch.yml;


####################################################################################################
print_usage () {
		echo -e "\nUsage: $0 <ES_LOCAL_IPADDR>  <LF_LOCAL_IPADDR> <NODE_ID>"
		echo -e "    ES_LOCAL_IPADDR - IP address where Elastic search serves the search requests"
		echo -e "                         (generally PUBLIC n/w IP of installed node)\n"
		echo -e "    LF_LOCAL_IPADDR - IP address where Logstash-Forwarder installed"
		echo -e "                         (generally PUBLIC n/w IP of installed node)\n"
		echo -e "    NODE_ID - 1. ELK (Elasticsearch Logstash Kibana) Setup"
		echo -e "              2. LF (Logstash-Forwarder) Setup"
		echo -e "                         (Enter appropriate choice ELK or LF)\n"

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
				echo -e "\nERROR: ES_LOCAL_IPADDR missing";
				print_usage;
				exit 0;
		else
				if validate_IP $ES_LOCAL_IPADDR; 
				then 
						echo -e "\nES_LOCAL_IPADDR $ES_LOCAL_IPADDR is reachable";
				else 
						echo -e "\nERROR: ES_LOCAL_IPADDR $ES_LOCAL_IPADDR is unreachable";
						exit 0;
				fi	
		fi
		if [ $COUNT_PARAM -eq 1 ]
		then
				echo -e "\nERROR: LF_LOCAL_IPADDR missing";
				print_usage;
				exit 0;
		else
				if validate_IP $LF_LOCAL_IPADDR; 
				then 
						echo -e "\nLF_LOCAL_IPADDR $LF_LOCAL_IPADDR is reachable";
				else 
						echo -e "\nERROR: LF_LOCAL_IPADDR $LF_LOCAL_IPADDR is unreachable";
						exit 0;
				fi	
		fi
		if [ $COUNT_PARAM -eq 2 ]
		then
				echo -e "\nERROR: NODE_ID missing";
				print_usage;
				exit 0;
		else
				if [[  $NODE_ID == "ELK" || $NODE_ID == elk ]]  			
				then
						echo -e "\n$NODE_ID";
  						install_JAVA;
  						install_Elasticsearch;
  						install_Kibana;
 						install_Logstash;
 						configure_Logstash;

				elif [[ $NODE_ID == "LF" || $NODE_ID == "lf" ]] 
				then
						echo -e "\n$NODE_ID";
  						install_JAVA;
						install_Logstash_Forwarder; 

				else
						echo -e "\nPlease give appropriate NODE_ID (ELK or LF)";
						exit 0;
				fi
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
install_JAVA() {
		echo -e "\t\t1 Installing Java 8\n";
		cd $HOME;
		if [ ! -f $PACKAGE_DIR/$JDK_TAR_FILE ]
		then
				echo -e "\nERROR: $PACKAGE_DIR/$JDK_TAR_FILE not exists";
				exit 0;
		fi
		sudo chmod -R 755 $PACKAGE_DIR/$JDK_TAR_FILE;
		sudo mkdir -p /usr/local/java;
		sudo cp -r $PACKAGE_DIR/$JDK_TAR_FILE /usr/local/java;
		sudo tar -xf /usr/local/java/$JDK_TAR_FILE -C /usr/local/java;

		grep -i "java" /etc/profile &> /dev/null;
		if [ $? -eq 0 ]
		then
				sed -i -e '/java/ s/^#*/#/' /etc/profile;
				sed -i -e '/JAVA/ s/^#*/#/' /etc/profile;
				sed -i -e '/PATH/ s/^#*/#/' /etc/profile;
		fi
		sudo sed -i '$aJAVA_HOME=/usr/local/java/'$JAVA_FILE' \nPATH=$PATH:$HOME/bin:/usr/local/java/'$JAVA_FILE'/bin \nexport JAVA_HOME\nexport PATH' /etc/profile
		sudo update-alternatives --install "/usr/bin/java" "java" "/usr/local/java/$JAVA_FILE/jre/bin/java" 1
		sudo update-alternatives --install "/usr/bin/javac" "javac" "/usr/local/java/$JAVA_FILE/bin/javac" 1 
		sudo update-alternatives --set java /usr/local/java/$JAVA_FILE/jre/bin/java
		sudo update-alternatives --set javac /usr/local/java/$JAVA_FILE/bin/javac
		## Reload your system wide PATH /etc/profile by typing the following command:
		. /etc/profile
		java -version;
		sleep 2;
		clear;
}
####################################################################################################
install_Elasticsearch() {
		echo -e "\t\t2 Install Elasticsearch\n";
		cd $HOME;
		if [ ! -f $PACKAGE_DIR/$ELASTICSEARCH_RPM ]
		then
				echo -e "\nERROR: $PACKAGE_DIR/$ELASTICSEARCH_RPM not exists";
				exit 0;
		fi
		
		rpm -qi $ELASTICSEARCH_RPM_PACKAGE &> /dev/null;
		if [ $? -eq 0 ]
		then
				echo -e "\nElasticSearch already installed";
				sed -i -e '/cluster.name/ s/^#*/#/' $ES_CONF_FILE;
				sed -i -e '/network.host/ s/^#*/#/' $ES_CONF_FILE;

		else
				rpm -Uvh $PACKAGE_DIR/$ELASTICSEARCH_RPM;
		fi
		echo -e "\n\nConfiguring elasticsearch";
		sudo sed -i -e "s/#cluster.name: elasticsearch/cluster.name: elasticsearch/" $ES_CONF_FILE;
		sudo sed -i -e "s/#network.host: 192.168.0.1/network.host: 0.0.0.0/" $ES_CONF_FILE
		sudo sed -i -e "s/#network.host: 0.0.0.0/network.host: 0.0.0.0/" $ES_CONF_FILE
		echo -e "Starting Elasticsearch on boot up : \n\n";
		systemctl daemon-reload;
		systemctl enable elasticsearch.service;
		echo -e "Starting Elasticsearch : \n\n";
		systemctl start elasticsearch.service;
		sleep 2;
		clear;
}
##################################################################################################
install_Kibana() {
		echo -e "\t\t3 Install Kibana4\n";
		cd $HOME;
		if [ ! -f $PACKAGE_DIR/$KIBANA_TAR_FILE ]
		then
				echo -e "\nERROR: $PACKAGE_DIR/$KIBANA_TAR_FILE not exists";
				exit 0;
		fi
		ls -l /opt/kibana/ &> /dev/null;
		if [ $? -eq 0 ]
		then
				rm -rf /opt/kibana/;
		fi

		tar -xf $PACKAGE_DIR/$KIBANA_TAR_FILE -C $PACKAGE_DIR ;
		sudo mkdir -p /opt/kibana;
		sudo cp -R $PACKAGE_DIR/$KIBANA_FILE/* /opt/kibana/;
		echo " " > /etc/systemd/system/kibana4.service;
		sed -i -e "1i[Service] \
				\nExecStart=/opt/kibana/bin/kibana \
				\nRestart=always \
				\nStandardOutput=syslog \
				\nStandardError=syslog \
				\nSyslogIdentifier=kibana4 \
				\nUser=root \
				\nGroup=root \
				\nEnvironment=NODE_ENV=production \
				\n[Install] \
				\nWantedBy=multi-user.target" /etc/systemd/system/kibana4.service;

		echo -e "Starting kibana on boot up : \n\n";
		sudo systemctl enable kibana4;
		echo -e "Starting kibana : \n\n";
		sudo systemctl start kibana4;
		sleep 2;
		clear;
}
##################################################################################################
install_Logstash() {
		echo -e "\t\t4 Install Logstash\n";
		cd $HOME;
		if [ ! -f $PACKAGE_DIR/$LOGSTASH_RPM ]
		then
				echo -e "\nERROR: $PACKAGE_DIR/$LOGSTASH_RPM not exists";
				exit 0;
		fi

		rpm -qi $LOGSTASH_RPM_PACKAGE &> /dev/null;
		if [ $? -eq 0 ]
		then
				echo -e "\nLogstash already installed";
				sudo rm -rf /etc/pki/tls/certs/logstash-forwarder.crt;
				sudo rm -rf /etc/pki/tls/private/logstash-forwarder.key;
				sed -i -e '/subjectAltName/d' /etc/pki/tls/openssl.cnf;
		else
				rpm -Uvh $PACKAGE_DIR/$LOGSTASH_RPM;
		fi

		echo -e "Generating SSL Certificates\n\n";
		sudo mkdir -p /etc/pki/tls/certs;
		sudo mkdir -p /etc/pki/tls/private;
		echo -e "\n\nConfiguring openssl.cnf";
		sed -i -e "225isubjectAltName = IP: $ES_LOCAL_IPADDR" /etc/pki/tls/openssl.cnf;
		sudo openssl req -config /etc/pki/tls/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout /etc/pki/tls/private/logstash-forwarder.key -out /etc/pki/tls/certs/logstash-forwarder.crt;
		if [ $? -ne 0 ]
		then
				echo -e "\nERROR: SSL Certificate is not created";
				exit 0;
		fi
		sleep 2;
		clear;
}
###################################################################################################
configure_Logstash() {
		echo -e "\t\t5 Configure Logstash\n\n";

		echo -e " " > /etc/logstash/conf.d/01-lumberjack-input.conf;
		echo -e "\n\nConfiguring 01-lumberjack-input.conf";
		sudo sed -i -e "1i input {\
				\n \tlumberjack { \
				\n \t\tport => 5000 \
				\n \t\ttype => \"logs\" \
				\n \t\tssl_certificate => \"/etc/pki/tls/certs/logstash-forwarder.crt\" \
				\n \t\tssl_key => \"/etc/pki/tls/private/logstash-forwarder.key\" \
				\n\t} \
				\n}" /etc/logstash/conf.d/01-lumberjack-input.conf;

		echo -e " " > /etc/logstash/conf.d/10-syslog.conf;
		echo -e "\n\nConfiguring 10-syslog.conf";
		sudo sed -i -e "1i filter { \
				\n \tif [type] == \"syslog\" { \
				\n \tgrok { \
				\n \t\tmatch => { \"message\" => \"%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}?:\[%{POSINT:syslog_pid}\]?: %{GREEDYDATA:syslog_message}\" } \
				\n \t\tadd_field => [ \"received_at\", \"%{@timestamp}\" ] \
				\n \t\tadd_field => [ \"received_from\", \"%{host}\" ] \
				\n \t} \
				\n \tsyslog_pri { } \
				\n \tdate { \
				\n \t\tmatch => [ \"syslog_timestamp\", \"MMM  d HH:mm:ss\", \"MMM dd HH:mm:ss\" ] \
				\n \t} \
				\n \t} \
				\n}" /etc/logstash/conf.d/10-syslog.conf;

		echo -e " " > /etc/logstash/conf.d/30-lumberjack-output.conf;
		echo -e "\n\nConfiguring 30-lumberjack-output.conf";
		sudo sed -i -e "1i output { \
				\n \telasticsearch { host => localhost } \
				\n \tstdout { codec => rubydebug } \
				\n}" /etc/logstash/conf.d/30-lumberjack-output.conf;

		echo -e "Coping SSL Certificate \n";
		scp /etc/pki/tls/certs/logstash-forwarder.crt root@$LF_LOCAL_IPADDR:/tmp;
		echo -e "Starting logstash : \n\n";
		systemctl start logstash.service;
		sleep 2;
		clear;
}
##################################################################################################
install_Logstash_Forwarder() {
		echo -e "\t\t6 Install Logstash-Forwarder\n\n";
		cd $HOME;
		if [ ! -f $PACKAGE_DIR/$LOGSTASH_FORWARDER_RPM ]
		then
				echo -e "\nERROR: $PACKAGE_DIR/$LOGSTASH_FORWARDER_RPM not exists";
				exit 0;
		fi

		rpm -qi $LOGSTASH_FORWARDER_RPM_PACKAGE &> /dev/null;
		if [ $? -eq 0 ]
		then
				echo -e "\nLogstash-Forwarder already installed";
				sudo rm -rf /etc/pki/tls/certs/logstash-forwarder.crt;
		else
				rpm -Uvh $PACKAGE_DIR/$LOGSTASH_FORWARDER_RPM;
		fi

		sudo mkdir -p /etc/pki/tls/certs;

		sudo cp /tmp/logstash-forwarder.crt /etc/pki/tls/certs/;
		sudo rm /etc/logstash-forwarder.conf;

		echo -e " " > /etc/logstash-forwarder.conf;
		echo -e "\n\nConfiguring Logstash-Forwarder.cnf";
		sudo sed -i -e "1i{\
				\n\t\"network\": {\
				\n\t\t\"servers\": [ \"$ES_LOCAL_IPADDR:5000\" ],\
				\n\t\t\"ssl ca\": \"/etc/pki/tls/certs/logstash-forwarder.crt\",\
				\n\t\t\"timeout\": 15\
				\n\t},\
				\n\t\"files\": [\
				\n\t{\
				\n\t\t\"paths\": [\
				\n\t\t\"/var/log/syslog\",\
				\n\t\t\"/var/log/auth.log\"\
				\n\t],\
				\n\t\"fields\": { \"type\": \"syslog\" }\
				\n\t}\
				\n\t]\
				\n}" /etc/logstash-forwarder.conf;

		echo -e "Starting Logstash Forwarder\n\n";
		systemctl start logstash-forwarder.service;
		sleep 2;
		clear;
}
#####################################################################################################
# Function Calling

validate_args;

sleep 2;
clear;
sudo systemctl status elasticsearch;
sudo systemctl status kibana4;
sudo systemctl status logstash;
sudo systemctl status logstash-forwarder;

