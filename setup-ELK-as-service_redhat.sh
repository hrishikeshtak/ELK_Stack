#!/bin/bash

clear;
echo -e "\n\n\t\tInstall Elasticsearch, Logstash, and Kibana 4\n";
####################################################################################################
variable_Declaration() {
		# Server IP address = IP address of Server on which kibana , elasticsearch is running
		IP_ADDRESS_SERVER="192.168.2.98";
		USER="root";
		CLIENT_IP="127.0.0.1";
# 		CLIENT_IP="192.168.2.81";
		JDK_TAR_FILE=jdk-8u60-linux-x64.tar.gz;
		JAVA_HOME=/usr/local/java;
		JAVA_FILE=jdk1.8.0_60;
}
####################################################################################################
install_JAVA() {
		yum -y install wget;
		echo -e "\t\t1 Installing Java 8\n\n";
		cd $HOME;
		sudo  wget --no-check-certificate --no-cookies --header "Cookie: oraclelicense=accept-securebackup-cookie"  http://download.oracle.com/otn-pub/java/jdk/8u60-b27/jdk-8u60-linux-x64.tar.gz;
		sudo chmod -R 755 $HOME/$JDK_TAR_FILE;
		sudo mkdir -p /usr/local/java;
		sudo cp -r $HOME/$JDK_TAR_FILE /usr/local/java;
		sudo tar -xf /usr/local/java/$JDK_TAR_FILE -C /usr/local/java;
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
		echo -e "\t\t2 Install Elasticsearch\n\n";
		wget https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-1.7.1.noarch.rpm;
		rpm -Uvh elasticsearch-1.7.1.noarch.rpm;
		echo -e "\n\nConfiguring elasticsearch";
		sudo sed -i -e "s/#cluster.name: elasticsearch/cluster.name: elasticsearch/" /etc/elasticsearch/elasticsearch.yml;
		sudo sed -i -e "s/#network.host: 192.168.0.1/network.host: 0.0.0.0/" /etc/elasticsearch/elasticsearch.yml
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
	echo -e "\t\t3 Install Kibana4\n\n";
	cd ~; wget https://download.elasticsearch.org/kibana/kibana/kibana-4.0.1-linux-x64.tar.gz;
	tar -xvf ~/kibana-4.0.1-linux-x64.tar.gz -C ~;
# 	sed -ie "s/host: \"0.0.0.0\"/host: \"$IP_ADDRESS_SERVER\"/" ~/kibana-4.0.1-linux-x64/config/kibana.yml;
	sudo mkdir -p /opt/kibana;
	sudo cp -R ~/kibana-4*/* /opt/kibana/;
	echo " " > /etc/systemd/system/kibana4.service;
	sed -i -e "1i[Service]\nExecStart=/opt/kibana/bin/kibana\nRestart=always\nStandardOutput=syslog\nStandardError=syslog\nSyslogIdentifier=kibana4\nUser=root\nGroup=root\nEnvironment=NODE_ENV=production\n\n[Install]\nWantedBy=multi-user.target" /etc/systemd/system/kibana4.service;

	echo -e "Starting kibana on boot up : \n\n";
	sudo systemctl enable kibana4;
	echo -e "Starting kibana : \n\n";
	sudo systemctl start kibana4;
	sleep 2;
	clear;
}
##################################################################################################
install_Logstash() {
		echo -e "\t\t4 Install Logstash\n\n";
		cd ~;
 		wget https://download.elastic.co/logstash/logstash/packages/centos/logstash-1.5.4-1.noarch.rpm;
		rpm -Uvh ~/logstash-1.5.4-1.noarch.rpm
		echo -e "Generating SSL Certificates\n\n";
		sudo mkdir -p /etc/pki/tls/certs;
		sudo mkdir -p /etc/pki/tls/private;
		echo -e "\n\nConfiguring openssl.cnf";
		sed -i -e "225isubjectAltName = IP: $IP_ADDRESS_SERVER" /etc/pki/tls/openssl.cnf;
		sudo openssl req -config /etc/pki/tls/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout /etc/pki/tls/private/logstash-forwarder.key -out /etc/pki/tls/certs/logstash-forwarder.crt;
		ls -l /etc/pki/tls/private/;
		ls -l /etc/pki/tls/certs/;
		sleep 2;
		clear;
}
###################################################################################################
configure_Logstash() {
		echo -e "\t\t5 Configure Logstash\n\n";
		echo -e " " > /etc/logstash/conf.d/01-lumberjack-input.conf;
		echo -e "\n\nConfiguring 01-lumberjack-input.conf";
		sudo sed -i -e "1i input {\n \tlumberjack {\n \t\tport => 5000\n \t\ttype => \"logs\"\n \t\tssl_certificate => \"/etc/pki/tls/certs/logstash-forwarder.crt\"\n \t\tssl_key => \"/etc/pki/tls/private/logstash-forwarder.key\"\n\t}\n}" /etc/logstash/conf.d/01-lumberjack-input.conf;
		echo -e " " > /etc/logstash/conf.d/10-syslog.conf;
		echo -e "\n\nConfiguring 10-syslog.conf";
		sudo sed -i -e "1i filter { \n \tif [type] == \"syslog\" { \n \tgrok { \n \t\tmatch => { \"message\" => \"%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}?:\[%{POSINT:syslog_pid}\]?: %{GREEDYDATA:syslog_message}\" } \n \t\tadd_field => [ \"received_at\", \"%{@timestamp}\" ] \n \t\tadd_field => [ \"received_from\", \"%{host}\" ] \n \t} \n \tsyslog_pri { } \n \tdate { \n \t\tmatch => [ \"syslog_timestamp\", \"MMM  d HH:mm:ss\", \"MMM dd HH:mm:ss\" ] \n \t} \n \t} \n}" /etc/logstash/conf.d/10-syslog.conf;
		echo -e " " > /etc/logstash/conf.d/30-lumberjack-output.conf;
		echo -e "\n\nConfiguring 30-lumberjack-output.conf";
		sudo sed -i -e "1i output { \n \telasticsearch { host => localhost } \n \tstdout { codec => rubydebug } \n}" /etc/logstash/conf.d/30-lumberjack-output.conf;
		echo -e "Starting logstash : \n\n";
		systemctl start logstash.service;
		sleep 2;
		clear;
}
##################################################################################################
install_Logstash_Forwarder() {
		echo -e "\t\t6 Install Logstash-Forwarder\n\n";
		echo -e "Coping SSL Certificate and Logstash Forwarder Package\n\n";
		scp /etc/pki/tls/certs/logstash-forwarder.crt $USER@$CLIENT_IP:/tmp;
		wget https://download.elasticsearch.org/logstash-forwarder/binaries/logstash-forwarder-0.4.0-1.x86_64.rpm
		rpm -Uvh logstash-forwarder-0.4.0-1.x86_64.rpm;
		sudo mkdir -p /etc/pki/tls/certs;

		sudo cp /tmp/logstash-forwarder.crt /etc/pki/tls/certs/;
		sudo rm /etc/logstash-forwarder.conf;
		echo -e " " > /etc/logstash-forwarder.conf;
		echo -e "\n\nConfiguring Logstash-Forwarder.cnf";
		sudo sed -i -e "1i{\n\t\"network\": {\n\t\t\"servers\": [ \"$IP_ADDRESS_SERVER:5000\" ],\n\t\t\"ssl ca\": \"/etc/pki/tls/certs/logstash-forwarder.crt\",\n\t\t\"timeout\": 15\n\t},\n\t\"files\": [\n\t{\n\t\t\"paths\": [\n\t\t\"/var/log/syslog\",\n\t\t\"/var/log/auth.log\"\n\t],\n\t\"fields\": { \"type\": \"syslog\" }\n\t}\n\t]\n}" /etc/logstash-forwarder.conf;

		echo -e "Starting Logstash Forwarder\n\n";
		systemctl start logstash-forwarder.service;
		sleep 2;
		clear;
}
#####################################################################################################
# Function Calling

variable_Declaration;
return_val=$(echo $?);
if [ "$return_val" -gt 0 ]
then
		echo -e "\nError in variable_Declaration function\n";
		exit 0;
fi

install_JAVA;
return_val=$(echo $?);
if [ "$return_val" -gt 0 ]
then
		echo -e "\nError in install_JAVA function\n";
		exit 0;
fi

install_Elasticsearch;
return_val=$(echo $?);
if [ "$return_val" -gt 0 ]
then
		echo -e "\nError in install_Elasticsearch function\n";
		exit 0;
fi

install_Kibana;
return_val=$(echo $?);
if [ "$return_val" -gt 0 ]
then
		echo -e "\nError in install_Kibana function\n";
		exit 0;
fi

install_Logstash;
return_val=$(echo $?);
if [ "$return_val" -gt 0 ]
then
		echo -e "\nError in install_Logstash function\n";
		exit 0;
fi

configure_Logstash;
return_val=$(echo $?);
if [ "$return_val" -gt 0 ]
then
		echo -e "\nError in configure_Logstash function\n";
		exit 0;
fi

install_Logstash_Forwarder;
return_val=$(echo $?);
if [ "$return_val" -gt 0 ]
then
		echo -e "\nError in install_Logstash_Forwarder function\n";
		exit 0;
fi

sleep 2;
clear;
sudo systemctl status elasticsearch;
sudo systemctl status kibana4;
sudo systemctl status logstash;
sudo systemctl status logstash-forwarder;

