#!/bin/bash

clear;
echo "\n\n\t\tInstall Elasticsearch, Logstash, and Kibana 4\n";
####################################################################################################
variable_Declaration() {
		# Server IP address = IP address of Server on which kibana , elasticsearch is running
		IP_ADDRESS_SERVER="192.168.104.195";
		USER="root";
		CLIENT_IP="127.0.0.1";
# 		CLIENT_IP="192.168.2.81";
}
####################################################################################################
install_JAVA() {
		echo "\t\t1 Installing Java 8\n\n";
		sudo add-apt-repository -y ppa:webupd8team/java;
		sudo apt-get update;
		echo debconf shared/accepted-oracle-license-v1-1 select true | sudo debconf-set-selections;
		echo debconf shared/accepted-oracle-license-v1-1 seen true | sudo debconf-set-selections;
		sudo apt-get -y install oracle-java8-installer;
		java -version;
		sleep 2;
		clear;
}
####################################################################################################
install_Elasticsearch() {
		echo "\t\t2 Install Elasticsearch\n\n";
		wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
		echo "deb http://packages.elastic.co/elasticsearch/1.7/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-1.7.list
		sudo apt-get update && sudo apt-get -y install elasticsearch=1.7.1;
		echo "\n\nConfiguring elasticsearch";
		sudo sed -i -e "s/#cluster.name: elasticsearch/cluster.name: elasticsearch/" /etc/elasticsearch/elasticsearch.yml;
		sudo sed -i -e "s/#network.host: 192.168.0.1/network.host: 0.0.0.0/" /etc/elasticsearch/elasticsearch.yml
		echo "Starting Elasticsearch on boot up : \n\n";
		sudo update-rc.d elasticsearch defaults 95 10;
		echo "Starting Elasticsearch : \n\n";
		sudo service elasticsearch restart;
# 		echo "Checking the status of Elasticsearch : \n\n";
# 		sudo service elasticsearch status;
		sleep 2;
		clear;
}
##################################################################################################
install_Kibana() {
	echo "\t\t3 Install Kibana4\n\n";
	cd ~; wget https://download.elasticsearch.org/kibana/kibana/kibana-4.0.1-linux-x64.tar.gz;
	tar -xvf ~/kibana-4.0.1-linux-x64.tar.gz -C ~;
# 	sed -ie "s/host: \"0.0.0.0\"/host: \"$IP_ADDRESS_SERVER\"/" ~/kibana-4.0.1-linux-x64/config/kibana.yml;
	sudo mkdir -p /opt/kibana;
	sudo cp -R ~/kibana-4*/* /opt/kibana/;
	cd ~; sudo wget https://gist.githubusercontent.com/thisismitch/8b15ac909aed214ad04a/raw/bce61d85643c2dcdfbc2728c55a41dab444dca20/kibana4;
	sudo mv ~/kibana4 /etc/init.d;
	sudo chmod +x /etc/init.d/kibana4;
	echo "Starting kibana on boot up : \n\n";
	sudo update-rc.d kibana4 defaults 96 9;
	echo "Starting kibana : \n\n";
	sudo service kibana4 start;
# 	echo "Checking the status of kibana : \n\n";
# 	sudo service kibana4 status;
	sleep 2;
	clear;
}
##################################################################################################
install_Logstash() {
		echo "\t\t4 Install Logstash\n\n";
		wget -qO - https://packages.elasticsearch.org/GPG-KEY-elasticsearch | sudo apt-key add -
		echo "deb http://packages.elasticsearch.org/logstash/1.5/debian stable main" | sudo tee /etc/apt/sources.list.d/logstash.list;
		sudo apt-get update && sudo apt-get -y install logstash=1:1.5.4-1;
		echo "Generating SSL Certificates\n\n";
		sudo mkdir -p /etc/pki/tls/certs;
		sudo mkdir /etc/pki/tls/private;
		echo "\n\nConfiguring openssl.cnf";
		sed -i -e "225isubjectAltName = IP: $IP_ADDRESS_SERVER" /etc/ssl/openssl.cnf;
		sudo openssl req -config /etc/ssl/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout /etc/pki/tls/private/logstash-forwarder.key -out /etc/pki/tls/certs/logstash-forwarder.crt;
		ls -l /etc/pki/tls/private/;
		ls -l /etc/pki/tls/certs/;
		sleep 2;
		clear;
}
###################################################################################################
configure_Logstash() {
		echo "\t\t5 Configure Logstash\n\n";
		echo " " > /etc/logstash/conf.d/01-lumberjack-input.conf;
		echo "\n\nConfiguring 01-lumberjack-input.conf";
		sudo sed -i -e "1i input {\n \tlumberjack {\n \t\tport => 5000\n \t\ttype => \"logs\"\n \t\tssl_certificate => \"/etc/pki/tls/certs/logstash-forwarder.crt\"\n \t\tssl_key => \"/etc/pki/tls/private/logstash-forwarder.key\"\n\t}\n}" /etc/logstash/conf.d/01-lumberjack-input.conf;
		echo " " > /etc/logstash/conf.d/10-syslog.conf;
		echo "\n\nConfiguring 10-syslog.conf";
		sudo sed -i -e "1i filter { \n \tif [type] == \"syslog\" { \n \tgrok { \n \t\tmatch => { \"message\" => \"%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}?:\[%{POSINT:syslog_pid}\]?: %{GREEDYDATA:syslog_message}\" } \n \t\tadd_field => [ \"received_at\", \"%{@timestamp}\" ] \n \t\tadd_field => [ \"received_from\", \"%{host}\" ] \n \t} \n \tsyslog_pri { } \n \tdate { \n \t\tmatch => [ \"syslog_timestamp\", \"MMM  d HH:mm:ss\", \"MMM dd HH:mm:ss\" ] \n \t} \n \t} \n}" /etc/logstash/conf.d/10-syslog.conf;
		echo " " > /etc/logstash/conf.d/30-lumberjack-output.conf;
		echo "\n\nConfiguring 30-lumberjack-output.conf";
		sudo sed -i -e "1i output { \n \telasticsearch { host => localhost } \n \tstdout { codec => rubydebug } \n}" /etc/logstash/conf.d/30-lumberjack-output.conf;
		echo "Starting logstash : \n\n";
		sudo service logstash restart;
# 		echo "Checking the status of logstash : \n\n";
# 		sudo service logstash status;
		sleep 2;
		clear;
}
##################################################################################################
install_Logstash_Forwarder() {
		echo "\t\t6 Install Logstash-Forwarder\n\n";
		echo "Coping SSL Certificate and Logstash Forwarder Package\n\n";
		scp /etc/pki/tls/certs/logstash-forwarder.crt $USER@$CLIENT_IP:/tmp;
		wget -O - http://packages.elasticsearch.org/GPG-KEY-elasticsearch | sudo apt-key add -;
		echo "deb http://packages.elasticsearch.org/logstashforwarder/debian stable main" | sudo tee /etc/apt/sources.list.d/logstashforwarder.list;
		sudo apt-get update && sudo apt-get install logstash-forwarder -y;
		sudo mkdir -p /etc/pki/tls/certs;
		sudo cp /tmp/logstash-forwarder.crt /etc/pki/tls/certs/;
		sudo rm /etc/logstash-forwarder.conf;
		echo " " > /etc/logstash-forwarder.conf;
		echo "\n\nConfiguring Logstash-Forwarder.cnf";
		sudo sed -i -e "1i{\n\t\"network\": {\n\t\t\"servers\": [ \"$IP_ADDRESS_SERVER:5000\" ],\n\t\t\"ssl ca\": \"/etc/pki/tls/certs/logstash-forwarder.crt\",\n\t\t\"timeout\": 15\n\t},\n\t\"files\": [\n\t{\n\t\t\"paths\": [\n\t\t\"/var/log/syslog\",\n\t\t\"/var/log/auth.log\"\n\t],\n\t\"fields\": { \"type\": \"syslog\" }\n\t}\n\t]\n}" /etc/logstash-forwarder.conf;

		echo "Starting Logstash Forwarder\n\n";
		sudo service logstash-forwarder start;
# 		echo "Checking the status of Logstash Forwarder\n\n";
# 		sudo service logstash-forwarder status;
		sleep 2;
		clear;
}
#####################################################################################################
# Function Calling

variable_Declaration;
return_val=$(echo $?);
if [ "$return_val" -gt 0 ]
then
		echo "\nError in variable_Declaration function\n";
		exit 0;
fi

install_JAVA;
return_val=$(echo $?);
if [ "$return_val" -gt 0 ]
then
		echo "\nError in install_JAVA function\n";
		exit 0;
fi

install_Elasticsearch;
return_val=$(echo $?);
if [ "$return_val" -gt 0 ]
then
		echo "\nError in install_Elasticsearch function\n";
		exit 0;
fi

install_Kibana;
return_val=$(echo $?);
if [ "$return_val" -gt 0 ]
then
		echo "\nError in install_Kibana function\n";
		exit 0;
fi

install_Logstash;
return_val=$(echo $?);
if [ "$return_val" -gt 0 ]
then
		echo "\nError in install_Logstash function\n";
		exit 0;
fi

configure_Logstash;
return_val=$(echo $?);
if [ "$return_val" -gt 0 ]
then
		echo "\nError in configure_Logstash function\n";
		exit 0;
fi

install_Logstash_Forwarder;
return_val=$(echo $?);
if [ "$return_val" -gt 0 ]
then
		echo "\nError in install_Logstash_Forwarder function\n";
		exit 0;
fi

sleep 2;
clear;
sudo service elasticsearch status;
sudo service kibana4 status;
sudo service logstash status;
sudo service logstash-forwarder status;

