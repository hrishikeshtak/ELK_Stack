#!/bin/bash

clear;
echo -e "\n\n\t\tInstall Elasticsearch, Logstash, and Kibana 4\n";
####################################################################################################
# Variable Declaration 
NODE_ID=$1;
COUNT_PARAM=$#;
####################################################################################################
error_check() {
		echo -e "\nERROR: $SCRIPT_NAME: at Line $2 : $1";
		exit 0;
}

print_usage () {
		echo -e "\nUsage: $0 <NODE_ID>"
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
####################################################################################################
install_JAVA() {
		echo -e "\t\t1 Installing Java 8\n\n";
		add-apt-repository -y ppa:webupd8team/java;
		apt-get update;
		echo -e debconf shared/accepted-oracle-license-v1-1 select true | debconf-set-selections;
		echo -e debconf shared/accepted-oracle-license-v1-1 seen true | debconf-set-selections;
		apt-get -y install oracle-java8-installer --force-yes;
		java -version || { error_check JAVA-not-installed ${LINENO};};
		sleep 2;
		clear;
}
####################################################################################################
install_Elasticsearch() {
		echo -e "\t\t2 Install Elasticsearch\n\n";
		wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | apt-key add -
		echo -e "deb http://packages.elastic.co/elasticsearch/1.7/debian stable main" | tee -a /etc/apt/sources.list.d/elasticsearch-1.7.list
		apt-get update && apt-get -y install elasticsearch=1.7.1;
}
##################################################################################################
install_Kibana() {
	echo -e "\t\t3 Install Kibana4\n\n";
	if [ ! -f ~/kibana-4.0.1-linux-x64.tar.gz ]
	then
			cd ~; wget https://download.elastic.co/kibana/kibana/kibana-4.1.2-linux-x64.tar.gz;
	fi
	tar -xvf ~/kibana-4.1.2-linux-x64.tar.gz -C ~;
	mkdir -p /opt/kibana;
	cp -R ~/kibana-4*/* /opt/kibana/;
}
##################################################################################################
install_Logstash() {
		echo -e "\t\t4 Install Logstash\n\n";
		wget -qO - https://packages.elasticsearch.org/GPG-KEY-elasticsearch | apt-key add -
		echo -e "deb http://packages.elasticsearch.org/logstash/1.5/debian stable main" | tee /etc/apt/sources.list.d/logstash.list;
		apt-get update && apt-get -y install logstash=1:1.5.4-1;
}
###################################################################################################
install_Logstash_Forwarder() {
		echo -e "\t\t6 Install Logstash-Forwarder\n\n";
		wget -O - http://packages.elasticsearch.org/GPG-KEY-elasticsearch | apt-key add -;
		echo -e "deb http://packages.elasticsearch.org/logstashforwarder/debian stable main" | tee /etc/apt/sources.list.d/logstashforwarder.list;
		apt-get update && apt-get install logstash-forwarder -y;
}
#####################################################################################################
validate_args;
