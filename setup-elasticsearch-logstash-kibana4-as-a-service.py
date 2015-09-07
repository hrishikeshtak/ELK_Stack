#!/usr/bin/env python
import sys
import subprocess

subprocess.call("clear",shell=True);
print "\n\n\t\tInstall Elasticsearch, Logstash, and Kibana 4\n";
####################################################################################################
IP_ADDRESS = "0.0.0.0";
USER = "root";


####################################################################################################

print "\t\t1 Install Java 8\n\n";
#subprocess.call("sudo add-apt-repository -y ppa:webupd8team/java",shell=True);
#subprocess.call("sudo apt-get update",shell=True);
#subprocess.call("sudo apt-get -y install oracle-java8-installer",shell=True);
#subprocess.call("java -version",shell=True);
#subprocess.call("sleep 2",shell=True);
#subprocess.call("clear",shell=True);

####################################################################################################

print "\t\t2 Install Elasticsearch\n\n";
#print "Run the following command to import the Elasticsearch public GPG key into apt:\n\n";
#subprocess.call("wget -O - http://packages.elasticsearch.org/GPG-KEY-elasticsearch | sudo apt-key add -",shell=True);
#subprocess.call("echo 'deb http://packages.elasticsearch.org/elasticsearch/1.4/debian stable main' | sudo tee /etc/apt/sources.list.d/elasticsearch.list",shell=True);
#subprocess.call("sudo apt-get update",shell=True);
#subprocess.call("sudo apt-get -y install elasticsearch=1.4.4",shell=True);
#subprocess.call("sudo sed -ie 's/#cluster.name: elasticsearch/cluster.name: elasticsearch/' /etc/elasticsearch/elasticsearch.yml",shell=True);
#string = "sudo sed -ie 's/#network.host: 192.168.0.1/network.host: " + IP_ADDRESS+"/' /etc/elasticsearch/elasticsearch.yml"
#subprocess.call(string,shell=True);
##
#print "To start Elasticsearch on boot up : \n\n";
#subprocess.call("sudo update-rc.d elasticsearch defaults 95 10",shell=True);
#print "Start Elasticsearch : \n\n";
#subprocess.call("sudo service elasticsearch restart",shell=True);
#print "To check the status Elasticsearch : \n\n";
#subprocess.call("sudo service elasticsearch status",shell=True);
#subprocess.call("sleep 2",shell=True);
#subprocess.call("clear",shell=True);
#
####################################################################################################
#
print "\t\t3 Install Kibana4\n\n";
#subprocess.call("cd ~; wget https://download.elasticsearch.org/kibana/kibana/kibana-4.0.1-linux-x64.tar.gz",shell=True);
#subprocess.call("tar -xvf ~/kibana-4.0.1-linux-x64.tar.gz -C ~",shell=True);
#string = "sed -ie 's/host: \"0.0.0.0\"/host: \"" + IP_ADDRESS + "\"/' ~/kibana-4.0.1-linux-x64/config/kibana.yml";
#subprocess.call(string,shell=True);
#string = "sed -ie 's/elasticsearch_url: \"http:\/\/localhost:9200\"/elasticsearch_url: \"http:\/\/"+IP_ADDRESS+":9200\"/' ~/kibana-4.0.1-linux-x64/config/kibana.yml";
#subprocess.call(string,shell=True);
#subprocess.call("sudo mkdir -p /opt/kibana",shell=True);
#subprocess.call("sudo cp -R ~/kibana-4*/* /opt/kibana/",shell=True);
#subprocess.call("cd ~; sudo wget https://gist.githubusercontent.com/thisismitch/8b15ac909aed214ad04a/raw/bce61d85643c2dcdfbc2728c55a41dab444dca20/kibana4",shell=True);
#subprocess.call("sudo mv ~/kibana4 /etc/init.d",shell=True);
#subprocess.call("sudo chmod +x /etc/init.d/kibana4",shell=True);
#print "To start kibana on boot up : \n\n";
#subprocess.call("sudo update-rc.d kibana4 defaults 96 9",shell=True);
#print "Start kibana : \n\n";
#subprocess.call("sudo service kibana4 start",shell=True);
#print "To check the status kibana : \n\n";
#subprocess.call("sudo service kibana4 status",shell=True);
#subprocess.call("sleep 2",shell=True);
#subprocess.call("clear",shell=True);

###################################################################################################

#print "\t\t4 Install Logstash\n\n";
#subprocess.call("echo 'deb http://packages.elasticsearch.org/logstash/1.5/debian stable main' | sudo tee /etc/apt/sources.list.d/logstash.list",shell=True);
#subprocess.call("sudo apt-get update",shell=True);
#subprocess.call("sudo apt-get install logstash -y",shell=True);
#
#print "Generate SSL Certificates\n\n";
#subprocess.call("sudo mkdir -p /etc/pki/tls/certs",shell=True);
#subprocess.call("sudo mkdir /etc/pki/tls/private",shell=True);
#string = "sed -ie '225isubjectAltName = IP: "+IP_ADDRESS+"' /etc/ssl/openssl.cnf";
#subprocess.call(string,shell=True);
#print "Generate the SSL certificate and private key in the appropriate locations (/etc/pki/tls/) \n\n";
#subprocess.call("sudo openssl req -config /etc/ssl/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout /etc/pki/tls/private/logstash-forwarder.key -out /etc/pki/tls/certs/logstash-forwarder.crt",shell=True);
#subprocess.call("ls -l /etc/pki/tls/private/",shell=True);
#subprocess.call("ls -l /etc/pki/tls/certs/",shell=True);
#subprocess.call("sleep 2",shell=True);
#subprocess.call("clear",shell=True);
#
#####################################################################################################
#
#print "\t\t5 Configure Logstash\n\n";
#print "Logstash configuration files are in the JSON-format, and reside in /etc/logstash/conf.d. The configuration consists of three sections: inputs, filters, and outputs.";
#
#subprocess.call("sudo echo \" \" > /etc/logstash/conf.d/01-lumberjack-input.conf",shell=True);
#subprocess.call("sudo sed -ie '1iinput {\n lumberjack {\n port => 5000\n type => \"logs\"\n ssl_certificate => \"/etc/pki/tls/certs/logstash-forwarder.crt\"\n ssl_key => \"/etc/pki/tls/private/logstash-forwarder.key\"\n }\n }' /etc/logstash/conf.d/01-lumberjack-input.conf",shell=True);
#
#print "This specifies a lumberjack input that will listen on tcp port 5000, and it will use the SSL certificate and private key that we created earlier.\n\n";
#
#subprocess.call("sudo echo \" \" > /etc/logstash/conf.d/10-syslog.conf",shell=True);
#subprocess.call("sudo sed -ie '1ifilter { \n if [type] == \"syslog\" { \n grok { \n match => { \"message\" => \"%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}\" } \n add_field => [ \"received_at\", \"%{@timestamp}\" ] \n add_field => [ \"received_from\", \"%{host}\" ] \n } \n syslog_pri { } \n date { \n match => [ \"syslog_timestamp\", \"MMM  d HH:mm:ss\", \"MMM dd HH:mm:ss\" ] \n } \n } \n }' /etc/logstash/conf.d/10-syslog.conf",shell=True);
#
#print "This filter looks for logs that are labeled as \"syslog\" type (by a Logstash Forwarder), and it will try to use \"grok\" to parse incoming syslog logs to make it structured and query-able";
#
#subprocess.call("sudo echo \" \" > /etc/logstash/conf.d/30-lumberjack-output.conf",shell=True);
#subprocess.call("sudo sed -ie '1ioutput { \n elasticsearch { host => localhost } \n stdout { codec => rubydebug } \n }' /etc/logstash/conf.d/30-lumberjack-output.conf",shell=True);
#print "This output basically configures Logstash to store the logs in Elasticsearch.\n\n";
#
#subprocess.call("sudo service logstash restart",shell=True);
#print "To check the status logstash : \n\n";
#subprocess.call("sudo service logstash status",shell=True);
#subprocess.call("sleep 2",shell=True);
#subprocess.call("clear",shell=True);
#
####################################################################################################
#
#print "\t\t6 Set Up Logstash Forwarder\n\n";
#print "Copy SSL Certificate and Logstash Forwarder Package\n\n";
#string = "scp /etc/pki/tls/certs/logstash-forwarder.crt "+USER+"@"+IP_ADDRESS+":/tmp";
#subprocess.call(string,shell=True);
#
#print "Install Logstash Forwarder Package\n\n";
#subprocess.call("echo 'deb http://packages.elasticsearch.org/logstashforwarder/debian stable main' | sudo tee /etc/apt/sources.list.d/logstashforwarder.list",shell=True);
#subprocess.call("wget -O - http://packages.elasticsearch.org/GPG-KEY-elasticsearch | sudo apt-key add -",shell=True);
#subprocess.call("sudo apt-get update",shell=True);
#subprocess.call("sudo apt-get install logstash-forwarder -y",shell=True);
#subprocess.call("sleep 2",shell=True);
#
#subprocess.call("sudo rm /etc/logstash-forwarder.conf",shell=True);
#subprocess.call("echo \" \" > /etc/logstash-forwarder.conf",shell=True);
#
#print "Configure Logstash Forwarder\n\n";
##string = 'sudo sed -ie \'1i{\n\"network\": {\n\"servers\": [ \"0.0.0.0:5000\" ],\n\"ssl ca\": \"/etc/pki/tls/certs/logstash-forwarder.crt\",\n\"timeout\": 15\n },\n \"files\": [\n{\n\"paths\": [\n\"/var/log/syslog\",\n\"/var/log/auth.log\"\n],\n\"fields\": { \"type\": \"syslog\" }\n}\n]\n}\' /etc/logstash-forwarder.conf';
## print string;
##subprocess.call(string,shell=True);
#subprocess.call('sudo echo -e "{\n"network\": {\n\"servers\": [ \"0.0.0.0:5000\" ],\n\"ssl ca\": \"/etc/pki/tls/certs/logstash-forwarder.crt\",\n\"timeout\": 15\n },\n \"files\": [\n{\n\"paths\": [\n\"/var/log/syslog\",\n\"/var/log/auth.log\"\n],\n\"fields\": { \"type\": \"syslog\" }\n}\n]\n}\" > /etc/logstash-forwarder.conf',shell=True);
#
#print "\n This configures Logstash Forwarder to connect to your Logstash Server on port 5000 (the port that we specified an input for earlier), and uses the SSL certificate that we created earlier. The paths section specifies which log files to send (here we specify syslog and auth.log), and the type section specifies that these logs are of type \"syslog* (which is the type that our filter is looking for).\n\n";
#subprocess.call("sleep 2",shell=True);
#print "Restart Logstash Forwarder\n\n";
#subprocess.call("sudo service logstash-forwarder restart",shell=True);
#print "To check the status of Logstash Forwarder\n\n";
#subprocess.call("sudo service logstash-forwarder status",shell=True);
#subprocess.call("sleep 2",shell=True);
#subprocess.call("clear",shell=True);
#
#####################################################################################################
#
#print "Connect to Kibana\n\n";
#print "In a web browser, go to the public IP address of your Logstash Server. After entering the \"kibanaadmin\" credentials.";
#
#
#subprocess.call("sleep 2",shell=True);
#subprocess.call("clear",shell=True);
#subprocess.call("sudo service elasticsearch status",shell=True);
#subprocess.call("sudo service kibana4 status",shell=True);
#subprocess.call("sudo service logstash status",shell=True);
#subprocess.call("sudo service logstash-forwarder status",shell=True);
#
#print "\n\nIf one of these is not running , Please check the log Files in /var/log dir\n\n";
