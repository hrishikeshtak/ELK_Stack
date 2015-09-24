#!/usr/bin/env python
import sys;
import os;
import subprocess;
import socket;
####################################################################################################
# Variable Declaration 
SCRIPT_NAME=sys.argv[0];
ES_LOCAL_IPADDR=0;
LF_LOCAL_IPADDR=0;
NODE_ID=0;
COUNT_ARGS=len(sys.argv);
DEVNULL=open(os.devnull,'w'); ## To redirect output to /dev/null;
ES_CONF_DIR="/etc/elasticsearch";
KIBANA_CONF_DIR="/opt/kibana/config";
SSL_CONF_DIR="/etc/ssl"; 
LOGSTASH_CONF_DIR="/etc/logstash/conf.d";
LOGSTASH_FORWARDER_CONF_DIR="/etc";
####################################################################################################
def validate_args():
    # check user is ROOT or not
    if not os.geteuid() == 0:
        sys.exit("User is not root");
    if COUNT_ARGS == 1:
        print  "\nERROR: ES_LOCAL_IPADDR missing";
        print_usage();
        sys.exit(0);
    elif COUNT_ARGS == 2:
        print  "\nERROR: LF_LOCAL_IPADDR missing";
        print_usage();
        sys.exit(0);
    elif COUNT_ARGS == 3:
        print  "\nERROR: NODE_ID missing";
        print_usage();
        sys.exit(0);
    elif COUNT_ARGS > 4:
        print "\nERROR: extra argument passed";
        print_usage();
        sys.exit(0);
    global ES_LOCAL_IPADDR;
    global LF_LOCAL_IPADDR;
    global NODE_ID;
    ES_LOCAL_IPADDR=sys.argv[1];
    validate_IP(ES_LOCAL_IPADDR);
    LF_LOCAL_IPADDR=sys.argv[2];
    validate_IP(LF_LOCAL_IPADDR);
    NODE_ID=sys.argv[3];
    if (NODE_ID == "ELK" or NODE_ID == "elk"):
         print NODE_ID;
#          configure_Elasticsearch();
#          configure_Kibana();
         configure_Logstash();
         command = "service elasticsearch status";
         execute_command(command,None,"elasticsearch not started");
         command = "service kibana4 status";
         execute_command(command,None,"kibana not started");
         command = "service logstash status";
         execute_command(command,None,"Logstash not started");
    elif (NODE_ID == "LF" or NODE_ID == "lf") :
        print NODE_ID;
        configure_Logstash_Forwarder(); 
        command = "service logstash-forwarder status";
        execute_command(command,None,"Logstash-forwarder not started");
    else:
        sys.exit("ERROR: Please give appropriate NODE_ID (ELK or LF)");
####################################################################################################
def validate_IP(IP_ADDR):
    try:
        socket.inet_aton(IP_ADDR);
        command = "ping -c1 %s" % IP_ADDR;
        error = "%s is not reachable" % IP_ADDR;
        execute_command(command,DEVNULL,error);
        print "%s is reachable" % IP_ADDR;
    except socket.error:
        print "%s IP Address not valid" %IP_ADDR;
        sys.exit(0);
####################################################################################################
def execute_command(string,disp_flag,error_message):
    return_value = subprocess.call(string,stdout=disp_flag,shell=True);
    error_check(return_value,error_message);
####################################################################################################
def print_usage():
    print  "\nUsage: %s <ES_LOCAL_IPADDR>  <LF_LOCAL_IPADDR> <NODE_ID>" % SCRIPT_NAME;
    print  "    ES_LOCAL_IPADDR - IP address where Elastic search serves the search requests";
    print  "                         (generally PUBLIC n/w IP of installed node)\n";
    print  "    LF_LOCAL_IPADDR - IP address where Logstash-Forwarder installed";
    print  "                         (generally PUBLIC n/w IP of installed node)\n";
    print  "    NODE_ID - 1. ELK (Elasticsearch Logstash Kibana) Setup";
    print  "              2. LF (Logstash-Forwarder) Setup";
    print  "                         (Enter appropriate choice ELK or LF)\n";
####################################################################################################
def error_check(return_value,error_message):
    if return_value != 0:
        print "ERROR: ",error_message;
        sys.exit(0);
####################################################################################################
def configure_Elasticsearch():
    print  "Configuring Elasticsearch\n\n";
    command = "sed -i -e '/cluster.name/ s/^#*/#/' %s/elasticsearch.yml;" %ES_CONF_DIR;
    execute_command(command,None,"Elasticsearch not configured");
    command = "sed -i -e '/network.host/ s/^#*/#/' %s/elasticsearch.yml;" %ES_CONF_DIR;
    execute_command(command,None,"Elasticsearch not configured");
    command = "sed -i -e '$a cluster.name: elasticsearch' %s/elasticsearch.yml;" %ES_CONF_DIR;
    execute_command(command,None,"Elasticsearch not configured");
    command = "sed -i -e '$a network.host: 0.0.0.0' %s/elasticsearch.yml;" %ES_CONF_DIR;
    execute_command(command,None,"Elasticsearch not configured");
    print  "Starting Elasticsearch : \n";
    command = "service elasticsearch restart;";
    execute_command(command,None,"elasticsearch not started");
    execute_command("sleep 2",None,None);
    execute_command("clear",None,None);

###################################################################################################
def configure_Kibana():
    print  "Starting kibana : ";
    command = "service kibana4 restart;";
    execute_command(command,None,"kibana4 not started");
    execute_command("sleep 2",None,None);
    execute_command("clear",None,None);

###################################################################################################
def configure_Logstash():
		print  "Configuring Logstash";
		print  "Generating SSL Certificates";
		command = "mkdir -p /etc/pki/tls/certs;";
		execute_command(command,None,"Logstash not configured");
		command = "mkdir -p /etc/pki/tls/private;";
		execute_command(command,None,"Logstash not configured");
		print  "Configuring openssl.cnf";
		command = "sed -i -e '/subjectAltName/ s/^#*/#/' %s/openssl.cnf;" %SSL_CONF_DIR;
		execute_command(command,None,"Logstash not configured");
		command = "sed -i -e \"226isubjectAltName = IP: %s" %ES_LOCAL_IPADDR;
		command1 = "\" %s/openssl.cnf" %SSL_CONF_DIR;
		final_command = command + command1;
		execute_command(final_command,None,"openssl not configured");
		command = "openssl req -config %s/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout /etc/pki/tls/private/logstash-forwarder.key -out /etc/pki/tls/certs/logstash-forwarder.crt;" %SSL_CONF_DIR;
		execute_command(command,None,"openssl not configured");
		command = 'echo " " > %s/01-lumberjack-input.conf;' %LOGSTASH_CONF_DIR;
		execute_command(command,None,None);
		print  "Configuring 01-lumberjack-input.conf";
		command = "cat >> %s/01-lumberjack-input.conf" %LOGSTASH_CONF_DIR + " << EOF\n";
                command1 = "input {\
                        \n \tlumberjack { \
                        \n \t\tport => 5000 \
                        \n \t\ttype => \"logs\" \
                        \n \t\tssl_certificate => \"/etc/pki/tls/certs/logstash-forwarder.crt\" \
                        \n \t\tssl_key => \"/etc/pki/tls/private/logstash-forwarder.key\" \
                        \n\t} \
                        \n} \
                \nEOF";
		command = command + command1;
		execute_command(command,None,"01-lumberjack-input.conf not configured");
		command = 'echo " " > %s/10-syslog.conf;' %LOGSTASH_CONF_DIR;
		execute_command(command,None,None);
		print  "Configuring 10-syslog.conf";
		command = "cat >> %s/10-syslog.conf" %LOGSTASH_CONF_DIR + " << EOF\n";
		command1 = "filter { \
                        \n \tif [type] == \"syslog\" { \
                        \n \tgrok { \
                        \n \t\tmatch => { \"message\" => \"%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}\" } \
                        \n \t\tadd_field => [ \"received_at\", \"%{@timestamp}\" ] \
                        \n \t\tadd_field => [ \"received_from\", \"%{host}\" ] \
                        \n \t} \
                        \n \tsyslog_pri { } \
                        \n \tdate { \
                        \n \t\tmatch => [ \"syslog_timestamp\", \"MMM  d HH:mm:ss\", \"MMM dd HH:mm:ss\" ] \
                        \n \t} \
                        \n \t} \
                        \n} \
		\nEOF";
		command = command + command1;
		execute_command(command,None,"10-syslog.conf not configured");
		command = 'echo " " > %s/30-lumberjack-output.conf;' %LOGSTASH_CONF_DIR;
		execute_command(command,None,None);
		print  "Configuring 30-lumberjack-output.conf";
		command = "cat >> %s/30-lumberjack-output.conf" %LOGSTASH_CONF_DIR + " << EOF\n";
                command1 = "output { \
                        \n \telasticsearch { host => localhost } \
                        \n \tstdout { codec => rubydebug } \
                        \n}\
		\nEOF";
		command = command + command1;
		execute_command(command,None,"30-lumberjack-output.conf not configured");
		print  "Coping SSL Certificate \n";
		command = "scp /etc/pki/tls/certs/logstash-forwarder.crt root@%s:/tmp" %LF_LOCAL_IPADDR;
		execute_command(command,None,"certificate not copy to %s" %LF_LOCAL_IPADDR);
		print  "Starting logstash : ";
		command = "service logstash restart";
		execute_command(command,None,"Logstash not started");
		execute_command("sleep 2",None,None);
		execute_command("clear",None,None);
###################################################################################################
def configure_Logstash_Forwarder():
		print "Configuring Logstash_Forwarder";
		command = "mkdir -p /etc/pki/tls/certs;";
		execute_command(command,None,"Logstash_Forwarder not configured");
		command = "cp /tmp/logstash-forwarder.crt /etc/pki/tls/certs/;";
		execute_command(command,None,"Logstash_Forwarder not configured");
		command = "rm /etc/logstash-forwarder.conf;";
		execute_command(command,None,"Logstash_Forwarder not configured");
		command = 'echo "  " > %s/logstash-forwarder.conf;' %LOGSTASH_FORWARDER_CONF_DIR;
		execute_command(command,None,"Logstash_Forwarder not configured");
		command = "cat >> %s/logstash-forwarder.conf " %LOGSTASH_FORWARDER_CONF_DIR + "<< EOF\n";
		command1 = "{\
				\n\t\"network\": {\
				\n\t\t\"servers\": [ \"%s:5000\" ],\
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
				\n}\
		\nEOF" %ES_LOCAL_IPADDR;
		command = command + command1;
		execute_command(command,None,"logstash-forwarder.conf not configured");
		print  "Starting Logstash Forwarder";
		command = "service logstash-forwarder restart;";
		execute_command(command,None,"Logstash_Forwarder not started");
		execute_command("sleep 2",None,None);
		execute_command("clear",None,None);

######################################################################################################
execute_command("clear",None,None);
print "\nConfigure Elasticsearch, Logstash, and Kibana 4";
validate_args();
####################################################################################################
