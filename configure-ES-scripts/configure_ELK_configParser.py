#!/usr/bin/env python
import sys;
import os;
import subprocess;
import socket;
import ConfigParser
import traceback
####################################################################################################
# Variable Declaration 
SCRIPT_NAME=sys.argv[0];
ES_LOCAL_IPADDR=0;
LF_LOCAL_IPADDR=0;
ENABLE_ES=0;
ENABLE_LF=0;
COUNT_ARGS=len(sys.argv);
DEVNULL=open(os.devnull,'w'); ## To redirect output to /dev/null;
ES_CONF_DIR="/etc/elasticsearch";
KIBANA_CONF_DIR="/opt/kibana/config";
SSL_CONF_DIR="/etc/ssl"; 
LOGSTASH_CONF_DIR="/etc/logstash/conf.d";
LOGSTASH_FORWARDER_CONF_DIR="/etc";
config_file="/home/hrishi/oc/elasticsearch/Final_ELK_GR_config_scripts/configParser/elasticsearch.ini";
####################################################################################################

# ESConfigParser(config_file);

class Elasticsearch():
    @classmethod
    def ESConfigParser(self,config_file):
        config = ConfigParser.ConfigParser(allow_no_value=True)
        try:
            config.read(config_file)
            print config.sections();
            print "Loaded Config File : %s" % config_file
            print "Validating Configutation File..."
            self.validateAllParams(config_file)
#             print "Validation of configuration file is done..."
        except Exception:
            print traceback.format_exc()

    @classmethod
    def validateAllParams(self,config_file):
        ''' validate config file  '''
        config = ConfigParser.ConfigParser(allow_no_value=True)
        config.read(config_file)
        sectionToBeValidate = config.sections();
        global ES_LOCAL_IPADDR;                                                                                          global LF_LOCAL_IPADDR;
        global ENABLE_ES;
        global ENABLE_LF;
        for section in sectionToBeValidate:
            option_list =  config.options(section)
#             print option_list;
            if section == "ELASTICSEARCH":
                optionList = ['enable_es', 'es_local_ipaddr', 'lf_local_ipaddr']
                res = cmp(option_list,optionList);
                if res == 0:
                    for i in range(0,len(optionList)):
                        if optionList[i] == "enable_es":
                            ENABLE_ES=config.get(section,optionList[i]);
                        elif optionList[i] == "es_local_ipaddr":
                            ES_LOCAL_IPADDR=config.get(section,optionList[i]);
                        elif optionList[i] == "lf_local_ipaddr":
                            LF_LOCAL_IPADDR=config.get(section,optionList[i]);
                        else:
                            sys.exit("extra argument in %s") %config_file;
                    if ( ENABLE_ES == "True" or ENABLE_ES == "true" or ENABLE_ES == "TRUE" ):
                        self.validate_args(ES_LOCAL_IPADDR,LF_LOCAL_IPADDR,"ELK")
                    else:
                        print "ENABLE_ES is not True , skipping configuration for Elasticsearch";
                else:
                    print "extra argument in %s" %config_file;
                    sys.exit(0);
            elif section == "LOGSTASH-FORWARDER":
                optionList = ['enable_lf'];
                res = cmp(option_list,optionList);
                if res == 0:
                    for i in range(0,len(optionList)):
                        if optionList[i] == "enable_lf":
                            ENABLE_LF=config.get(section,optionList[i]);
                        else:
                            sys.exit("extra argument in %s") %config_file;
                    if ( ENABLE_LF == "True" or ENABLE_LF == "true" or ENABLE_LF == "TRUE" ):
                        self.validate_args(ES_LOCAL_IPADDR,LF_LOCAL_IPADDR,"LF")
                    else:
                        print "ENABLE_LF is not True , skipping configuration for Logstash-Forwarder";
                else:
                    print "extra argument in %s" %config_file;
                    sys.exit(0);
            else:
                print "Found new section %s. skipping validation for " %section
                continue


#     @classmethod
#     def configure_ELK(self,ES_IPADDR,LF_IPADDR):
#         self.validate_args(ES_IPADDR,LF_IPADDR,"ELK")

#     @classmethod
#     def configure_LF(self,ES_IPADDR,LF_IPADDR):
#         self.validate_args(ES_IPADDR,LF_IPADDR,"LF")

    @classmethod
    def validate_args(self,ES_IPADDR,LF_IPADDR,NODE_ID):
        """ Validation of argument """
        # check user is ROOT or not
#         if not os.geteuid() == 0:
#             sys.exit("User is not root");
        global ES_LOCAL_IPADDR;
        ES_LOCAL_IPADDR= ES_IPADDR;
        global LF_LOCAL_IPADDR;
        LF_LOCAL_IPADDR = LF_IPADDR;
        self.validate_IP(ES_LOCAL_IPADDR);
        self.validate_IP(LF_LOCAL_IPADDR);
        if (NODE_ID == "ELK" or NODE_ID == "elk"):
            self.configure_Elasticsearch();
            self.configure_Kibana();
            self.configure_Logstash();
            command = "sudo service elasticsearch status";
            self.execute_command(command,None,"elasticsearch not started");
            command = "sudo service kibana4 status";
            self.execute_command(command,None,"kibana not started");
            command = "sudo service logstash status";
            self.execute_command(command,None,"Logstash not started");
            print "SUCCESS: Elasticsearch is running";
        elif (NODE_ID == "LF" or NODE_ID == "lf") :
            self.configure_Logstash_Forwarder(); 
            command = "sudo service logstash-forwarder status";
            self.execute_command(command,None,"Logstash-forwarder not started");
            print "SUCCESS: logstash-forwarder is running";
        else:
            print "NODE_ID is : ",NODE_ID;
            sys.exit("ERROR: Please give appropriate NODE_ID (ELK or LF)");
####################################################################################################
    @classmethod
    def validate_IP(self,IP_ADDR):
        try:
            socket.inet_aton(IP_ADDR);
            command = "ping -c1 %s" % IP_ADDR;
            error = "%s is not reachable" % IP_ADDR;
            self.execute_command(command,DEVNULL,error);
            print "%s is reachable" % IP_ADDR;
        except socket.error:
            print "%s IP Address not valid" %IP_ADDR;
            sys.exit(0);
####################################################################################################
    @classmethod
    def execute_command(self,string,disp_flag,error_message):
        return_value = subprocess.call(string,stdout=disp_flag,shell=True);
        self.error_check(return_value,error_message);
####################################################################################################
    @classmethod
    def print_usage(self):
        print  "\nUsage: %s <ES_LOCAL_IPADDR>  <LF_LOCAL_IPADDR> <NODE_ID>" % SCRIPT_NAME;
        print  "    ES_LOCAL_IPADDR - IP address where Elastic search serves the search requests";
        print  "                         (generally PUBLIC n/w IP of installed node)\n";
        print  "    LF_LOCAL_IPADDR - IP address where Logstash-Forwarder installed";
        print  "                         (generally PUBLIC n/w IP of installed node)\n";
        print  "    NODE_ID - 1. ELK (Elasticsearch Logstash Kibana) Setup";
        print  "              2. LF (Logstash-Forwarder) Setup";
        print  "                         (Enter appropriate choice ELK or LF)\n";
####################################################################################################
    @classmethod
    def error_check(self,return_value,error_message):
        if return_value != 0:
            print "ERROR: ",error_message;
            sys.exit(0);
####################################################################################################
    @classmethod
    def configure_Elasticsearch(self):
#         print  "Configuring Elasticsearch\n\n";
        command = "sudo sed -i -e '/cluster.name/ s/^#*/#/' %s/elasticsearch.yml;" %ES_CONF_DIR;
        self.execute_command(command,None,"Elasticsearch not configured");
        command = "sudo sed -i -e '/network.host/ s/^#*/#/' %s/elasticsearch.yml;" %ES_CONF_DIR;
        self.execute_command(command,None,"Elasticsearch not configured");
        command = "sudo sed -i -e '$a cluster.name: elasticsearch' %s/elasticsearch.yml;" %ES_CONF_DIR;
        self.execute_command(command,None,"Elasticsearch not configured");
        command = "sudo sed -i -e '$a network.host: 0.0.0.0' %s/elasticsearch.yml;" %ES_CONF_DIR;
        self.execute_command(command,None,"Elasticsearch not configured");
#         print "Starting Elasticsearch on boot up : \n\n";                 
        command = "sudo update-rc.d elasticsearch defaults 95 10";
        self.execute_command(command,None,"elasticsearch not started");
#         print  "Starting Elasticsearch : \n";
        command = "sudo service elasticsearch restart;";
        self.execute_command(command,None,"elasticsearch not started");
###################################################################################################
    @classmethod
    def configure_Kibana(self):
#         print  "Starting kibana : ";
#         print "Starting kibana on boot up : \n\n";
        command = "cd ~; wget https://gist.githubusercontent.com/thisismitch/8b15ac909aed214ad04a/raw/bce61d85643c2dcdfbc2728c55a41dab444dca20/kibana4;"
        self.execute_command(command,None,"kibana4 not downloaded");
        command = "mv ~/kibana4 /etc/init.d;"
        self.execute_command(command,None,"kibana4 not downloaded");
        command = "chmod +x /etc/init.d/kibana4;"
        self.execute_command(command,None,"kibana4 not downloaded");
        command = "sudo update-rc.d kibana4 defaults 96 9;"
        self.execute_command(command,None,"kibana4 not started");
        command = "sudo service kibana4 restart;";
        self.execute_command(command,None,"kibana4 not started");
###################################################################################################
    @classmethod
    def configure_Logstash(self):
#         print  "Configuring Logstash";
# 	print  "Generating SSL Certificates";
	command = "sudo mkdir -p /etc/pki/tls/certs;";
	self.execute_command(command,None,"Logstash not configured");
	command = "sudo mkdir -p /etc/pki/tls/private;";
	self.execute_command(command,None,"Logstash not configured");
# 	print  "Configuring openssl.cnf";
	command = "sudo sed -i -e '/subjectAltName/ s/^#*/#/' %s/openssl.cnf;" %SSL_CONF_DIR;
	self.execute_command(command,None,"Logstash not configured");
	command = "sudo sed -i -e \"226isubjectAltName = IP: %s" %ES_LOCAL_IPADDR;
	command1 = "\" %s/openssl.cnf" %SSL_CONF_DIR;
	final_command = command + command1;
	self.execute_command(final_command,None,"openssl not configured");
	command = "sudo openssl req -config %s/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout /etc/pki/tls/private/logstash-forwarder.key -out /etc/pki/tls/certs/logstash-forwarder.crt;" %SSL_CONF_DIR;
	self.execute_command(command,None,"openssl not configured");
	command = 'echo " " | sudo tee %s/01-lumberjack-input.conf;' %LOGSTASH_CONF_DIR;
	self.execute_command(command,DEVNULL,None);
# 	print  "Configuring 01-lumberjack-input.conf";
        command = "cat << EOF | sudo tee %s/01-lumberjack-input.conf\n" %LOGSTASH_CONF_DIR;
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
	self.execute_command(command,DEVNULL,"01-lumberjack-input.conf not configured");
	command = 'echo " " | sudo tee %s/10-syslog.conf;' %LOGSTASH_CONF_DIR;
	self.execute_command(command,DEVNULL,None);
# 	print  "Configuring 10-syslog.conf";
        command = "cat << EOF | sudo tee %s/10-syslog.conf\n" %LOGSTASH_CONF_DIR;
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
	self.execute_command(command,DEVNULL,"10-syslog.conf not configured");
	command = 'echo " " | sudo tee %s/30-lumberjack-output.conf;' %LOGSTASH_CONF_DIR;
	self.execute_command(command,DEVNULL,None);
#         print  "Configuring 30-lumberjack-output.conf";
        command = "cat << EOF | sudo tee %s/30-lumberjack-output.conf\n" %LOGSTASH_CONF_DIR; 
        command1 = "output { \
                \n \telasticsearch { host => localhost } \
                \n \tstdout { codec => rubydebug } \
                \n}\
	\nEOF";
        command = command + command1;
	self.execute_command(command,DEVNULL,"30-lumberjack-output.conf not configured");
# 	print  "Coping SSL Certificate \n";
	command = "scp /etc/pki/tls/certs/logstash-forwarder.crt root@%s:/tmp" %LF_LOCAL_IPADDR;
	self.execute_command(command,None,"certificate not copy to %s" %LF_LOCAL_IPADDR);
#         print "Starting Logstash on boot up : \n\n";
        command = "sudo update-rc.d logstash defaults 95 10";
        self.execute_command(command,None,"Logstash not started");
# 	print  "Starting logstash : ";
	command = "sudo service logstash restart";
	self.execute_command(command,None,"Logstash not started");
##################################################################################################
    @classmethod
    def configure_Logstash_Forwarder(self):
#         print "Configuring Logstash_Forwarder";
	command = "sudo mkdir -p /etc/pki/tls/certs;";
	self.execute_command(command,None,"Logstash_Forwarder not configured");
	command = "sudo cp /tmp/logstash-forwarder.crt /etc/pki/tls/certs/;";
	self.execute_command(command,None,"Logstash_Forwarder not configured , first configure elasticsearch");
	command = "sudo rm /etc/logstash-forwarder.conf;";
	self.execute_command(command,None,"Logstash_Forwarder not configured");
	command = 'echo " " | sudo tee %s/logstash-forwarder.conf;' %LOGSTASH_FORWARDER_CONF_DIR;
	self.execute_command(command,DEVNULL,"Logstash_Forwarder not configured");
        command = "cat << EOF | sudo tee %s/logstash-forwarder.conf\n" %LOGSTASH_FORWARDER_CONF_DIR; 
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
	self.execute_command(command,DEVNULL,"logstash-forwarder.conf not configured");
#         print "Starting Logstash-forwarder on boot up : \n\n";
        command = "sudo update-rc.d logstash-forwarder defaults 95 10";
        self.execute_command(command,None,"Logstash_Forwarder not started");
# 	print  "Starting Logstash Forwarder";
	command = "sudo service logstash-forwarder restart;";
	self.execute_command(command,None,"Logstash_Forwarder not started");

######################################################################################################
