#!/usr/bin/env python
import sys;
import os;
import subprocess;
import socket;
import ConfigParser
####################################################################################################
# Variable Declaration 
SCRIPT_NAME=sys.argv[0];
GRAPHITE_LOCAL_IPADDR=0;
GRAPHITE_WEB_PORT=0;
ENABLE_GRAPHITE=0;
COUNT_ARGS=len(sys.argv);
DEVNULL=open(os.devnull,'w'); ## To redirect output to /dev/null;
GRAPHITE_CONF_DIR="/etc/graphite";
DEFAULT_CARBON_CONF_DIR="/etc/default";
CARBON_CONF_DIR="/etc/carbon";
STATSD_CONF_DIR="/etc/statsd";
####################################################################################################
class Graphite():
    @classmethod
    def GraphiteConfigParser(self,config_file):
        config = ConfigParser.ConfigParser(allow_no_value=True)
        try:
            config.read(config_file)
            print "Loaded Config File : %s" % config_file
            print "Validating Configutation File..."
            self.validateAllParams(config_file)
        except Exception:
            print traceback.format_exc()

    @classmethod
    def validateAllParams(self,config_file):
        ''' validate config file  '''
        config = ConfigParser.ConfigParser(allow_no_value=True)
        config.read(config_file)
        sectionToBeValidate = config.sections();
        global GRAPHITE_LOCAL_IPADDR;        
        global GRAPHITE_WEB_PORT;
        global ENABLE_GRAPHITE;
        for section in sectionToBeValidate:
            option_list =  config.options(section)
            if section == "GRAPHITE":
                optionList = ['enable_graphite', 'graphite_local_ipaddr', 'graphite_web_port']
                res = cmp(option_list,optionList);
                if res == 0:
                    for paramater in optionList:
                        if paramater == "enable_graphite":
                            ENABLE_GRAPHITE=config.get(section,paramater);
                        elif paramater == "graphite_local_ipaddr":
                            GRAPHITE_LOCAL_IPADDR=config.get(section,paramater);
                        elif paramater == "graphite_web_port":
                            GRAPHITE_WEB_PORT=config.get(section,paramater);
                        else:
                            sys.exit("extra argument in %s") %config_file;
                    if ( ENABLE_GRAPHITE == "True" or ENABLE_GRAPHITE == "true" or ENABLE_GRAPHITE == "TRUE" ):
                        self.validate_args(GRAPHITE_LOCAL_IPADDR,GRAPHITE_WEB_PORT);
                    else:
                        print "ENABLE_GRAPHITE is not True , skipping configuration for Graphite";
                else:
                    print "extra argument in %s" %config_file;
                    sys.exit(0);
            else:
                print "Found new section %s. skipping validation for " %section
                continue
####################################################################################################
    @classmethod
    def validate_args(self,GRAPHITE_IPADDR,GRAPHITE_PORT):
        global GRAPHITE_LOCAL_IPADDR;
        global GRAPHITE_WEB_PORT;
        GRAPHITE_LOCAL_IPADDR=GRAPHITE_IPADDR;
        self.validate_IP(GRAPHITE_LOCAL_IPADDR);
        GRAPHITE_WEB_PORT=GRAPHITE_PORT;
        self.validate_PORT(GRAPHITE_WEB_PORT);
        self.configure_graphite();
        self.configure_apache();
        self.configure_statsd();
        print "SUCCESS: Graphite is Running on %s:%s" %(GRAPHITE_LOCAL_IPADDR,GRAPHITE_WEB_PORT);
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
    def validate_PORT(self,PORT):
        PORT = int(PORT);
        if not (PORT >= 0 and PORT < 65535):
            print "ERROR: Given value is outside the range of (0, 65535): %s" % PORT;
            self.print_usage();
            sys.exit(0);
####################################################################################################
    @classmethod
    def execute_command(self,string,disp_flag,error_message):
        return_value = subprocess.call(string,stdout=disp_flag,shell=True);
        self.error_check(return_value,error_message);
####################################################################################################
    @classmethod
    def error_check(self,return_value,error_message):
        if return_value != 0:
            print "ERROR: ",error_message;
            sys.exit(0);
####################################################################################################
    @classmethod
    def configure_graphite(self):
        command = "sudo sed -i -e '/SECRET_KEY/ s/^#*/#/' %s/local_settings.py;" %GRAPHITE_CONF_DIR;
        self.execute_command(command,None,"configure Graphite not successful");
        command = "sudo sed -i -e '/USE_REMOTE/ s/^#*/#/' %s/local_settings.py;" %GRAPHITE_CONF_DIR;
        self.execute_command(command,None,"configure Graphite not successful");
        command = "sudo sed -i -e '/TIME_ZONE/ s/^#*/#/' %s/local_settings.py;" %GRAPHITE_CONF_DIR;
        self.execute_command(command,None,"configure Graphite not successful");
	command = "sudo sed -i -e '/ALLOWED_HOSTS/ s/^#*/#/' %s/local_settings.py;" %GRAPHITE_CONF_DIR;
        self.execute_command(command,None,"configure Graphite not successful");
        command = "echo \"SECRET_KEY = 'a_salty_string'\" | sudo tee --append %s/local_settings.py;" %GRAPHITE_CONF_DIR;
        self.execute_command(command,DEVNULL,"configure Graphite not successful");
        command = "echo \"TIME_ZONE = 'Asia/Kolkata'\" | sudo tee --append %s/local_settings.py;" %GRAPHITE_CONF_DIR;
        self.execute_command(command,DEVNULL,"configure Graphite not successful");
        command = "echo \"ALLOWED_HOSTS = ['localhost', '%s']\" | sudo tee --append %s/local_settings.py;" %(GRAPHITE_LOCAL_IPADDR,GRAPHITE_CONF_DIR);
        self.execute_command(command,DEVNULL,"configure Graphite not successful");
        command = "sudo sed -i -e '/USE_REMOTE/ s/^#//' %s/local_settings.py;" %GRAPHITE_CONF_DIR;
        self.execute_command(command,None,"configure Graphite not successful");
        command = "echo -e \"no\n\" | graphite-manage syncdb;";
        self.execute_command(command,None,"Database is not synced");
        command = "sudo chmod 777 /var/lib/graphite/graphite.db";
        self.execute_command(command,None,"Database is not synced");
        command = "sudo sed -i -e '/CARBON_CACHE/ s/^#*/#/' %s/graphite-carbon;" %DEFAULT_CARBON_CONF_DIR;
        self.execute_command(command,None,"carbon-cache not enabled");
        command = "sudo sed -i -e '$aCARBON_CACHE_ENABLED=true' %s/graphite-carbon;" %DEFAULT_CARBON_CONF_DIR;
        self.execute_command(command,None,"carbon-cache not enabled");
        command = "sudo sed -i -e '/ENABLE_LOGROTATION/ s/^#*/#/' %s/carbon.conf;" %CARBON_CONF_DIR;
        self.execute_command(command,None,"carbon not configured");
        command = "sudo sed -i -e '$aENABLE_LOGROTATION = True' %s/carbon.conf;" %CARBON_CONF_DIR;
        self.execute_command(command,None,"carbon not configured");
        command = "sudo sed -i -e \"/10s/ s/^#*/#/\" %s/storage-schemas.conf" %CARBON_CONF_DIR;
        self.execute_command(command,None,"carbon not configured");
        command = "sudo sed -i -e \"/test/ s/^#*/#/\" %s/storage-schemas.conf" %CARBON_CONF_DIR;
        self.execute_command(command,None,"carbon not configured");
        command = "sudo sed -i -e \"/stats/ s/^#*/#/\" %s/storage-schemas.conf" %CARBON_CONF_DIR;
        self.execute_command(command,None,"carbon not configured");
        command = "sudo sed -i -e \"10i[test]\
            \\npattern = ^test/\.\
            \\nretentions = 10s:10m,1m:1h,10m:1d\" %s/storage-schemas.conf;" %CARBON_CONF_DIR;
        self.execute_command(command,None,"carbon not configured");
        command = "sudo sed -i -e \"10i[statsd]\
            \\npattern = ^stats.*\
            \\nretentions = 10s:1d,1m:7d,10m:1y\" %s/storage-schemas.conf;" %CARBON_CONF_DIR;
        self.execute_command(command,None,"carbon not configured");
        command = "sudo cp /usr/share/doc/graphite-carbon/examples/storage-aggregation.conf.example %s/storage-aggregation.conf;" %CARBON_CONF_DIR;
        self.execute_command(command,None,"carbon not configured");
        command = "sudo service carbon-cache start;";
        self.execute_command(command,None,"carbon not started");
####################################################################################################
    @classmethod
    def configure_apache(self):
        command = "sudo cp /usr/share/graphite-web/apache2-graphite.conf /etc/apache2/sites-available;";
        self.execute_command(command,None,"apache not configured");
        command = "sudo sed -i -e 's/80/%s/' /etc/apache2/sites-available/apache2-graphite.conf;" %GRAPHITE_WEB_PORT;
        self.execute_command(command,None,"apache not configured");
        command = "sudo sed -i -e '$a Listen %s' /etc/apache2/ports.conf;" %GRAPHITE_WEB_PORT;
        self.execute_command(command,None,"apache not configured");
        command = "sudo a2enmod wsgi;";
        self.execute_command(command,None,"apache not configured");
        command = "sudo a2ensite apache2-graphite;";
        self.execute_command(command,None,"apache not configured");
        command = "sudo service apache2 reload;";
        self.execute_command(command,None,"apache not configured");
#####################################################################################################
    @classmethod
    def configure_statsd(self):
        command = "echo \" \" | sudo tee %s/localConfig.js;" %STATSD_CONF_DIR;
        self.execute_command(command,DEVNULL,"statsd not configured");
        command = "sudo sed -i -e '1i{\
            \\ngraphitePort: 2003\
            \\n, graphiteHost: \"%s\"\
            \\n, port: 8125\
            \\n, graphite: {\
            \\nlegacyNamespace: false\
            \\n}\
            \\n}' %s/localConfig.js;" %(GRAPHITE_LOCAL_IPADDR,STATSD_CONF_DIR);
        self.execute_command(command,None,"statsd not configured");
        command = "sudo service carbon-cache restart;";
        self.execute_command(command,None,"statsd not configured");
        command = "sudo service statsd status;";
        self.execute_command(command,None,"statsd not configured");
####################################################################################################
if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit("Please give ini file as argument")
    Graphite.GraphiteConfigParser(sys.argv[1])
