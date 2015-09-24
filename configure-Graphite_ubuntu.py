#!/usr/bin/env python
import sys;
import os;
import subprocess;
import socket;
####################################################################################################
# Variable Declaration 
SCRIPT_NAME=sys.argv[0];
GRAPHITE_LOCAL_IPADDR=0;
GRAPHITE_WEB_PORT=0;
COUNT_ARGS=len(sys.argv);
DEVNULL=open(os.devnull,'w'); ## To redirect output to /dev/null;
GRAPHITE_CONF_DIR="/etc/graphite";
DEFAULT_CARBON_CONF_DIR="/etc/default";
CARBON_CONF_DIR="/etc/carbon";
STATSD_CONF_DIR="/etc/statsd";
####################################################################################################
def validate_args():
    # check user is ROOT or not
    if not os.geteuid() == 0:
        sys.exit("User is not root");
    if COUNT_ARGS == 1:
        print  "\nERROR: GRAPHITE_LOCAL_IPADDR missing";
        print_usage();
        sys.exit(0);
    elif COUNT_ARGS == 2:
        print  "\nERROR: GRAPHITE_WEB_PORT missing";
        print_usage();
        sys.exit(0);
    elif COUNT_ARGS > 3:
        print "\nERROR: extra argument passed";
        print_usage();
        sys.exit(0);
    global GRAPHITE_LOCAL_IPADDR;
    global GRAPHITE_WEB_PORT;
    GRAPHITE_LOCAL_IPADDR=sys.argv[1];
    validate_IP(GRAPHITE_LOCAL_IPADDR);
    GRAPHITE_WEB_PORT=sys.argv[2];
    validate_PORT(GRAPHITE_WEB_PORT);
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
def validate_PORT(PORT):
    PORT = int(PORT);
    if not (PORT >= 0 and PORT < 65535):
        print "ERROR: Given value is outside the range of (0, 65535): %s" % PORT;
        print_usage();
        sys.exit(0);
        
####################################################################################################
def execute_command(string,disp_flag,error_message):
    return_value = subprocess.call(string,stdout=disp_flag,shell=True);
    error_check(return_value,error_message);
####################################################################################################
def print_usage():
    print "\nUsage: $0 <GRAPHITE_LOCAL_IPADDR>  <GRAPHITE_WEB_PORT> ";
    print "    GRAPHITE_LOCAL_IPADDR - IP address where Graphite will be running";
    print "                         (generally PUBLIC n/w IP of installed node)\n";
    print "    GRAPHITE_WEB_PORT - Port number ";
    print "                         (ex 8000)\n";

###################################################################################################
def error_check(return_value,error_message):
    if return_value != 0:
        print "ERROR: ",error_message;
        sys.exit(0);
####################################################################################################
def configure_graphite():
    command = "sed -i -e '/SECRET_KEY/ s/^#*/#/' %s/local_settings.py;" %GRAPHITE_CONF_DIR;
    execute_command(command,None,"configure Graphite not successful");
    command = "sed -i -e '/USE_REMOTE/ s/^#*/#/' %s/local_settings.py;" %GRAPHITE_CONF_DIR;
    execute_command(command,None,"configure Graphite not successful");
    command = "sed -i -e '/TIME_ZONE/ s/^#*/#/' %s/local_settings.py;" %GRAPHITE_CONF_DIR;
    execute_command(command,None,"configure Graphite not successful");
    command = "echo \"SECRET_KEY = 'a_salty_string'\" >> %s/local_settings.py;" %GRAPHITE_CONF_DIR;
    execute_command(command,None,"configure Graphite not successful");
    command = "echo \"TIME_ZONE = 'Asia/Kolkata'\" >> %s/local_settings.py;" %GRAPHITE_CONF_DIR;
    execute_command(command,None,"configure Graphite not successful");
    command = "sed -i -e '/USE_REMOTE/ s/^#//' %s/local_settings.py;" %GRAPHITE_CONF_DIR;
    execute_command(command,None,"configure Graphite not successful");
    command = "echo -e \"no\n\" | graphite-manage syncdb;";
    execute_command(command,None,"Database is not synced");
    command = "sed -i -e '/CARBON_CACHE/ s/^#*/#/' %s/graphite-carbon;" %DEFAULT_CARBON_CONF_DIR;
    execute_command(command,None,"carbon-cache not enabled");
    command = "sed -i -e '$aCARBON_CACHE_ENABLED=true' %s/graphite-carbon;" %DEFAULT_CARBON_CONF_DIR;
    execute_command(command,None,"carbon-cache not enabled");
    command = "sed -i -e '/ENABLE_LOGROTATION/ s/^#*/#/' %s/carbon.conf;" %CARBON_CONF_DIR;
    execute_command(command,None,"carbon not configured");
    command = "sed -i -e '$aENABLE_LOGROTATION = True' %s/carbon.conf;" %CARBON_CONF_DIR;
    execute_command(command,None,"carbon not configured");
    command = "sed -i -e \"/10s/ s/^#*/#/\" %s/storage-schemas.conf" %CARBON_CONF_DIR;
    execute_command(command,None,"carbon not configured");
    command = "sed -i -e \"/test/ s/^#*/#/\" %s/storage-schemas.conf" %CARBON_CONF_DIR;
    execute_command(command,None,"carbon not configured");
    command = "sed -i -e \"/stats/ s/^#*/#/\" %s/storage-schemas.conf" %CARBON_CONF_DIR;
    execute_command(command,None,"carbon not configured");
    command = "sed -i -e \"10i[test]\
            \\npattern = ^test/\.\
            \\nretentions = 10s:10m,1m:1h,10m:1d\" %s/storage-schemas.conf;" %CARBON_CONF_DIR;
    execute_command(command,None,"carbon not configured");
    command = "sed -i -e \"10i[statsd]\
            \\npattern = ^stats.*\
            \\nretentions = 10s:1d,1m:7d,10m:1y\" %s/storage-schemas.conf;" %CARBON_CONF_DIR;
    execute_command(command,None,"carbon not configured");
    command = "cp /usr/share/doc/graphite-carbon/examples/storage-aggregation.conf.example %s/storage-aggregation.conf;" %CARBON_CONF_DIR;
    execute_command(command,None,"carbon not configured");
    command = "service carbon-cache start;";
    execute_command(command,None,"carbon not started");

####################################################################################################
def configure_apache():
    command = "a2dissite 000-default;";
    execute_command(command,None,"apache not configured");
    command = "cp /usr/share/graphite-web/apache2-graphite.conf /etc/apache2/sites-available;";
    execute_command(command,None,"apache not configured");
    command = "sed -i -e 's/80/%s/' /etc/apache2/sites-available/apache2-graphite.conf;" %GRAPHITE_WEB_PORT;
    execute_command(command,None,"apache not configured");
    command = "sed -i -e '$a Listen %s' /etc/apache2/ports.conf;" %GRAPHITE_WEB_PORT;
    execute_command(command,None,"apache not configured");
    command = "a2enmod wsgi;";
    execute_command(command,None,"apache not configured");
    command = "a2ensite apache2-graphite;";
    execute_command(command,None,"apache not configured");
    command = "service apache2 reload;";
    execute_command(command,None,"apache not configured");
#####################################################################################################
def configure_statsd():
    command = "echo \" \" > %s/localConfig.js;"%STATSD_CONF_DIR;
    execute_command(command,None,"statsd not configured");
    command = "sed -i -e '1i{\
            \\ngraphitePort: 2003\
            \\n, graphiteHost: \"%s\"\
            \\n, port: 8125\
            \\n, graphite: {\
            \\nlegacyNamespace: false\
            \\n}\
            \\n}' %s/localConfig.js;" %(GRAPHITE_LOCAL_IPADDR,STATSD_CONF_DIR);
    execute_command(command,None,"statsd not configured");
    command = "service carbon-cache restart;";
    execute_command(command,None,"statsd not configured");
    command = "service statsd status;";
    execute_command(command,None,"statsd not configured");
####################################################################################################
execute_command("clear",None,None);
print "\nConfigure Graphite";
validate_args();
configure_graphite();
configure_apache();
configure_statsd();
