#!/bin/bash

echo -e "Configure ELK Stack (Elasticsearch, Logstash, Kibana) along with Filebeat\n"

# Variable Declaration 
ES_LOCAL_IPADDR=$1
FB_LOCAL_IPADDR=$2
NODE_ID=$3
COUNT_PARAM=$#
ES_CONF_FILE=/etc/elasticsearch/elasticsearch.yml
LOGSTASH_CONF_PATH=/etc/logstash/conf.d
FILEBEAT_CONF_PATH=/etc/filebeat

error_check() {
    echo -e "\nERROR: $SCRIPT_NAME: at Line $2 : $1"
    exit 0
}

print_usage () {
    echo -e "\nUsage: $0 <ES_LOCAL_IPADDR>  <FB_LOCAL_IPADDR> <NODE_ID>"
    echo -e "    ES_LOCAL_IPADDR - IP address where Elastic search serves the search requests"
    echo -e "                         (generally PUBLIC n/w IP of installed node)\n"
    echo -e "    FB_LOCAL_IPADDR - IP address where Filebeat installed"
    echo -e "                         (generally PUBLIC n/w IP of installed node)\n"
    echo -e "    NODE_ID - 1. ELK (Elasticsearch Logstash Kibana) Setup"
    echo -e "              2. FB (Filebeat) Setup"
    echo -e "                         (Enter appropriate choice ELK or FB)\n"
}

validate_args() {
    # check user is ROOT or not
    if [ $EUID -ne 0 ] 
    then
        echo -e "\nERROR: The user must be root"
        exit 0
    fi
    if [ $COUNT_PARAM -eq 0 ]
    then
        echo -e "\nERROR: ES_LOCAL_IPADDR missing"
        print_usage
        exit 0
    else
        if validate_IP $ES_LOCAL_IPADDR 
        then 
                echo -e "\nES_LOCAL_IPADDR $ES_LOCAL_IPADDR is reachable"
        else 
                echo -e "\nERROR: ES_LOCAL_IPADDR $ES_LOCAL_IPADDR is unreachable"
                exit 0
        fi	
    fi
    if [ $COUNT_PARAM -eq 1 ]
    then
        echo -e "\nERROR: FB_LOCAL_IPADDR missing"
        print_usage
        exit 0
    else
        if validate_IP $FB_LOCAL_IPADDR 
        then 
                echo -e "\nFB_LOCAL_IPADDR $FB_LOCAL_IPADDR is reachable"
        else 
                echo -e "\nERROR: FB_LOCAL_IPADDR $FB_LOCAL_IPADDR is unreachable"
                exit 0
        fi	
    fi
    if [ $COUNT_PARAM -eq 2 ]
    then
        echo -e "\nERROR: NODE_ID missing"
        print_usage
        exit 0
    else
        if [[  $NODE_ID == "ELK" || $NODE_ID == elk ]]  			
        then
            echo -e "\n$NODE_ID"
            install_JAVA
            install_Elasticsearch
            install_Kibana
            install_Logstash
            configure_Logstash
        elif [[ $NODE_ID == "FB" || $NODE_ID == "fb" ]] 
        then
            echo -e "\n$NODE_ID"
            install_Filebeat 
        else
            echo -e "\nPlease give appropriate NODE_ID (ELK or FB)"
            exit 0
        fi
    fi
}

validate_IP() {
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
                && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    if [ $stat -eq 0 ]
    then			
        ping -c1 $1 &> /dev/null
        if [ $? -eq 0 ] 
        then 
                stat=$?
        else 
                stat=$?
        fi
    else
        echo -e "\n$1 is not valid IP ADDRESS"
        exit 0
    fi
    return $stat
}

install_JAVA() {
    echo -e "Installing Java\n\n"
    sudo add-apt-repository -y ppa:webupd8team/java
    sudo apt-get update
    echo -e debconf shared/accepted-oracle-license-v1-1 select true | debconf-set-selections
    echo -e debconf shared/accepted-oracle-license-v1-1 seen true | debconf-set-selections
    sudo apt-get -y install oracle-java8-installer --force-yes
    java -version || { error_check JAVA-not-installed ${LINENO};}
}

install_Elasticsearch() {
    echo -e "Install Elasticsearch\n\n"
    wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
    echo "deb http://packages.elastic.co/elasticsearch/2.x/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-2.x.list
    sudo apt-get update
    sudo apt-get -y install elasticsearch
    echo -e "\n\nConfiguring elasticsearch"
    sed -i '/cluster.name/ s/^#*/#/' $ES_CONF_FILE
    sed -i '/node.name:/ s/^#*/#/' $ES_CONF_FILE
    sed -i '/network.host/ s/^#*/#/' $ES_CONF_FILE
    sed -i '$a cluster.name: elasticsearch-'$ES_LOCAL_IPADDR'' $ES_CONF_FILE 
    sed -i '$a node.name: elasticsearch-'$ES_LOCAL_IPADDR'' $ES_CONF_FILE
    sed -i '$a network.host: 0.0.0.0' $ES_CONF_FILE
    echo -e "Starting Elasticsearch on boot up : \n\n"
    sudo update-rc.d elasticsearch defaults 95 10
    echo -e "Starting Elasticsearch : \n\n"
    sudo service elasticsearch restart
}

install_Kibana() {
    echo -e "Install Kibana\n\n"
    echo "deb http://packages.elastic.co/kibana/4.4/debian stable main" | sudo tee -a /etc/apt/sources.list.d/kibana-4.4.x.list
    sudo apt-get update
    sudo apt-get -y install kibana
    echo -e "Starting kibana on boot up : \n\n"
    sudo update-rc.d kibana defaults 96 9
    echo -e "Starting kibana : \n\n"
    sudo service kibana start
}

install_Logstash() {
    echo -e "Install Logstash\n\n"
    echo 'deb http://packages.elastic.co/logstash/2.2/debian stable main' | sudo tee /etc/apt/sources.list.d/logstash-2.2.x.list
    sudo apt-get update
    sudo apt-get -y install logstash
    echo -e "Generating SSL Certificates\n\n"
    sudo mkdir -p /etc/pki/tls/certs
    sudo mkdir /etc/pki/tls/private
    echo -e "\n\nConfiguring openssl.cnf"
    sed -i -e "225isubjectAltName = IP: $ES_LOCAL_IPADDR" /etc/ssl/openssl.cnf || { error_check SSL-certificate-not-created ${LINENO};}
    sudo openssl req -config /etc/ssl/openssl.cnf -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout /etc/pki/tls/private/filebeat.key -out /etc/pki/tls/certs/filebeat.crt
    if [ $? -ne 0 ]
    then
        echo -e "\nERROR: SSL Certificate is not created"
        exit 0
    fi
}

configure_Logstash() {
    echo -e "Configure Logstash\n\n"
    echo " " | sudo tee $LOGSTASH_CONF_PATH/02-filebeat-input.conf
    cat << EOF | sudo tee $LOGSTASH_CONF_PATH/02-filebeat-input.conf &> /dev/null
input {
    beats {
        port => 5044
        type => "logs"
        ssl => true
        ssl_certificate => "/etc/pki/tls/certs/filebeat.crt"
        ssl_key => "/etc/pki/tls/private/filebeat.key"
    }
}
EOF
    echo " " | sudo tee $LOGSTASH_CONF_PATH/10-syslog.conf
    cat << EOF | sudo tee $LOGSTASH_CONF_PATH/10-syslog.conf &> /dev/null
filter {
    if [type] == "syslog" {
        grok {
            # syslog grok filter
            match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
            add_field => [ "received_at", "%%{@timestamp}" ]
            add_field => [ "received_from", "%%{host}" ]
        }
        # For syslog priority and severity
        syslog_pri { }
        date {
            match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
        }
        uuid {
            target => "@uuid"
            overwrite => true
        }
        # fingerprint of logs to remove redundancy
        fingerprint {
            source => ["message"]
            target => "fingerprint"
            key => "78787878"
            method => "SHA1"
            concatenate_sources => true
        }
    }
}
EOF
    echo " " | sudo tee $LOGSTASH_CONF_PATH/30-elasticsearch-output.conf
    cat << EOF | sudo tee $LOGSTASH_CONF_PATH/30-elasticsearch-output.conf &> /dev/null
output {
    elasticsearch { hosts => ["localhost:9200"] }
    stdout { codec => rubydebug }
}
EOF
    echo -e "Coping SSL Certificate \n"
    scp /etc/pki/tls/certs/filebeat.crt root@$FB_LOCAL_IPADDR:/tmp || { error_check scp-not-done-properly ${LINENO} ; }
    echo -e "Starting logstash : \n\n"
    sudo update-rc.d logstash defaults 96 9
    sudo service logstash restart
}

install_Filebeat() {
    echo -e "Install Filebeat\n\n"
    echo "deb https://packages.elastic.co/beats/apt stable main" |  sudo tee -a /etc/apt/sources.list.d/beats.list
    wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
    sudo apt-get update
    sudo apt-get -y install filebeat
    sudo mkdir -p /etc/pki/tls/certs
    sudo cp /tmp/filebeat.crt /etc/pki/tls/certs/
    sudo sed -i 's/\/var\/log\/\*.log/\/var\/log\/syslog/' $FILEBEAT_CONF_PATH/filebeat.yml
    sudo sed -i 's/input_type: log/# input_type: log/' $FILEBEAT_CONF_PATH/filebeat.yml
    sudo sed -i 's/#document_type: log/document_type: syslog/' $FILEBEAT_CONF_PATH/filebeat.yml
    sudo sed -i 's/#fields_under_root: false/fields_under_root: true/' $FILEBEAT_CONF_PATH/filebeat.yml
    # Disable elsticsearch as output
    sudo sed -i 's/elasticsearch:/#elasticsearch:/' $FILEBEAT_CONF_PATH/filebeat.yml
    sudo sed -i 's/hosts: \[\"localhost:9200\"\]/#hosts: \[\"localhost:9200\"\]/' $FILEBEAT_CONF_PATH/filebeat.yml
    # enable logstash as output
    sudo sed -i 's/#logstash:/logstash:/' $FILEBEAT_CONF_PATH/filebeat.yml
    sudo sed -i '/hosts: \[\".*:5044\"\]/ s/^#*/#/' $FILEBEAT_CONF_PATH/filebeat.yml
    sudo sed -i '/tls:/ s/^#*/#/' $FILEBEAT_CONF_PATH/filebeat.yml
    sudo sed -i '/certificate_authorities:/ s/^#*/#/' $FILEBEAT_CONF_PATH/filebeat.yml
    sudo sed -i "/# The Logstash hosts/a \    \hosts: [\"$ES_LOCAL_IPADDR:5044\"]" $FILEBEAT_CONF_PATH/filebeat.yml
    sudo sed -i 's/#index: filebeat/index: logstash/' $FILEBEAT_CONF_PATH/filebeat.yml
    sudo sed -i "/# Optional TLS. By default is off./a \   \ tls: \\n \    \ certificate_authorities: ['/etc/pki/tls/certs/filebeat.crt']" $FILEBEAT_CONF_PATH/filebeat.yml
    sudo sudo update-rc.d filebeat defaults 95 10
    sudo sudo service filebeat restart
}

# Function Calling
validate_args
