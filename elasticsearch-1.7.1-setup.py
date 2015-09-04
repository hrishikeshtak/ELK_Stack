#!/usr/bin/env python
import sys
import subprocess

subprocess.call("clear",shell=True);
print "\n\nElasticSearch-1.7.1 Setup\n";

#############################################################
HOME_DIR="$HOME/elasticsearch";
USER = "Hrishi";
IP = "127.0.0.1";
#############################################################
string = "mkdir -p " + HOME_DIR;
subprocess.call(string,shell=True);
 
subprocess.call("wget -P $HOME/elasticsearch https://download.elastic.co/elasticsearch/elasticsearch/elasticsearch-1.7.1.tar.gz",shell=True);

string = "tar -xvf "+ HOME_DIR + "/elasticsearch-1.7.1.tar.gz -C "+ HOME_DIR;
subprocess.call(string,shell=True);

print"\n\nSetting elasticsearch.yml File";

string = "sed -ie 's/#cluster.name: elasticsearch/cluster.name: elasticsearch/' "+ HOME_DIR + "/elasticsearch-1.7.1/config/elasticsearch.yml"
subprocess.call(string,shell=True);

string = "sed -ie 's/#node.name: \"Franz Kafka\"/node.name: \"" + USER +  "\"/' "+ HOME_DIR + "/elasticsearch-1.7.1/config/elasticsearch.yml"
subprocess.call(string,shell=True);

string = "sed -ie 's/#network.host: 192.168.0.1/network.host: " + IP +"/' "+ HOME_DIR + "/elasticsearch-1.7.1/config/elasticsearch.yml"
subprocess.call(string,shell=True);

print "\n\nInstall the Plugins";
string = HOME_DIR + "/elasticsearch-1.7.1/bin/plugin -install mobz/elasticsearch-head";
subprocess.call(string,shell=True);
string = HOME_DIR + "/elasticsearch-1.7.1/bin/plugin -install lukas-vlcek/bigdesk";
subprocess.call(string,shell=True);
string = HOME_DIR + "/elasticsearch-1.7.1/bin/plugin -install elasticsearch/marvel/latest";
subprocess.call(string,shell=True);

print "\n\nRun the ElasticSearch";
string = "nohup "+ HOME_DIR + "/elasticsearch-1.7.1/bin/elasticsearch &"
subprocess.call(string,shell=True);

print "\n\nRun the Webbrowser and check localhost:9200/_plugin/head";
print "\n\nDone";

subprocess.call("sleep 2",shell=True);
subprocess.call("clear",shell=True);
print "\n\nSetup LogStash-1.5.4\n";
subprocess.call("wget -P $HOME/elasticsearch https://download.elastic.co/logstash/logstash/logstash-1.5.4.tar.gz",shell=True);
string = "tar -xvf "+ HOME_DIR + "/logstash-1.5.4.tar.gz -C "+ HOME_DIR;
subprocess.call(string,shell=True);
print "\n\nDone";


subprocess.call("sleep 2",shell=True);
subprocess.call("clear",shell=True);
print "\n\nSetup Kibana4\n";
subprocess.call("wget -P $HOME/elasticsearch https://download.elastic.co/kibana/kibana/kibana-4.1.1-linux-x64.tar.gz",shell=True);
string = "tar -xvf "+ HOME_DIR + "/kibana-4.1.1-linux-x64.tar.gz -C "+ HOME_DIR;
subprocess.call(string,shell=True);
print "\n\nRun the Kibana";
string = "nohup "+ HOME_DIR + "/kibana-4.1.1-linux-x64/bin/kibana &"
subprocess.call(string,shell=True);

print "\n\nDone";





