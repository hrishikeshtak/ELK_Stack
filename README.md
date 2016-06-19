# elasticsearch-logstash-kibana

#### Install Elasticsearch, Logstash, and Kibana

Our setup has four main components:
  
  1. Logstash: Logstash is an open source tool for collecting, parsing, and storing logs for future use
  2. Elasticsearch: Stores all of the logs
  3. Kibana: Kibana is a web interface that can be used to search and view the logs that Logstash has indexed.
  4. Filebeat: Installed on servers that will send their logs to Logstash, Filebeat serves as a log forwarding agent that utilizes the lumberjack networking protocol to communicate with Logstash.
  

                    Kibana   <-   ElasticSearch    <-  Logstash    <-   Filebeat
                    
  
We will install Elasticsearch , Logstash and kibana on a single server called "ELK Server" and The Filebeat will be installed on all of the client called "Client Servers: that we want to gather logs from.

    Installation Directory :
    
    1. Logstash is installed in /opt/logstash/
    2. Logstash configuration files are located in /etc/logstash/conf.d
    3. Elasticsearch is installed in /usr/share/elasticsearch
    4. Elasticsearch configuration files are located in /etc/elasticsearch
    5. Kibana is installed in /opt/kibana/
    6. kibana configuration files are located in /opt/kibana/config
    
