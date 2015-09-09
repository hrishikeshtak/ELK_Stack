# elasticsearch-logstash-kibana

#### Install Elasticsearch, Logstash, and Kibana 4 on Ubuntu 14.04

We will cover the installation of the Elasticsearch ELK Stack on Ubuntu 14.04 that is, Elasticsearch , Logstash , and Kibana 4. We will also show you how to configure it to gather and visualize the syslogs of your systems in a centralized location.

Our setup has four main components:
  
  1. Logstash: Logstash is an open source tool for collecting, parsing, and storing logs for future use
  2. Elasticsearch: Stores all of the logs
  3. Kibana: Kibana 4 is a web interface that can be used to search and view the logs that Logstash has indexed.
  4. Logstash Forwarder: Installed on servers that will send their logs to Logstash, Logstash Forwarder serves as a log forwarding agent that utilizes the lumberjack networking protocol to communicate with Logstash.
  

                    Kibana   <-   ElasticSearch    <-  Logstash    <-   Logstash Forwarder
                    
  
We will install Elasticsearch , Logstash and kibana on a single server and The Logstash Forwarder will be installed on all of the client servers that we want to gather logs from.

1.  Install Java 8 : 
      Elasticsearch and Logstash require Java .
      install_JAVA() function from script "setup-elasticsearch-logstash-kibana4-as-a-service.sh" install Oracle Java 8 .
      
2.  Install Elasticsearch :

      Run the following command to import the Elasticsearch public GPG key into apt:
      
        $ wget -O - http://packages.elasticsearch.org/GPG-KEY-elasticsearch | sudo apt-key add -
        
      Create the Elasticsearch source list:
      
        $ echo 'deb http://packages.elasticsearch.org/elasticsearch/1.4/debian stable main' | sudo tee /etc/apt/sources.list.d/elasticsearch.list 
        
        "install_Elasticsearch()" function from script "setup-elasticsearch-logstash-kibana4-as-a-service.sh"
        install Elasticsearch
        
        The configuration file for elasticsearch is /etc/elasticsearch/elasticsearch.yml , 
        where we specify our configurations like cluster.name , network.host . 

3.  Install Kibana : 

      install_Kibana() function from script "setup-elasticsearch-logstash-kibana4-as-a-service.sh" 
      install kibana
      
