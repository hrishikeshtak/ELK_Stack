# elasticsearch-logstash-kibana

#### Install Elasticsearch, Logstash, and Kibana 4 on Ubuntu 14.04

We will cover the installation of the Elasticsearch ELK Stack on Ubuntu 14.04 that is, Elasticsearch , Logstash , and Kibana 4. We will also show you how to configure it to gather and visualize the syslogs of your systems in a centralized location.

Our setup has four main components:
  
  1. Logstash: Logstash is an open source tool for collecting, parsing, and storing logs for future use
  2. Elasticsearch: Stores all of the logs
  3. Kibana: Kibana 4 is a web interface that can be used to search and view the logs that Logstash has indexed.
  4. Logstash Forwarder: Installed on servers that will send their logs to Logstash, Logstash Forwarder serves as a log forwarding agent that utilizes the lumberjack networking protocol to communicate with Logstash.
  

                    Kibana   <-   ElasticSearch    <-  Logstash    <-   Logstash Forwarder
                    
  
We will install Elasticsearch , Logstash and kibana on a single server called "ELK Server" and The Logstash Forwarder will be installed on all of the client called "Client Servers: that we want to gather logs from.

1.  Install Java 8 : 

      Elasticsearch and Logstash require Java .
      "install_JAVA()" function , from script 
      "setup-elasticsearch-logstash-kibana4-as-a-service_ubuntu.sh" install Oracle Java 8 .
      
2.  Install Elasticsearch :

      Run the following command to import the Elasticsearch public GPG key into apt:
      
        $ wget -O - http://packages.elasticsearch.org/GPG-KEY-elasticsearch | sudo apt-key add -
        
      Create the Elasticsearch source list:
      
        $ echo 'deb http://packages.elasticsearch.org/elasticsearch/1.4/debian stable main' | sudo tee /etc/apt/sources.list.d/elasticsearch.list 
        
        "install_Elasticsearch()" , function from script 
        "setup-elasticsearch-logstash-kibana4-as-a-service_ubuntu.sh" install Elasticsearch
        
        The configuration file for elasticsearch is /etc/elasticsearch/elasticsearch.yml , 
        where we specify our configurations like cluster.name , network.host . 

3.  Install Kibana : 

      "install_Kibana()" function , from script 
      "setup-elasticsearch-logstash-kibana4-as-a-service_ubuntu.sh" install kibana .
      
      The kibana configuration file : /opt/kibana/config/kibana.yml , where we specify host ip , 
      on which our kibana server will run.
      
4.  Install Logstash : 

    Generate SSL Certificates :
      
      Since we are going to use Logstash Forwarder to ship logs from our client servers to our 
      ELK Server, we need to create an SSL certificate and key pair. The certificate 
      is used by the Logstash Forwarder to verify the identity of ELK Server.
      
      we have to add IP address of our ELK server in /etc/ssl/openssl.cnf
      under [ v3_ca ] section in the file.

    "install_Logstash()" function , from script 
    "setup-elasticsearch-logstash-kibana4-as-a-service_ubuntu.sh" 
    install Logstash and create SSL Certificates .
    
5.  Configure Logstash : 

      Logstash configuration files are in the JSON-format, and reside in /etc/logstash/conf.d. 
      The configuration consists of three sections: inputs, filters, and outputs.
      
      "configure_Logstash()"  function , from script 
      "setup-elasticsearch-logstash-kibana4-as-a-service_ubuntu.sh" 
      configure logstash.
      
6.  Set Up Logstash Forwarder (Add Client Servers) :

      Copy SSL Certificate and Logstash Forwarder Package : 
      
      On ELK Server, copy the SSL certificate to Client Server (substitute the client server's 
      address, and username).
      
        $ scp /etc/pki/tls/certs/logstash-forwarder.crt user@client_server_private_address:/tmp
        
        Now copy the ELK server's SSL certificate into the /etc/pki/tls/certs :
        
        $ sudo cp /tmp/logstash-forwarder.crt /etc/pki/tls/certs/
        
        "install_Logstash_Forwarder()"  function , from script
        "setup-elasticsearch-logstash-kibana4-as-a-service_ubuntu.sh" 
        install logstash_forwarder.
        
7.  Connect to Kibana : 
  
        In a web browser, go to the IP address of your ELK Server .
      
