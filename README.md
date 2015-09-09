# elasticsearch-logstash-kibana

#### How To Install Elasticsearch, Logstash, and Kibana 4 on Ubuntu 14.04

We will cover the installation of the Elasticsearch ELK Stack on Ubuntu 14.04 that is, Elasticsearch , Logstash , and Kibana 4. We will also show you how to configure it to gather and visualize the syslogs of your systems in a centralized location.

Our setup has four main components:
  
  1. Logstash: Logstash is an open source tool for collecting, parsing, and storing logs for future use
  2. Elasticsearch: Stores all of the logs
  3. Kibana: Kibana 4 is a web interface that can be used to search and view the logs that Logstash has indexed.
  4. Logstash Forwarder: Installed on servers that will send their logs to Logstash, Logstash Forwarder serves as a log forwarding agent that utilizes the lumberjack networking protocol to communicate with Logstash.
  

                    Kibana   <-   ElasticSearch    <-  Logstash    <-   Logstash Forwarder
                    
  
