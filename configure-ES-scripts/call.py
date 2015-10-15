#!/usr/bin/env python
import sys
from configure_ELK_configParser import Elasticsearch

config_file="elasticsearch.ini";

def main():
    elasticsearch = Elasticsearch();
    elasticsearch.ESConfigParser(config_file);

main();
