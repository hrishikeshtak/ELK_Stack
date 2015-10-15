#!/usr/bin/env python
import sys
from configure_Graphite_configParser import Graphite

config_file="graphite.ini";

def main():
    graphite = Graphite();
    graphite.ESConfigParser(config_file);

main();
