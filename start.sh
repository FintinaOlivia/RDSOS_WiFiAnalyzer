#!/bin/sh

DIR="wifi_analyzer"

if [ ! -d "$DIR" ]; then
    ./init.sh
fi

source wifi_analyzer/bin/activate
cd src
sudo ../wifi_analyzer/bin/python3 startup.py