#!/bin/sh

DIR="wifi_analyzer"

if [ ! -d "$DIR" ]; then
    ./init.sh
fi

source wifi_analyzer/bin/activate
cd src
python3 startup.py