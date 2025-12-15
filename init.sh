#!/bin/sh

python3 -m venv wifi_analyzer
source wifi_analyzer/bin/activate
pip install -r requirements.txt
pip install --upgrade pip

cd src/scripts
chmod 755 monitor_mode.sh
chmod 755 managed_mode.sh