#!/bin/sh
sudo ip link set wlp3s0 down
sudo iw dev wlp3s0 set type managed
sudo ip link set wlp3s0 up 
sudo nmcli dev set wlp3s0 managed yes 