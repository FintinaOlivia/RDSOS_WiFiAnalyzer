#!/bin/sh
sudo nmcli dev set wlp3s0 managed no     
sudo ip link set wlp3s0 down
sudo iw dev wlp3s0 set type monitor
sudo ip link set wlp3s0 up 