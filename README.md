# RDSOS WiFiAnalyzer

The requirements for this app include two parts: network scanning and package sniffing.

1. WiFi Analyzer

Each network has to be identified through a graphical icon in the interface, its colour (red, yellow, green) reflecting the strength of the given network's signal.

The information made available about the detected wireless networks should be:
- SSID
- Access Point
- MAC address
- Manufacturer
- Channel
- Security characteristics

The user must not be connected to WiFi at the time of running the app.

2. Sniffer

Similar to TCPdump, the sniffer should capture packages on the wireless interface and display data about them:

- IEEE 802.11 headers (source and destinaation MAC addresses)
- IP headers (source and destination IPs)
- TCP headers (source and destiation TCP ports)
- for HTTP packages (destination port is 80), the ASCII payload will be displayed.

The sniffer must work in both the "Monitor" and "Managed" modes.