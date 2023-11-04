# [wargame3 jaws.pcapng](https://github.com/li-li-ge/ctf_writeups/blob/main/code/forensics_wargames/war3_networks/jaws.pcapng)

* its a pcapng so try to open it by ***wireshark*** jaws.pcapng (need to install Wireshark first)
go through all the records , and you can use filter by http.accept got ur first flag

![](https://github.com/ace-lii/ctf_writeups/blob/main/img/jaw.png?raw=true)

> COMP6841{IS_HTTPS_REALLY_NECCESSARY?}



* then get all the suspicious objects from HTTP by export and save from file,I got tomcat.png, then tried strings/ xxd/ exiftool and got nothing, then tried binwalk

* still working on the other flag