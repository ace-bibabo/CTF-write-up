# [wargame1 file](https://github.com/li-li-ge/ctf_writeups/blob/main/code/forensics_wargames/war1/file)

* Tried ***xxd*** ***strings*** ***exiftool*** ***binwalk*** but nothing found
* then I gave up and ate my lunch.
* then I go through the hexdump, I see ffd9? its mentioned in the tutorial which mentioned in tutorial which means its a jpeg file. let me change to file.jpg or file.jpeg.
* but still got format error by using exiftool

```
exiftool file.jpg 
ExifTool Version Number         : 12.60
File Name                       : file.jpg
Directory                       : .
File Size                       : 76 kB
File Modification Date/Time     : 2023:11:03 16:02:42+11:00
File Access Date/Time           : 2023:11:03 16:02:45+11:00
File Inode Change Date/Time     : 2023:11:03 16:02:42+11:00
File Permissions                : -rw-r--r--
Error                           : File format error
```

* then I try to know jpeg format header will look like ? googled get answer need ffd8 ffe1, 
* then I added it to the file by python

```
new_header = b'\xff\xd8\xff\xe1'

with open('file', 'rb') as original_file:
    original_data = original_file.read()

with open('file.jpg', 'wb') as new_file:
    new_file.write(new_header)
    new_file.write(original_data) 
```
> flag s
![](https://github.com/li-li-ge/ctf_writeups/blob/main/code/forensics_wargames/war1/file.jpg?raw=true)