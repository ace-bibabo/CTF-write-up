# w2

## broken disk

* mount the disc img to os 

~~~
sudo mount -o loop,offset=0 disk.img /mnt/mydisk
mount: /mnt/mydisk: invalid file system.
~~~


* figure out the file format 

~~~
file disk.img
disk.img: data

exiftool disk.img
ExifTool Version Number         : 12.76
File Name                       : disk.img
Directory                       : .
File Size                       : 2.1 MB
File Modification Date/Time     : 2024:06:13 11:18:12+10:00
File Access Date/Time           : 2024:06:13 11:18:35+10:00
File Inode Change Date/Time     : 2024:06:13 11:18:36+10:00
File Permissions                : -rw-r--r--
Error                           : First 1025 bytes of file is binary zeros


binwalk -Me disk.img

Scan Time:     2024-06-13 11:21:12
Target File:   /Users/ace/Documents/cs/digital forensics/w2/broken_discs/disk.img
MD5 Checksum:  a1f0b8f4a3b37c9e4885d9dfab9c9080
Signatures:    411

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
12287         0x2FFF          LZMA compressed data, properties: 0x5B, dictionary size: 0 bytes, uncompressed size: 2036 bytes
40960         0xA000          PNG image, 674 x 322, 8-bit/color RGBA, non-interlaced
41017         0xA039          Zlib compressed data, default compression
139264        0x22000         JPEG image data, JFIF standard 1.01	
	
~~~

* extract the PNG/ZIP/JPEG inside

~~~
PNG 

from 
0000a000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.PNG........IHDR|
...
to
00011820  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

dd if=disk.img of=extracted.bin bs=16 skip=2560 count=45321
45321+0 records in
45321+0 records out
725136 bytes transferred in 0.087989 secs (8241212 bytes/sec)

binwalk extracted.bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 674 x 322, 8-bit/color RGBA, non-interlaced
57            0x39            Zlib compressed data, default compression
98304         0x18000         JPEG image data, JFIF standard 1.01

JPG
dd if=extracted.bin of=e.jpg bs=16 skip=6144 count=2048


~~~ 


* open the jpeg get the half flag try to align with the font format and guess what they are.













