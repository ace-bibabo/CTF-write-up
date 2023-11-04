# [wargame2 image](https://github.com/li-li-ge/ctf_writeups/blob/main/code/forensics_wargames/war2/image.jpg?raw=true)

* when encountering an image, first try to get some info from from metadata, so tried ***xxd*** ***strings***  ***exiftool*** first

```
% xxd image.jpg | grep COMP

% exiftool image.jpg 
ExifTool Version Number         : 12.60
File Name                       : image.jpg
Directory                       : .
File Size                       : 201 kB
File Modification Date/Time     : 2021:03:15 20:14:12+11:00
File Access Date/Time           : 2023:11:03 13:20:43+11:00
File Inode Change Date/Time     : 2023:11:02 22:24:49+11:00
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Big-endian (Motorola, MM)
User Comment                    : password: YmFzZTY0X2lzX25vdF9lbmNyeXB0aW9u
Current IPTC Digest             : b60a13f43b882cb064d31df57e1781bd
Coded Character Set             : UTF8
........
```

* then try to decode this password with ***Cyberchef***， before that I asked chatgpt what this encode is it gives me clue its base64 and got decryped password: base64-is-not-encryption

>base64: "It uses 64 characters (A-Z, a-z, 0-9, and "+" and "/"), typically with "=" as the padding character."

 
* try to type it into the flag but not correct. 
then I tried Google is there anything/tools used with image forensics? got an answer from ***binwalk***, and found a flag embedded in this image file!

```
% binwalk image.jpg    
          
DECIMAL       HEXADECIMAL     DESCRIPTION

0             0x0             JPEG image data, EXIF standard
12            0xC             TIFF image data, big-endian, offset of first image directory: 8
3111          0xC27           Copyright string: "Copyright (c) 1998 Hewlett-Packard Company"
200496        0x30F30         Zip archive data, encrypted at least v2.0 to extract, compressed size: 57, uncompressed size: 47, name: flag.txt
200713        0x31009         End of Zip archive, footer length: 22
```
```

% binwalk -e  image.jpg               
DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             JPEG image data, EXIF standard
12            0xC             TIFF image data, big-endian, offset of first image directory: 8
3111          0xC27           Copyright string: "Copyright (c) 1998 Hewlett-Packard Company"
200496        0x30F30         Zip archive data, encrypted at least v2.0 to extract, compressed size: 57, uncompressed size: 47, name: flag.txt
200713        0x31009         End of Zip archive, footer length: 22
```
```
% unzip _image.jpg.extracted/30F30.zip 
Archive:  _image.jpg.extracted/30F30.zip
[_image.jpg.extracted/30F30.zip] flag.txt password: 
  inflating: flag.txt 
```
>COMP6841{BUT_BUT_WINDOWS_SAID_IT_WAS_AN_IMAGE}

 


