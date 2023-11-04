# [Matryoshka doll](https://play.picoctf.org/practice/challenge/129?category=4&page=1&search=)

use ***binwalk*** to get flag from matryoshka doll

```
 1012  binwalk dolls.jpg
 1013  binwalk -e  dolls.jpg
 1014  binwalk -e  _dolls.jpg
 1015  binwalk -e  _dolls.jpg.extracted/123.png
 1016  binwalk -e  _dolls.jpg.extracted/_123.png.extracted/base_images/3_c.jpg
```


```
cat  _dolls.jpg.extracted/_123.png.extracted/base_images/_3_c.jpg.extracted/base_images/_4_c.jpg.extracted/flag.txt
```
>picoCTF{4f11048e83ffc7d342a15bd2309b47de} 

![](https://github.com/ace-lii/ctf_writeups/blob/main/img/dolls.jpg?raw=true)