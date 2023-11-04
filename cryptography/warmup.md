# warmup
>Base64 is a group of tetrasexagesimal binary-to-text encoding schemes that represent binary data (more specifically, a sequence of 8-bit bytes) in sequences of 24 bits that can be represented by four 6-bit Base64 digits.


```
text = "NDM0ZjRkNTA3YjQ5NWY2ODRmNzA0NTVmNzkzMDc1NWY0MTUyMzM1Zjc3NjE3MjZkNjU2NDVmMzI1ZjY2Njk2ZTY0NWY2ZDMwNzI0NTVmNDYzMTYxNjc3MzIxN2Q="
```

* First encountered the text, noticed the presence of the '=' character. I searched using the keyword '= end encode,' and the search results indicated that it might be Base64 encoding. by using ***base64 -d*** to decode it

```
echo 'NDM0ZjRkNTA3YjQ5NWY2ODRmNzA0NTVmNzkzMDc1NWY0MTUyMzM1Zjc3NjE3MjZkNjU2NDVmMzI1ZjY2Njk2ZTY0NWY2ZDMwNzI0NTVmNDYzMTYxNjc3MzIxN2Q=' | base64 -d
434f4d507b495f684f70455f7930755f4152335f7761726d65645f325f66696e645f6d3072455f4631616773217d
```

* Then, there's another encoded text, which appears to be a different encoding. Is it some form of hash? Its length is 93, which is quite unusual. I attempted to use ***hashcat*** to determine the type of hash, it says No hash-mode matches the structure of the input hash.

* Attempted to ask ChatGPT for help in decoding this text. ChatGPT provided a clue that it's in ***ASCII code***, but the initial attempt at decoding it yielded an incorrect answer. I then used Python to decode it. OMG should realize that the flag must contain "COMP," which corresponds to ASCII "COMP" (43 4F 4D 50).

	```
import binascii
ascii_text = "434F4D507B495F684F70455F7930755F4152335F7761726D65645F325F66696E645F6D3072455F4631616773217D"
hex_data = ascii_text.encode("utf-8")
decoded_text = binascii.unhexlify(hex_data).decode("utf-8")
print(decoded_text)
	```
* another way can use [cyberchef](https://gchq.github.io/CyberChef/) much easier. 

>COMP{I_hOpE_y0u_AR3_warmed_2_find_m0rE_F1ags!} 

