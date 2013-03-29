SSLSnake
========

Python v3 based SSL cipher verification tool

SSL Snake is a simple tool that verifies the SSL ciphers supported by a given server. It relies on OpenSSL to obtain the list of ciphers supported by the local host, and using this list, attempts to negotiate a connection to the remote server.
<br><br>
SSL Snake supports the standard cipher filters supported by OpenSSL: HIGH, MEDIUM, LOW/EXP, eNULL, aNULL, and SSlv2. Combine the cipher suites as you see fit. It's still in beta, and hasn't been tested against nearly enough live targets, so any input or suggestions is very much appreciated.
<br><br>
SSL Snake v0.9

-?  this junk<br>
-h	host or ip<br>
-f	host file<br>
-p	port (default 443)<br>
-all	every supported cipher<br>
-high	high grade ciphers<br>
-med	medium grade ciphers<br>
-low	low grade ciphers<br>
-sslv2	sslv2 ciphers<br>
-anon	null authentication ciphers<br>
-clear	clear-text ciphers<br>
-v	verbose output (print cert details)<br><br>
Example:<br><br>
python sslSnake.py -h www.example.com -low -ssl2v -v<br>
<br>
Hit me up to complain: Shawn.Evans@knowledgecg.com
