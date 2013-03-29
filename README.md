SSLSnake
========

Python v3 based SSL cipher verification tool

SSL Snake v0.9

-?  this junk
-h	host or ip
-f	host file
-p	port (default 443)
-all	every supported cipher
-high	high grade ciphers
-med	medium grade ciphers
-low	low grade ciphers
-sslv2	sslv2 ciphers
-anon	null authentication ciphers
-clear	clear-text ciphers
-v	verbose output (print cert details)

Example:
python sslSnake.py -h www.example.com -low -ssl2 -v

Hit me up to complain: Shawn.Evans@knowledgecg.com
