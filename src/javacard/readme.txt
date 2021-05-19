tlsse.cap is a TLS1.3 server that echoes incoming commmands
It should work with mst of javacard 3.0.4 and more
To download the code in a javacard start load_tls_se_304.bat
The server name is: ethertrust
the openssl command line is :
openssl s_client -tls1_3 -connect 127.0.0.1:443 -servername ethertrust -groups P-256 -cipher DHE -ciphersuites TLS_AES_128_CCM_SHA256 -no_ticket -psk 0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20
