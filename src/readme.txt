For Ubuntu or Raspberry PI
- Install PCSC-LITE
- Create a directory keystore
- Under the directory keystore, create directories ./config and ./trace
- Copy the files config.txt, atr.txt, cardsn.txt, users.txt under ./config
- Copy the sources files under keystore
- To compile the sources execute the command:  
  gcc -o keystore -Wall -O2  ./main.c ./mutuex.c ./pcsc.c ./atr.c ./pcscemulator.c ./grid.c ./serverk.c  ./windowglue.c  -I/usr/include/PCSC -I.  -L/usr/lib -lpcsclite -lpthread
 - To run the keystore type ./keystore
