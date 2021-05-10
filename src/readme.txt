For Ubuntu or Raspberry PI
- Install PCSC-LITE
  sudo apt-get update
  sudo apt-get install libpcsclite1 pcscd
  sudo apt-get install libpcsclite-dev libusb-dev
  sudo apt-get install  pcsc-tools

- Create a directory keystore

- Under the directory keystore, create directories ./config and ./trace

- Copy the files config.txt, atr.txt, cardsn.txt, users.txt under ./config

- Copy the sources files under keystore

- To compile the sources execute the command:  
  gcc -o keystore -Wall -O2  ./main.c ./mutuex.c ./pcsc.c ./atr.c ./pcscemulator.c ./grid.c ./serverk.c  ./windowglue.c  -I/usr/include/PCSC -I.  -L/usr/lib -lpcsclite -lpthread

- To run the keystore type ./keystore
