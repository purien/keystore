Keystore reused the RACS concept (and code) adressing grid of secure elements

For Ubuntu or Raspberry PI
- Install PCSC-LITE
  sudo apt-get update
  sudo apt-get install libpcsclite1 pcscd
  sudo apt-get install libpcsclite-dev libusb-dev
  sudo apt-get install pcsc-tools

- Create a directory keystore

- Under the directory keystore, create directories ./config and ./trace

- Copy the files config.txt, atr.txt, cardsn.txt, users.txt under ./config
  atr.txt is not used (relation between ATR and Javacard-AID) because AID is default application
  cardsn.txt is the relation between CardSN (i.e. ATR historical bytes) and SEID (CardSN->SEID)
  users.txt  is the relation between TLS ServerName (UserID= TLS-SN) and SEID (SN->SEID)
  Multiple TLS Server Name can be assoiated a SEID

- Copy the sources files under keystore

- To compile the sources execute the command:  
  gcc -o keystore -Wall -O2  ./main.c ./mutuex.c ./pcsc.c ./atr.c ./pcscemulator.c ./grid.c ./serverk.c  ./windowglue.c  -I/usr/include/PCSC -I.  -L/usr/lib -lpcsclite -lpthread

- To run the keystore type ./keystore or ./keystore ./config
