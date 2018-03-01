Enc28j60 driver for the msp430 modified from driver by Iain Derrington (www.kandi-electronics.com)

Implements a basic webclient that will send messages to a server. Will be able to read basic messages back.

Webclient part now working. 

.:Edit:. Webclient somewhat works. Note will often crash!

See http://mostlyprog.wordpress.com/2011/12/01/msp430-enc28j60-ethernet/ for progress.


Parts to do:

1. SPI link reading and writing.
2. ENC28J60 driver.
3. EthernetII Header.
4. IP Header.
5. TCP Header.
6. HTTP Header.

Parts complete:

1. Checked by simple reads and writes to enc28j60. See spi_test.c for example.
2. Checked by sending ARP and recieving reply. See arp_test.c for example.
3. Same as 2.
4. Checked by sending and recieving Ping. Proper Example to be added.
5. Checked by handshake with a server. Proper Example to be added.
6. Checked by downloading basic web page. Note currently will not download but most of the code is there.

Now that the basic client is working focus is on finishing TCP cleanly and general tidy up of the code base.

Edit: 25/02/2018 by Angelo Loza

The goal of the use of this work by Duncans Pumpkin is connect throught internet a board 
manufactured by scalini http://indscalini.com/
An academic board with a texas microcontroller MSP430F2274 and a Ethernet Shield ENC28J60

The communication is with SPI:
MSP430F2274 ----> ENC28J60-H
GND       GND
VCC       3.3V & RST

P2.0      CS 	- P2.0/ACLK/A0/OA0I0 	 	PIN 8 	IN MSP430F2274 BOARD
UCB0SOMI  MISO 	- P3.2/UCB0SOMI/UCB0SCL  	PIN 13 	IN MSP430F2274 BOARD
UCB0CLK   SCK 	- P3.3/UCB0CLK/UCA0STE  	PIN 14 	IN MSP430F2274 BOARD
USB0SIMO  MOSI 	- P3.1/UCB0SIMO/UCB0SDA 	PIN 12 	IN MSP430F2274 BOARD

If you're using Code Composer Studio v7 give some compilation errors, with
spi_test.c and arp_test.c the solution thar I found is move the files to another folder.
Disable register optimization in project properties.

The main objective is communicate two boards in local lan, sending http GET request and receive 
it in the second board to turn on a water pump when a cistern is empty. 

The code of Duncan below contains everything to do that, whatever, the part of
web client it's somewhat working and the purpose is leave it working 100%.

Edit: 28/02/2018 by Angelo Loza

Local LAN connection working alternately, success test and packets
recorded with Wireshark, corresponding files attached in doc folder. You'll need to
put in WS filter ip.address = 192.168.3.100 and you will see the
HTTP package (/s.php/s=XXX HTTP / 1.1) and a OK response, the errors
were documented in doc folder too, but in spanish, I will translate it later.

