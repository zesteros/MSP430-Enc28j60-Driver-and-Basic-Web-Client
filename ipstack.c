#include "ipstack.h"
#include "enc28j60.h"
#include <string.h>
// Switch to host order for the enc28j60
#define HTONS(x) ((x<<8)|(x>>8))

// MAC address of the enc28j60
const unsigned char deviceMAC[6] = {0x00,0xa0,0xc9,0x14,0xc8,0x00};
// Router MAC is not known at beginning and requires an ARP reply to know.
//Establecer mac del router (access point) a conectar //todo:automatizar esto.
unsigned char routerMAC[6] = {0xf4,0xdc,0xf9,0xb2,0x83,0xfe};
// IP address of the enc28j60
unsigned char deviceIP[4] = {192,168,3,100};
// IP address of the router
unsigned char routerIP[4] = {192,168,3,1};

unsigned char serverIP[4] = {192,168,3,11};

unsigned char dnsIP[4] = {8,8,8,8};

/*
 * negociación en tres pasos (SYN, SYN/ACK y ACK)
 *
 * */

int IPstackHTMLPost(const char* url, const char* data, char* reply)
{
  //First we need to do some DNS looking up
  //DNSLookup(url); //Fills in serverIP only if you don't know the IP
  //Now that we have the IP we can connect to the server
    /*Create a new packet*/
  unsigned char packet[MAXPACKETLEN];
/*Expand the memory assigned to packet according TCP Packet*/
  memset(packet,0,sizeof(TCPhdr));//zero the memory as we need all flags = 0

  //Syn server
  /*Setup the packet according tcp protocol*/
  SetupBasicIPPacket(packet, TCPPROTOCOL, serverIP);
  TCPhdr* tcp = (TCPhdr*)packet;
  /*Puerto de fuente */
  tcp->sourcePort = HTONS(0xe2d7);
  /*Puerto de destino 80*/
  tcp->destPort = HTONS(80);
  //Seq No and Ack No are zero
  tcp->seqNo[0] = 1;
  tcp->hdrLen = (sizeof(TCPhdr)-sizeof(IPhdr))/4;
  tcp->SYN = 1;
  tcp->wndSize = HTONS(200);
  //Add in some basic options
  unsigned char opts[] = { 0x02, 0x04,0x05,0xb4,0x01,0x01,0x04,0x02};
  //memcpy(&tcp->options[0],&opts[0],8);

  unsigned int len = sizeof(TCPhdr);

  tcp->ip.len = HTONS(sizeof(TCPhdr)-sizeof(EtherNetII));
  int pseudochksum = chksum(TCPPROTOCOL+len-sizeof(IPhdr), tcp->ip.source, 8);
  tcp->chksum = HTONS(~(chksum(pseudochksum,packet + sizeof(IPhdr), len-sizeof(IPhdr))));
  tcp->ip.chksum = HTONS(~(chksum(0, packet+sizeof(EtherNetII), sizeof(IPhdr)-sizeof(EtherNetII))));

  MACWrite(packet,len);

  /*Fin de etapa ACK*/

  //ack syn/ack
  /*Transmite los datos*/
  do{
      /*Obtiene los datos mientras el puerto de destino sea diferente al e2d7*/
    GetPacket(TCPPROTOCOL, packet);
  }while(!(tcp->destPort==HTONS(0xe2d7)));
  /*Responde*/
  ackTcp(tcp,len);
  MACWrite( packet, len );

  //Send the actual data
  /*Copia los datos al paquete TCP*/
  //first we need change to a push
  tcp->PSH = 1;
  tcp->ip.ident = 0xDEED;
  //Now copy in the data
  /*Copia los datos*/
  int datalen = strlen(data);
  memcpy( packet + sizeof(TCPhdr), data, datalen);
  /*Ahora la longitud es la longitud del paquete más la longitud de los datos*/
  len = sizeof(TCPhdr) + datalen;
  /*Modifica algunos encabezados*/
  tcp->ip.len = HTONS(len-sizeof(EtherNetII));
  tcp->chksum = 0;
  tcp->ip.chksum = 0;
  pseudochksum = chksum(TCPPROTOCOL+len-sizeof(IPhdr),tcp->ip.source,sizeof(deviceIP)*2);
  tcp->chksum = HTONS(~(chksum(pseudochksum, packet + sizeof(IPhdr),len-sizeof(IPhdr))));
  tcp->ip.chksum = HTONS(~(chksum(0, packet + sizeof(EtherNetII), sizeof(IPhdr)-sizeof(EtherNetII))));
  /*Manda el paquete*/
  MACWrite(packet, len);
  /*Lee las respuestas*/
  do{
    GetPacket(TCPPROTOCOL, packet);
  }while(!(tcp->destPort==HTONS(0xe2d7)));
  /*Copia la respuesta al paquete*/
  memcpy( reply, packet + len -7, 7);
  ackTcp(tcp, len);
  MACWrite( packet, len);

  /*Finaliza la transmisión*/
  tcp->PSH=0;
  tcp->FIN=1;
  tcp->ACK=1;
  tcp->chksum = 0;
  tcp->ip.chksum = 0;
  pseudochksum = chksum(TCPPROTOCOL+len-sizeof(IPhdr), tcp->ip.source, sizeof(deviceIP)*2);
  tcp->chksum = HTONS(~(chksum(pseudochksum,packet + sizeof(IPhdr), len-sizeof(IPhdr))));
  tcp->ip.chksum = HTONS(~(chksum(0, packet + sizeof(EtherNetII), sizeof(IPhdr)-sizeof(EtherNetII))));
  MACWrite(packet,len);
  memcpy(tcp, reply, sizeof(tcp));
  //Now we need to copy the payload to the reply buffer and ack the reply
  do{
       /*Obtiene los datos mientras el puerto de destino sea diferente al e2d7*/
     GetPacket(TCPPROTOCOL, packet);
   }while(!(tcp->destPort==HTONS(0xe2d7)));
   /*Responde*/
   ackTcp(tcp,len);
   MACWrite( packet, len );
  return 0;
}

void
add32(unsigned char *op32, unsigned int op16)
{
  op32[3] += (op16 & 0xff);
  op32[2] += (op16 >> 8);
  
  if(op32[2] < (op16 >> 8)) {
    ++op32[1];
    if(op32[1] == 0) {
      ++op32[0];
    }
  }
  
  
  if(op32[3] < (op16 & 0xff)) {
    ++op32[2];
    if(op32[2] == 0) {
      ++op32[1];
      if(op32[1] == 0) {
	++op32[0];
      }
    }
  }
}

static unsigned int
chksum(unsigned int sum, unsigned char *data, unsigned int len)
{
  unsigned int t;
  const unsigned char *dataptr;
  const unsigned char *last_byte;

  dataptr = data;
  last_byte = data + len - 1;
  
  while(dataptr < last_byte) {	/* At least two more bytes */
    t = (dataptr[0] << 8) + dataptr[1];
    sum += t;
    if(sum < t) {
      sum++;		/* carry */
    }
    dataptr += 2;
  }
  
  if(dataptr == last_byte) {
    t = (dataptr[0] << 8) + 0;
    sum += t;
    if(sum < t) {
      sum++;		/* carry */
    }
  }

  /* Return sum in host byte order. */
  return sum;
}
/*Crea un nuevo paquete IP*/
void SetupBasicIPPacket( unsigned char* packet, unsigned char protocol, unsigned char* destIP )
{
    /*Inicializa la estructura del paquete ip*/
  IPhdr* ip = (IPhdr*)packet;
  /*Define el tipo de IP*/
  ip->eth.type = HTONS(IPPACKET);
  /*Copia a la direccion de destino de la IP la mac del router*/
  memcpy( ip->eth.DestAddrs, routerMAC, sizeof(routerMAC) );
  /*Copia a la dirección del fuente la mac de este dispositivo*/
  memcpy( ip->eth.SrcAddrs, deviceMAC, sizeof(deviceMAC) );
  /*Establece la version del protocolo (v4)*/
  ip->version = 0x4;
  /*Establece la dimension de hdr (5)*/
  ip->hdrlen = 0x5;

  ip->diffsf = 0;
  ip->ident = 2; //Chosen at random roll of dice
  ip->flags = 0x2;
  ip->fragmentOffset1 = 0x0;
  ip->fragmentOffset2 = 0x0;
  /*Establece ttl en 128*/
  ip->ttl = 128;
  /*Establece en char el protocolo (desde parámetro)*/
  ip->protocol = protocol;
  ip->chksum = 0x0;
  /*Copia a la dirección de fuente la dirección ip de este dispositivo*/
  memcpy( ip->source , deviceIP, sizeof(deviceIP) );
  /*Copia a la dirección de destino la ip de destino proporcionada como parámetro*/
  memcpy( ip->dest, destIP, sizeof(deviceIP) );
}

void SendArpPacket(unsigned char* targetIP){
  ARP arpPacket;
  
  /*----Setup EtherNetII Header----*/
  //The source of the packet will be the device mac address.
  memcpy( arpPacket.eth.SrcAddrs, deviceMAC, sizeof(deviceMAC) );
  //The destination is broadcast ie all bits are 0xff.
  memset( arpPacket.eth.DestAddrs, 0xff, sizeof(deviceMAC) );
  //The type of packet being sent is an ARP
  arpPacket.eth.type = HTONS(ARPPACKET);
  
  /*----Setup ARP Header----*/
  arpPacket.hardware = HTONS(ETHERNET);
  //We are wanting IP address resolved.
  arpPacket.protocol = HTONS(IPPACKET);
  arpPacket.hardwareSize = sizeof(deviceMAC);
  arpPacket.protocolSize = sizeof(deviceIP);
  arpPacket.opCode = HTONS(ARPREQUEST);
  
  //Target MAC is set to 0 as it is unknown.
  memset( arpPacket.targetMAC, 0, sizeof(deviceMAC) );
  //Sender MAC is the device MAC address.
  memcpy( arpPacket.senderMAC, deviceMAC, sizeof(deviceMAC) );
  //The target IP is the IP address we want resolved.
  memcpy( arpPacket.targetIP, targetIP, sizeof(routerIP));
  
  //If we are just making sure this IP address is not in use fill in the 
  //sender IP address as 0. Otherwise use the device IP address.
  if ( !memcmp( targetIP, deviceIP, sizeof(deviceIP) ) )
  { 
    memset( arpPacket.senderIP, 0, sizeof(deviceIP) );
  }
  else
  {
    memcpy( arpPacket.senderIP, deviceIP, sizeof(deviceIP) );
  }
  
  //Send out the packet.
  MACWrite((unsigned char*)&arpPacket,sizeof(ARP));
}

void ReplyArpPacket(ARP* arpPacket)
{
  //To reply we want to make sure the IP address is for us first
  if( !memcmp( arpPacket->targetIP, deviceIP, sizeof(deviceIP) ) )
  {
    //The arp is for us so swap the src and dest addrs
    memcpy( arpPacket->eth.DestAddrs, arpPacket->eth.SrcAddrs, sizeof(deviceMAC) );
    memcpy( arpPacket->eth.SrcAddrs, deviceMAC, sizeof(deviceMAC) );
    //Swap the target and sender MACs
    memcpy( arpPacket->targetMAC, arpPacket->senderMAC, sizeof(deviceMAC) );
    memcpy( arpPacket->senderMAC, deviceMAC, sizeof(deviceMAC) );
    //Swap the target and sender IPs
    memcpy( arpPacket->targetIP, arpPacket->senderIP, sizeof(deviceIP) );
    memcpy( arpPacket->senderIP, deviceIP, sizeof(deviceIP));
    //Change the opCode to reply
    arpPacket->opCode = HTONS(ARPREPLY); 
    
    MACWrite((unsigned char*) arpPacket, sizeof(ARP));
  }
}

unsigned int ackTcp(TCPhdr* tcp, unsigned int len)
{
  //Zero the checksums
  tcp->chksum = 0x0;
  tcp->ip.chksum = 0x0;
  // First sort out the destination mac and source
  memcpy( tcp->ip.eth.DestAddrs, tcp->ip.eth.SrcAddrs, sizeof(deviceMAC) );
  memcpy( tcp->ip.eth.SrcAddrs, deviceMAC, sizeof(deviceMAC) );
  // Next flip the ips
  memcpy( tcp->ip.dest, tcp->ip.source, sizeof(deviceIP) );
  memcpy( tcp->ip.source, deviceIP, sizeof(deviceIP) );
  // Next flip ports
  unsigned int destPort = tcp->destPort;
  tcp->destPort = tcp->sourcePort;
  tcp->sourcePort = destPort;
  // Swap ack and seq
  char ack[4];
  memcpy( ack, tcp->ackNo, sizeof(ack) );
  memcpy( tcp->ackNo, tcp->seqNo, sizeof(ack) );
  memcpy( tcp->seqNo, ack, sizeof(ack) );
  
  if( tcp->SYN )
  {
    add32( tcp->ackNo, 1 );
  }
  else
  {
    add32( tcp->ackNo, len - sizeof(TCPhdr) );
  }
  tcp->SYN = 0;
  tcp->ACK = 1;
  tcp->hdrLen = (sizeof(TCPhdr)-sizeof(IPhdr))/4;
  len = sizeof(TCPhdr);
  tcp->ip.len = HTONS(len-sizeof(EtherNetII));
  
  int pseudochksum = chksum(TCPPROTOCOL+len-sizeof(IPhdr),
                            tcp->ip.source, sizeof(deviceIP)*2);
  tcp->chksum = HTONS(~(chksum(pseudochksum, 
                               ((unsigned char*)tcp) + sizeof(IPhdr),
                               len-sizeof(IPhdr))));
  
  tcp->ip.chksum = HTONS(~(chksum(0,((unsigned char*)tcp) + sizeof(EtherNetII),
                                  sizeof(IPhdr)-sizeof(EtherNetII))));
  return len;
}

void SendPing( unsigned char* targetIP )
{
  ICMPhdr ping;
  SetupBasicIPPacket( (unsigned char*)&ping, ICMPPROTOCOL, targetIP );
  
  ping.ip.flags = 0x0;
  ping.type = 0x8;
  ping.code = 0x0;
  ping.chksum = 0x0;
  ping.iden = HTONS(0x1);
  ping.seqNum = HTONS(76);

  ping.chksum = HTONS( ~( chksum(0, ((unsigned char*)&ping) + sizeof(IPhdr ),
                                    sizeof(ICMPhdr) - sizeof(IPhdr) ) ) );
  ping.ip.len = HTONS(60-sizeof(EtherNetII));
  ping.ip.chksum = HTONS( ~( chksum( 0, (unsigned char*)&ping + sizeof(EtherNetII),
                                  sizeof(IPhdr) - sizeof(EtherNetII))));
  
  MACWrite( (unsigned char*)&ping, sizeof(ICMPhdr) );  
}

void PingReply(ICMPhdr* ping, unsigned int len)
{
  if ( ping->type == ICMPREQUEST )
  {
    ping->type = ICMPREPLY;
    ping->chksum = 0x0;
    ping->ip.chksum = 0x0;
    //Swap the destination MAC address'
    memcpy( ping->ip.eth.DestAddrs, ping->ip.eth.SrcAddrs, sizeof(deviceMAC) );
    memcpy( ping->ip.eth.SrcAddrs, deviceMAC, sizeof(deviceMAC) );
    //Swap the destination IP address'
    memcpy( ping->ip.dest, ping->ip.source, sizeof(deviceIP) );
    memcpy( ping->ip.source, deviceIP, sizeof(deviceIP) );
    
    ping->chksum = HTONS( ~( chksum(0, ((unsigned char*) ping) + sizeof(IPhdr ),
                                    len - sizeof(IPhdr) ) ) );
    ping->ip.chksum = HTONS( ~( chksum(0, ((unsigned char*) ping) + sizeof(EtherNetII),
                                       sizeof(IPhdr) - sizeof(EtherNetII) ) ) );
    MACWrite((unsigned char*) ping, len);
  }
}
/*Método para obtener los paquetes donde se recibe un protocolo y un paquete*/
char GetPacket(int protocol, unsigned char* packet){
    unsigned char i = 0;
    /*son de 254 bits (8 bytes)*/
  for(i; i < 255; ++i){//Should make this return 0 after so many failed packets
      /*declara la longitud del paquete (0)*/
    unsigned int len;
    /*si la longitud corresponde a la longitud del paquete*/
    if ( len = MACRead( packet, MAXPACKETLEN ) )
    {
        /*Convierte el paquete en Ethernet*/
      EtherNetII* eth = (EtherNetII*)packet;

      /*Si es un paquete ARP*/
      if ( eth->type == HTONS(ARPPACKET) )
      {
          /*Convierte el paquete en paquete ARP*/
        ARP* arpPacket = (ARP*)packet;
        /*Si pide contestar contesta*/
        if ( arpPacket->opCode == HTONS(ARPREQUEST))
          //We have an arp and we should reply
          ReplyArpPacket(arpPacket);
      }
      /*Si el paquete es IP*/
      else if( eth->type == HTONS(IPPACKET) )
      {
        //We have an IP packet and we need to check protocol.
        IPhdr* ip = (IPhdr*)packet;
        /*Si el paquete es correcto regresa 1*/
        if( ip->protocol == protocol )
        {
          return 1;
        }
        /*Si el paquete es ICMP*/
        //Reply to any Pings
        if( ip->protocol == ICMPPROTOCOL )
        {
            /*Responde al ping*/
          PingReply((ICMPhdr*)packet, len);
        }
      }
    }
  }
  return 0;
}
  
int IPstackInit()
{
  initMAC( deviceMAC );
  // Announce we are here
  SendArpPacket( deviceIP );
  // Just waste a bit of time confirming no one has our IP
  unsigned int i = 0;
  for(i; i < 0x0fff; i++){
    ARP arpPacket;
    if( MACRead( (unsigned char*) &arpPacket, sizeof(ARP) ) )
    {
      if( arpPacket.eth.type == HTONS(ARPPACKET) )
      {
        if( !memcmp( arpPacket.senderIP, deviceIP, sizeof(deviceIP) ) )
        {
          // Uh oh this IP address is already in use
          return 0;
        }
      }
    }
  }
  // Well no one replied so its safe to assume IP address is OK
  // Now we need to get the routers MAC address
  SendArpPacket( routerIP );
  i = 0;
  for(i; i < 0x5fff; i++)
  {
    ARP arpPacket;
    if( MACRead( (unsigned char*) &arpPacket, sizeof(ARP) ) )
    {
      if( arpPacket.eth.type == HTONS(ARPPACKET) )
      {
        if( arpPacket.opCode == HTONS(ARPREPLY) && !memcmp( arpPacket.senderIP, routerIP, sizeof(routerIP) ) )
        {
          // Should be the routers reply so copy the mac address
          memcpy( routerMAC, arpPacket.senderMAC, sizeof(routerMAC) );
          return 1;
        }
      }
    }
    // Every now and then send out another ARP
    if( !(i % 0x1000) )
    {
      SendArpPacket( routerIP );
    }
  }
  return 0;
}


void DNSLookup( const char* url )
{
  unsigned char packet[MAXPACKETLEN];
  DNShdr* dns = (DNShdr*)packet;
  SetupBasicIPPacket(packet, UDPPROTOCOL, dnsIP);
  
  dns->udp.sourcePort = HTONS(0xDC6F);//Place a number in here
  dns->udp.destPort = HTONS(DNSUDPPORT);
  dns->udp.len = 0;
  dns->udp.chksum = 0;
  
  dns->id = HTONS(0xfae3); //Chosen at random roll of dice
  dns->flags = HTONS(0x0100);
  dns->qdCount = HTONS(1);
  dns->anCount = 0;
  dns->nsCount = 0;
  dns->arCount = 0;
  //Add in question header
  char* dnsq = (char*)(packet + sizeof(DNShdr) + 1);//Note the +1
  int noChars = 0;
  char * c = url;
  for(c; *c != '\0' && *c !='\\'; ++c, ++dnsq)
  {
    *dnsq = *c;
    if ( *c == '.' )
    {
      *(dnsq-(noChars+1)) = noChars;
      noChars = 0;
    }
    else ++noChars;
  }
  *(dnsq-(noChars+1)) = noChars;
  *dnsq++ = 0;
  //Next finish off the question with the host type and class
  *dnsq++ = 0;
  *dnsq++ = 1;
  *dnsq++ = 0;
  *dnsq++ = 1;
  //char lenOfQuery = (unsigned char*)dnsq-&uip_buf[sizeof(DNShdr)];
  unsigned int len = (unsigned char*)dnsq-packet;
  //Calculate all lengths
  dns->udp.len = HTONS(len-sizeof(IPhdr));
  dns->udp.ip.len = HTONS(len-sizeof(EtherNetII));
  //Calculate all checksums
  int pseudochksum = chksum(UDPPROTOCOL+len-sizeof(IPhdr),
                            dns->udp.ip.source, sizeof(deviceIP)*2);
  dns->udp.chksum = HTONS(~(chksum(pseudochksum,
                                   packet+sizeof(IPhdr),
                                   len-sizeof(IPhdr))));
  dns->udp.ip.chksum = HTONS(~(chksum(0,
                                      packet+sizeof(EtherNetII),
                                      sizeof(IPhdr)-sizeof(EtherNetII))));
  
  
  MACWrite(packet,len);
  while(1)
  {
    GetPacket(UDPPROTOCOL, packet);
    if( ((UDPhdr*)packet)->sourcePort == HTONS(DNSUDPPORT))
    {
      dns = (DNShdr*)packet;
      if ( dns->id == HTONS(0xfae3)) //See above for reason
      {
        //IP address is after original query so we should go to the end plus lenOfQuery
        //There are also 12 bytes of other data we do not need to know
        //Grab IP from message and copy into serverIP
        //The address should be the last 4 bytes of the buffer. This is not fool proof and
        //should be changed in the future
        memcpy( serverIP, packet+len-4, sizeof(serverIP));
        return;
      }
    }
  }
}


int IPstackIdle()
{
  unsigned char packet[MAXPACKETLEN];
  GetPacket(0,packet);
  return 1;
}
