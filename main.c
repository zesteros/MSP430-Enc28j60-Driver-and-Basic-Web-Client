#include <msp430.h>
#include "ipstack.h"

const char* url = "192.168.3.150";
const char* data = "GET /sensortest.php/?sensor=000000 HTTP/1.1\r\nHost: 192.168.3.150\r\n\r\n";
char reply[] = "SUCCESS";

int main(void){
  // Stop watchdog timer to prevent time out reset
  WDTCTL = WDTPW + WDTHOLD;
  IPstackInit();
 // unsigned char target[] = {192,168,3,1};
  //SendPing(target);
  IPstackHTMLPost(url, data, reply );
  while(1){
      IPstackIdle();
  }
}
