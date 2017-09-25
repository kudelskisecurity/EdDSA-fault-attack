#include <Crypto.h>
#include <Curve25519.h>
#include <Ed25519.h>
#include <RNG.h>
#include <SHA512.h>

// Global Variables
// We can use a fix key.
uint8_t priv[32] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,22,23,24,25,26,27,28,29,30};
uint8_t pub[32];
uint8_t signa[64];
uint8_t message[32];
String mes = "test1";

void setup() {
  //Initialize serial and wait for port to open:
  Serial.begin(115200);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for native USB port only
  }

  // For random key
  //RNG.begin("EdDSA", 950);
  Serial.println("Ed25519 signatures");
  pinMode(2, OUTPUT);
  //Ed25519Y::generatePrivateKey(priv);   
  
  Serial.print("private key:\t");
  PrintHex(priv, 32,0);
  
  Ed25519::derivePublicKey(pub, priv);
  
  Serial.print("public key:\t");
  PrintHex(pub, 32,0);

  memset(message,0,32);
  mes.getBytes(message, 32);
}

void PrintHex(uint8_t *data, uint8_t len, uint8_t off) // prints 8-bit data in hex, see https://forum.arduino.cc/index.php?topic=38107.0
{
 uint8_t length = len - off;
 char tmp[length*2+1];
 byte first ;
 int j=0;
 for (uint8_t i=off; i<off+length; i++)
 {
   first = (data[i] >> 4) | 48;
   if (first > 57) tmp[j] = first + (byte)39;
   else tmp[j] = first ;
   j++;

   first = (data[i] & 0x0F) | 48;
   if (first > 57) tmp[j] = first + (byte)39;
   else tmp[j] = first;
   j++;
 }
 tmp[length*2] = 0;
 Serial.println(tmp);
}

void loop() {
  if (Serial.read() == 's')
  {
    // No interruptuion during processing time.
    noInterrupts();
    Ed25519::sign(signa, priv, pub, message, 32);
    // Allow interruptions.
    interrupts();
    Serial.println("r:");
    PrintHex(signa, 32,0);
    Serial.println("s:");
    PrintHex(signa, 64,32);
  }
}
