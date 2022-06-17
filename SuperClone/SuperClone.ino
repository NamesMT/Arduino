/*
 * --------------------------------------------------------------------------------------------------------------------
 * SuperClone - One to Many full block 0 cloner script.
 * This script will clone whole block 0 (including BBC & Manufacturer info) from a Mifare card to changeable cards, use at your own risk!
 * --------------------------------------------------------------------------------------------------------------------
 * The script is using the MFRC522 library; for further details and other examples see: https://github.com/miguelbalboa/rfid
 *
 * @author NamesMT
 * @license DBAD - Dont Be a Dick - https://dbad-license.org/.
 *
 * Typical pin layout used:
 * -----------------------------------------------------------------------------------------
 *             MFRC522      Arduino       Arduino   Arduino    Arduino          Arduino
 *             Reader/PCD   Uno/101       Mega      Nano v3    Leonardo/Micro   Pro Micro
 * Signal      Pin          Pin           Pin       Pin        Pin              Pin
 * -----------------------------------------------------------------------------------------
 * RST/Reset   RST          9             5         D9         RESET/ICSP-5     RST
 * SPI SS      SDA(SS)      10            53        D10        10               10
 * SPI MOSI    MOSI         11 / ICSP-4   51        D11        ICSP-4           16
 * SPI MISO    MISO         12 / ICSP-1   50        D12        ICSP-1           14
 * SPI SCK     SCK          13 / ICSP-3   52        D13        ICSP-3           15
 *
 * More pin layouts for other boards can be found here: https://github.com/miguelbalboa/rfid#pin-layout
 *
 * There's also Red, Green and Blue led pins at 3, 5 and 6 respectively.
 */

#include <SPI.h>
#include <MFRC522.h>

#define RST_PIN 9 // Configurable, see typical pin layout above
#define SS_PIN 10 // Configurable, see typical pin layout above

#define LED_R 3 // Configurable, PWM
#define LED_G 5 // Configurable, PWM
#define LED_B 6 // Configurable, PWM

#define SIZEOFARR(array) (sizeof(array) / sizeof(array[0]))

MFRC522 mfrc522(SS_PIN, RST_PIN); // Create MFRC522 instance
MFRC522::MIFARE_Key key = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
MFRC522::StatusCode status;

byte originBuffer[18];
byte bufferByteCount = sizeof(originBuffer);
bool read = false;

void LED(int r, int g, int b)
{
  analogWrite(LED_R, r);
  analogWrite(LED_G, g);
  analogWrite(LED_B, b);
}

void setupLEDs()
{
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(LED_B, OUTPUT);
  LED(50, 0, 0);
}

void setup()
{
  setupLEDs();

  Serial.begin(115200); // Initialize serial communications with the PC
  while (!Serial)
    ;                 // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
  SPI.begin();        // Init SPI bus
  mfrc522.PCD_Init(); // Init MFRC522 card
  Serial.println(F("Warning: this script overwrites the full block 0 of your changable card, use with caution! (manufacturer data will be lost, your card could be bricked.)"));
}

bool readOrigin()
{
  if (!read)
  {
    LED(50, 10, 0);
    mfrc522.MIFARE_Read((byte)0, originBuffer, (&bufferByteCount));
    LED(60, 0, 40);
    mfrc522.PCD_StopCrypto1();
    delay(6000);

    LED(0, 0, 30);

    read = true;

    return false;
  }
  else
  {
    return true;
  }
}

void writeCard()
{
  Serial.println(F("wcs"));

  LED(50, 10, 0);

  // Dump UID
  Serial.print(F("Card UID:"));
  for (byte i = 0; i < mfrc522.uid.size; i++)
  {
    Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
    Serial.print(mfrc522.uid.uidByte[i], HEX);
  }
  Serial.println();

  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.print(F("PICC type: "));
  Serial.print(mfrc522.PICC_GetTypeName(piccType));
  Serial.print(F(" (SAK "));
  Serial.print(mfrc522.uid.sak);
  Serial.print(")\r\n");
  if (piccType != MFRC522::PICC_TYPE_MIFARE_MINI && piccType != MFRC522::PICC_TYPE_MIFARE_1K && piccType != MFRC522::PICC_TYPE_MIFARE_4K)
  {
    Serial.println(F("This sample only works with MIFARE Classic cards."));
    return;
  }

  delay(100);

  // // Overwrite new card with origin's block 0
  // if (mfrc522.MIFARE_SetBlock0(originBuffer, SIZEOFARR(originBuffer), true))
  // {
  //   Serial.println(F("Wrote new UID to card."));
  // }

  // Stop encrypted traffic so we can send raw bytes
  mfrc522.PCD_StopCrypto1();

  Serial.println(F("bab"));

  // Activate UID backdoor
  if (!mfrc522.MIFARE_OpenUidBackdoor(true))
  {
    Serial.println(F("Activating the UID backdoor failed."));
    return;
  }

  // Overwrite new card with origin's block 0
  status = mfrc522.MIFARE_Write((byte)0, originBuffer, (byte)16);
  if (status != MFRC522::STATUS_OK)
  {
    Serial.print(F("MIFARE_Write() failed: "));
    Serial.println(MFRC522::GetStatusCodeName(status));
    return;
  }

  // Wake the card up again
  byte atqa_answer[2];
  byte atqa_size = 2;
  mfrc522.PICC_WakeupA(atqa_answer, &atqa_size);

  // Halt PICC and re-select it so DumpToSerial doesn't get confused
  mfrc522.PICC_HaltA();
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial())
  {
    return;
  }

  // Dump the new memory contents
  Serial.println(F("New UID and contents:"));
  mfrc522.PICC_DumpToSerial(&(mfrc522.uid));

  LED(0, 20, 0);

  delay(8000);

  LED(0, 0, 30);
}

void loop()
{
  // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle. And if present, select one.
  if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial())
  {
    delay(100);
    return;
  }

  // Authenticate for reading
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, (byte)1, &key, &mfrc522.uid);

  if (status != MFRC522::STATUS_OK)
  {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(MFRC522::GetStatusCodeName(status));
    return;
  }

  if (readOrigin())
    writeCard();
}
