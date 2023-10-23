#include <api.h>
#include <bendian.h>
#include <core.h>
#include <permutations.h>

#include <WiFi.h>
#include <HTTPClient.h>
#include <Arduino.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <Crypto.h>
#include <Curve25519.h>
#include <RNG.h>
#include <Arduino_JSON.h>
#include "DHT.h"

#define RELAY_PIN 23
#define PINK_OUT_SENSOR 26 // cam bien hong ngoai
#define LIGHT_SENSOR 13
#define DHT_PIN 15
#define FAN 5
#define LED_1 19
#define LED_2 22
#define DHTTYPE DHT11 // there are multiple kinds of DHT sensors
DHT dht(DHT_PIN, DHTTYPE);

#define HUMIDITY A0 // analog/ do am

// #define LIGHT_MIN 200           // ngưỡng ánh sáng coi là tối để bật đèn, tùy chỉnh theo nhu cầu
// #define LIGHT_ON_DURATION 15000 // 15s, thời gian tắt đèn sau khi không còn chuyển động

// Khai báo tần suất cập nhật dữ liệu đất là 10 phút 1 lần
// const int UPDATE_INTERVAL = 600000; // 10p * 60s * 1000ms;
// unsigned long lastSentToServer = 0;
// Khai báo thời gian bật relay tưới nước
// const int WATER_INTERVAL = 60000; // thời gian tưới là 60s
// boolean relayStatus = false;         // lưu trạng thái bật tắt cảu relay

int lightStatus = 0;
// boolean relayStatus = false;
boolean alarmMode = false;
boolean socketState = 0;

unsigned long lastMotionDetected = 0; // lưu thời gian lần cuối phát hiện chuyển động

// endpoint
#define END_POINT "http://192.168.1.100:9494"

// khai bao do dai
#define MAX_MESSAGE_LEN 100 // Maximum message length
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16
#define KEY_LENGTH_32 32

// Khai báo biến cho khóa Diffie-Hellman và khóa chia sẻ bí mật
uint8_t privateKey[KEY_LENGTH_32];   // Khóa bí mật của bạn
uint8_t publicKey[KEY_LENGTH_32];    // Khóa công khai của bạn
uint8_t sharedSecret[KEY_LENGTH_32]; // Khóa chia sẻ bí mật sau khi tính
uint8_t partnerPublicKey[KEY_LENGTH_32];

// tam thoi chua dung nonce
const unsigned char nonce[CRYPTO_NPUBBYTES] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// decrypt
int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                        unsigned char *nsec, const unsigned char *c,
                        unsigned long long clen, const unsigned char *ad,
                        unsigned long long adlen, const unsigned char *npub,
                        const unsigned char *k)
{
  if (clen < CRYPTO_ABYTES)
  {
    *mlen = 0;
    return -1;
  }

  state s;
  u32_4 tmp;
  (void)nsec;

  // set plaintext size
  *mlen = clen - CRYPTO_ABYTES;

  ascon_core(&s, m, c, *mlen, ad, adlen, npub, k, ASCON_DEC);

  tmp.words[0].h = ((u32 *)(c + *mlen))[0];
  tmp.words[0].l = ((u32 *)(c + *mlen))[1];
  tmp.words[1].h = ((u32 *)(c + *mlen))[2];
  tmp.words[1].l = ((u32 *)(c + *mlen))[3];
  tmp = ascon_rev8(tmp);
  u32_2 t0 = tmp.words[0];
  u32_2 t1 = tmp.words[1];

  // verify tag (should be constant time, check compiler output)
  if (((s.x3.h ^ t0.h) | (s.x3.l ^ t0.l) | (s.x4.h ^ t1.h) | (s.x4.l ^ t1.l)) != 0)
  {
    *mlen = 0;
    return -1;
  }

  return 0;
}

int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *nsec, const unsigned char *npub,
                        const unsigned char *k)
{
  state s;
  u32_4 tmp;
  (void)nsec;

  // set ciphertext size
  *clen = mlen + CRYPTO_ABYTES;

  ascon_core(&s, c, m, mlen, ad, adlen, npub, k, ASCON_ENC);

  tmp.words[0] = s.x3;
  tmp.words[1] = s.x4;
  tmp = ascon_rev8(tmp);

  // set tag
  ((u32 *)(c + mlen))[0] = tmp.words[0].h;
  ((u32 *)(c + mlen))[1] = tmp.words[0].l;
  ((u32 *)(c + mlen))[2] = tmp.words[1].h;
  ((u32 *)(c + mlen))[3] = tmp.words[1].l;

  return 0;
}

const char *ssid = "DuyManhKMA";
const char *password = "your_PASSWORD";

// hexStringToByteArray
void hexStringToByteArray(const char *hexString, uint8_t *byteArray, size_t byteLength)
{
  int hexStringLength = strlen(hexString);

  // Đảm bảo rằng độ dài của chuỗi hex là số chẵn
  if (hexStringLength % 2 != 0)
  {
    // Nếu độ dài không chẵn, bạn có thể xử lý lỗi hoặc điều chỉnh độ dài
    // ví dụ: thêm '0' ở đầu chuỗi để làm cho độ dài chẵn
  }

  // Tính toán độ dài của mảng uint8_t
  int byteArraySize = hexStringLength / 2;

  // Khai báo mảng uint8_t để lưu trữ dữ liệu đã chuyển đổi

  // Lặp qua chuỗi hex và chuyển đổi thành mảng uint8_t
  for (int i = 0; i < hexStringLength; i += 2)
  {
    char hexPair[3] = {hexString[i], hexString[i + 1], '\0'};
    byteArray[i / 2] = strtol(hexPair, nullptr, 16);
  }
}

// Khoi tao trao doi khoa
void initDiffihelman()
{
  String hexPublicKey = "";
  String partnerPublicKeyStr = "";

  // Tạo cặp khóa Diffie-Hellman
  Curve25519::dh1(publicKey, privateKey);
  String hexstring = "";
  // doi public tu arr sang string gui len server
  for (int i = 0; i < KEY_LENGTH_32; i++)
  {
    if (publicKey[i] < 0x10)
    {
      hexstring += '0';
    }

    hexstring += String(publicKey[i], HEX);
  }
  Serial.println("public key string:");
  Serial.println(hexstring);
  Serial.println("**********************");

  HTTPClient http;
  // Địa chỉ của server và endpoint

  // Print the hexadecimal string
  String serverAddress = END_POINT;
  String endpoint = "/api/asconv12/diffie-hellman";
  String jsonBody = "{\"publicKey\":\"" + hexstring + "\"}";
  http.begin(serverAddress + endpoint);
  http.addHeader("Content-Type", "application/json");

  // Gửi POST request
  int httpResponseCode = http.POST(jsonBody);

  if (httpResponseCode > 0)
  {
    partnerPublicKeyStr = http.getString();
    Serial.println(httpResponseCode);
    Serial.println(partnerPublicKeyStr);
  }
  else
  {
    Serial.print("Error on sending POST request: ");
    Serial.println(httpResponseCode);
  }
  // doi gia tri hex string public key tu server sang byte de tinh toan shared key
  const char *hexString = partnerPublicKeyStr.c_str();
  Serial.println("Server publickey");
  Serial.println(hexString);
  hexStringToByteArray(hexString, partnerPublicKey, sizeof(partnerPublicKey));
  Serial.println("Diffie-Hellman ShpartnerPublicKeyared Secret:");
  for (int i = 0; i < KEY_LENGTH_32; i++)
  {
    Serial.print(partnerPublicKey[i], HEX);
    Serial.print(" ");
  }

  // se chuyen doi tu parnerkey -> shared
  if (!Curve25519::dh2(partnerPublicKey, privateKey))
  {
    Serial.println("Error!!!!");
    http.end();
    return;
  }

  http.end();
  Serial.println("Diffie-Hellman Shared Secret:");
  for (int i = 0; i < KEY_LENGTH_32; i++)
  {
    Serial.print(partnerPublicKey[i], HEX);
    Serial.print(" ");
  }
  Serial.println();
}

void setup()
{
  Serial.begin(115200);
  delay(1000);

  pinMode(RELAY_PIN, OUTPUT);
  pinMode(PINK_OUT_SENSOR, INPUT);
  pinMode(LIGHT_SENSOR, INPUT);
  pinMode(FAN, OUTPUT);
  pinMode(LED_1, OUTPUT);
  pinMode(LED_2, OUTPUT);
  digitalWrite(FAN, HIGH);
  digitalWrite(LED_1, HIGH);
  digitalWrite(LED_2, HIGH);
  digitalWrite(RELAY_PIN, LOW);

  WiFi.begin(ssid);
  while (WiFi.status() != WL_CONNECTED)
  {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }
  Serial.println("Connected to WiFi");
}

// sendPost resquet cipher text len server
String sendPostRequest(String hexCiphertext, unsigned long long ciphertext_len, unsigned long long mess_len)
{
  Serial.println("Start to post to server");
  HTTPClient http;
  // Địa chỉ của server và endpoint
  String serverAddress = END_POINT;
  String endpoint = "/api/asconv12";

  String jsonBody = "{\n  \"ciphertext\":\"" + hexCiphertext + "\",\n  \"cipherTextLength\":" + ciphertext_len + ",\n  \"messageLength\":" + mess_len + "\n}";

  http.begin(serverAddress + endpoint);
  http.addHeader("Content-Type", "application/json");

  // Gửi POST request
  int httpResponseCode = http.POST(jsonBody);
  String response = "";
  if (httpResponseCode > 0)
  {
    response = http.getString();
    Serial.println(httpResponseCode);
    Serial.println(response);
  }
  else
  {
    Serial.print("Error on sending POST request: ");
    Serial.println(httpResponseCode);
  }

  http.end();
  return response;
}

void loop()
{

  float h = dht.readHumidity();
  // Read temperature as Celsius (the default)
  float t = dht.readTemperature();
  // Read temperature as Fahrenheit (isFahrenheit = true)
  float f = dht.readTemperature(true);
  // Check if any reads failed and exit early (to try again).
  if (isnan(h) || isnan(t) || isnan(f))
  {
    Serial.println("Failed to read from DHT sensor!");
    return;
  }
  // Compute heat index in Fahrenheit (the default)
  float hif = dht.computeHeatIndex(f, h);
  // Compute heat index in Celsius (Fahrenheit = false)
  float hic = dht.computeHeatIndex(t, h, false);

  // he thong vuon thong minh==================================================
  float moisture = 0;
  // Đọc độ ẩm đất hiện tại từ cảm biến đọc 10 lần và
  // lấy trung bình cộng để đảm bảo kết quả là ổn định
  for (int i = 0; i < 10; i++)
  {
    moisture = moisture + analogRead(A0);
    delay(500);
    Serial.println(moisture);
  }

  int motionDetected = digitalRead(PINK_OUT_SENSOR);
  int lightStatus = digitalRead(LIGHT_SENSOR);

  initDiffihelman();
  // Khoi tao json
  JSONVar jsonObj;

  // Thêm các trường dữ liệu vào JSON
  jsonObj["temperature"] = t;
  jsonObj["humidity"] = h;
  jsonObj["humidityGround"] = (int)moisture;
  jsonObj["isDark"] = lightStatus;
  jsonObj["isMotionDetected"] = motionDetected;
  // Chuyển đổi JSON thành chuỗi
  String jsonString = JSON.stringify(jsonObj);
  char message[jsonString.length() + 1]; // +1 cho ký tự kết thúc chuỗi null

  jsonString.toCharArray(message, sizeof(message));
  jsonString = jsonString + "!";
  const char associated_data[] = "AdditionalData";
  String hexCiphertext = "";
  // cat key tu 32 -> 16
  uint8_t partnerPublicKey16[16];
  for (int i = 0; i < 16; i++)
  {
    partnerPublicKey16[i] = partnerPublicKey[i];
  }

  unsigned char ciphertext[MAX_MESSAGE_LEN + CRYPTO_ABYTES];
  unsigned long long ciphertext_len;

  int encrypt_result = crypto_aead_encrypt(
      ciphertext, &ciphertext_len,
      (const unsigned char *)message, strlen(message),
      NULL, 0,
      NULL, nonce, partnerPublicKey16);

  if (encrypt_result != 0)
  {
    Serial.println("Encryption failed");
  }
  else
  {
    Serial.println("Encryption successful");
    for (size_t i = 0; i < ciphertext_len; i++)
    {
      if (ciphertext[i] < CRYPTO_KEYBYTES)
      {
        hexCiphertext += "0"; // Đảm bảo có đủ 2 ký tự hex
      }
      hexCiphertext += String(ciphertext[i], HEX);
      Serial.print(ciphertext[i], HEX);
      Serial.print(" ");
    }
    Serial.println();

    // Decrypt the ciphertext
    unsigned char decrypted_message[MAX_MESSAGE_LEN];
    unsigned long long decrypted_message_len;
    unsigned char nsec[CRYPTO_NSECBYTES]; // Non-secret data (not used in this example)

    // lay cipher text chua du lieu tu serrver roi chuyen sang byte arr de giai ma
    String ciphertextRes = sendPostRequest(hexCiphertext, ciphertext_len, strlen(message));
    uint8_t cipherServer[ciphertextRes.length()];
    const char *hexString = ciphertextRes.c_str();
    hexStringToByteArray(hexString, cipherServer, ciphertextRes.length());

    int decrypt_result = crypto_aead_decrypt(
        decrypted_message, &decrypted_message_len,
        NULL, cipherServer, sizeof(cipherServer) / 2,
        NULL, 0,
        nonce, partnerPublicKey16);

    if (decrypt_result != 0)
    {
      Serial.println("Decryption failed");
    }
    else
    {
      digitalWrite(RELAY_PIN, LOW);

      digitalWrite(FAN, LOW);

      Serial.print("Decryption successful. Decrypted Message: ");
      Serial.println((char *)decrypted_message);
      JSONVar myObject = JSON.parse((char *)decrypted_message);

      // JSON.typeof(jsonVar) can be used to get the type of the variable
      if (JSON.typeof(myObject) == "undefined")
      {
        Serial.println("Parsing input failed!");
        ESP.restart();
      }
      if (myObject.hasOwnProperty("light"))
      {
        if ((bool)myObject["light"] == 1)
        {
          digitalWrite(LED_2, LOW);
          digitalWrite(LED_1, LOW);
        }
        else
        {
          digitalWrite(LED_2, HIGH);
          digitalWrite(LED_1, HIGH);
        }
      }
      if (myObject.hasOwnProperty("fan"))
      {
        if ((bool)myObject["fan"] == 1)
        {
          digitalWrite(FAN, LOW);
        }
        else
        {
          digitalWrite(FAN, HIGH);
        }
      }
      if (myObject.hasOwnProperty("pump"))
      {
        if ((bool)myObject["pump"] == 1)
        {
          digitalWrite(RELAY_PIN, HIGH);
        }
        else
        {
          digitalWrite(RELAY_PIN, LOW);
        }
      }
    }
  }

  //
  memset(privateKey, 0, sizeof(privateKey));
  memset(publicKey, 0, sizeof(publicKey));
  memset(sharedSecret, 0, sizeof(sharedSecret));
  memset(partnerPublicKey16, 0, sizeof(partnerPublicKey16));
  // Để đảm bảo chỉ gửi request một lần, không cần loop nữa
  delay(20000); // Đợi 20 giây và sau đó kết thúc chương trình
  ESP.restart();
}
