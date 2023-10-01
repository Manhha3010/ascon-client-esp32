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


// khai bao do dai
#define MAX_MESSAGE_LEN 100  // Maximum message length
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16
#define KEY_LENGTH_32 32

// Khai báo biến cho khóa Diffie-Hellman và khóa chia sẻ bí mật
uint8_t privateKey[KEY_LENGTH_32];    // Khóa bí mật của bạn
uint8_t publicKey[KEY_LENGTH_32];     // Khóa công khai của bạn
uint8_t sharedSecret[KEY_LENGTH_32];  // Khóa chia sẻ bí mật sau khi tính
uint8_t partnerPublicKey[KEY_LENGTH_32];

// tam thoi chua dung nonce
const unsigned char nonce[CRYPTO_NPUBBYTES] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};



// decrypt
int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k) {
  if (clen < CRYPTO_ABYTES) {
    *mlen = 0;
    return -1;
  }

  state s;
  u32_4 tmp;
  (void)nsec;

  // set plaintext size
  *mlen = clen - CRYPTO_ABYTES;

  ascon_core(&s, m, c, *mlen, ad, adlen, npub, k, ASCON_DEC);

  tmp.words[0].h = ((u32*)(c + *mlen))[0];
  tmp.words[0].l = ((u32*)(c + *mlen))[1];
  tmp.words[1].h = ((u32*)(c + *mlen))[2];
  tmp.words[1].l = ((u32*)(c + *mlen))[3];
  tmp = ascon_rev8(tmp);
  u32_2 t0 = tmp.words[0];
  u32_2 t1 = tmp.words[1];

  // verify tag (should be constant time, check compiler output)
  if (((s.x3.h ^ t0.h) | (s.x3.l ^ t0.l) | (s.x4.h ^ t1.h) | (s.x4.l ^ t1.l)) != 0) {
    *mlen = 0;
    return -1;
  }

  return 0;
}

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
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
  ((u32*)(c + mlen))[0] = tmp.words[0].h;
  ((u32*)(c + mlen))[1] = tmp.words[0].l;
  ((u32*)(c + mlen))[2] = tmp.words[1].h;
  ((u32*)(c + mlen))[3] = tmp.words[1].l;

  return 0;
}



const char* ssid = "DuyManhKMA";
const char* password = "your_PASSWORD";


// hexStringToByteArray
void hexStringToByteArray(const char* hexString, uint8_t* byteArray, size_t byteLength) {
  int hexStringLength = strlen(hexString);

  // Đảm bảo rằng độ dài của chuỗi hex là số chẵn
  if (hexStringLength % 2 != 0) {
    // Nếu độ dài không chẵn, bạn có thể xử lý lỗi hoặc điều chỉnh độ dài
    // ví dụ: thêm '0' ở đầu chuỗi để làm cho độ dài chẵn
  }

  // Tính toán độ dài của mảng uint8_t
  int byteArraySize = hexStringLength / 2;

  // Khai báo mảng uint8_t để lưu trữ dữ liệu đã chuyển đổi

  // Lặp qua chuỗi hex và chuyển đổi thành mảng uint8_t
  for (int i = 0; i < hexStringLength; i += 2) {
    char hexPair[3] = { hexString[i], hexString[i + 1], '\0' };
    byteArray[i / 2] = strtol(hexPair, nullptr, 16);
  }
}

// Khoi tao trao doi khoa
void initDiffihelman() {
  String hexPublicKey = "";
  String partnerPublicKeyStr = "";


  // Tạo cặp khóa Diffie-Hellman
  Curve25519::dh1(publicKey, privateKey);
  String hexstring = "";
  // doi public tu arr sang string gui len server
  for (int i = 0; i < KEY_LENGTH_32; i++) {
    if (publicKey[i] < 0x10) {
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
  String serverAddress = "http://192.168.1.104:9494";
  String endpoint = "/api/asconv12/diffie-hellman";
  String jsonBody = "{\"publicKey\":\"" + hexstring + "\"}";
  http.begin(serverAddress + endpoint);
  http.addHeader("Content-Type", "application/json");

  // Gửi POST request
  int httpResponseCode = http.POST(jsonBody);

  if (httpResponseCode > 0) {
    partnerPublicKeyStr = http.getString();
    Serial.println(httpResponseCode);
    Serial.println(partnerPublicKeyStr);
  } else {
    Serial.print("Error on sending POST request: ");
    Serial.println(httpResponseCode);
  }
  // doi gia tri hex string public key tu server sang byte de tinh toan shared key
  const char* hexString = partnerPublicKeyStr.c_str();
  Serial.println("Server publickey");
  Serial.println(hexString);
  hexStringToByteArray(hexString, partnerPublicKey, sizeof(partnerPublicKey));
  Serial.println("Diffie-Hellman ShpartnerPublicKeyared Secret:");
  for (int i = 0; i < KEY_LENGTH_32; i++) {
    Serial.print(partnerPublicKey[i], HEX);
    Serial.print(" ");
  }

  // se chuyen doi tu parnerkey -> shared
  if (!Curve25519::dh2(partnerPublicKey, privateKey)) {
    Serial.println("Error!!!!");
    http.end();
    return;
  }



  http.end();
  Serial.println("Diffie-Hellman Shared Secret:");
  for (int i = 0; i < KEY_LENGTH_32; i++) {
    Serial.print(partnerPublicKey[i], HEX);
    Serial.print(" ");
  }
  Serial.println();
}



void setup() {
  Serial.begin(115200);
  delay(1000);


  WiFi.begin(ssid);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }
  Serial.println("Connected to WiFi");
}

// sendPost resquet cipher text len server
String sendPostRequest(String hexCiphertext, unsigned long long ciphertext_len, unsigned long long mess_len) {

  HTTPClient http;
  // Địa chỉ của server và endpoint
  String serverAddress = "http://192.168.1.104:9494";
  String endpoint = "/api/asconv12";

  String jsonBody = "{\n  \"ciphertext\":\"" + hexCiphertext + "\",\n  \"cipherTextLength\":" + ciphertext_len + ",\n  \"messageLength\":" + mess_len + "\n}";

  http.begin(serverAddress + endpoint);
  http.addHeader("Content-Type", "application/json");

  // Gửi POST request
  int httpResponseCode = http.POST(jsonBody);
  String response = "";
  if (httpResponseCode > 0) {
    response = http.getString();
    Serial.println(httpResponseCode);
    Serial.println(response);
  } else {
    Serial.print("Error on sending POST request: ");
    Serial.println(httpResponseCode);
  }

  http.end();
  return response;
}




void loop() {


  initDiffihelman();
// Khoi tao json
  JSONVar jsonObj;

  // Thêm các trường dữ liệu vào JSON
  jsonObj["temperature"] = 24;
  jsonObj["humidity"] = 69;
  // Chuyển đổi JSON thành chuỗi
  String jsonString = JSON.stringify(jsonObj);
  char message[jsonString.length() + 1];  // +1 cho ký tự kết thúc chuỗi null

  jsonString.toCharArray(message, sizeof(message));
  jsonString = jsonString + "!";
  const char associated_data[] = "AdditionalData";
  String hexCiphertext = "";
  // cat key tu 32 -> 16
  uint8_t partnerPublicKey16[16];
  for (int i = 0; i < 16; i++) {
    partnerPublicKey16[i] = partnerPublicKey[i];
  }

  unsigned char ciphertext[MAX_MESSAGE_LEN + CRYPTO_ABYTES];
  unsigned long long ciphertext_len;

  int encrypt_result = crypto_aead_encrypt(
    ciphertext, &ciphertext_len,
    (const unsigned char*)message, strlen(message),
    NULL, 0,
    NULL, nonce, partnerPublicKey16);

  if (encrypt_result != 0) {
    Serial.println("Encryption failed");
  } else {
    Serial.println("Encryption successful" );
    for (size_t i = 0; i < ciphertext_len; i++) {
      if (ciphertext[i] < CRYPTO_KEYBYTES) {
        hexCiphertext += "0";  // Đảm bảo có đủ 2 ký tự hex
      }
      hexCiphertext += String(ciphertext[i], HEX);
      Serial.print(ciphertext[i], HEX);
      Serial.print(" ");
    }
    Serial.println();

    // Decrypt the ciphertext
    unsigned char decrypted_message[MAX_MESSAGE_LEN];
    unsigned long long decrypted_message_len;
    unsigned char nsec[CRYPTO_NSECBYTES];  // Non-secret data (not used in this example)



// lay cipher text chua du lieu tu serrver roi chuyen sang byte arr de giai ma
    String ciphertextRes = sendPostRequest(hexCiphertext, ciphertext_len, strlen(message));
    uint8_t cipherServer[ciphertextRes.length()];  
    const char* hexString = ciphertextRes.c_str();
    hexStringToByteArray(hexString, cipherServer, ciphertextRes.length());


    int decrypt_result = crypto_aead_decrypt(
      decrypted_message, &decrypted_message_len,
      NULL, cipherServer, sizeof(cipherServer) / 2,
      NULL, 0,
      nonce, partnerPublicKey16);

    if (decrypt_result != 0) {
      Serial.println("Decryption failed");
    } else {
      Serial.print("Decryption successful. Decrypted Message: ");
      Serial.println((char*)decrypted_message);
    }
  }

// 
  memset(privateKey, 0, sizeof(privateKey));
  memset(publicKey, 0, sizeof(publicKey));
  memset(sharedSecret,0,sizeof(sharedSecret));
  memset(partnerPublicKey16,0,sizeof(partnerPublicKey16));
  // Để đảm bảo chỉ gửi request một lần, không cần loop nữa
  delay(5000);  // Đợi 5 giây và sau đó kết thúc chương trình
  ESP.restart();
}
