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

void sendPostRequest(String hexCiphertext) {

  HTTPClient http;
  // Địa chỉ của server và endpoint
  String serverAddress = "http://192.168.1.106:9494";
  String endpoint = "/api/asconv12";
  String jsonBody = "{\"ciphertext\":\"" + hexCiphertext + "\"}";
  http.begin(serverAddress + endpoint);
  http.addHeader("Content-Type", "application/json");

  // Gửi POST request
  int httpResponseCode = http.POST(jsonBody);

  if (httpResponseCode > 0) {
    String response = http.getString();
    Serial.println(httpResponseCode);
    Serial.println(response);
  } else {
    Serial.print("Error on sending POST request: ");
    Serial.println(httpResponseCode);
  }

  http.end();
}
#define MAX_MESSAGE_LEN 100  // Maximum message length
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16

const unsigned char key[CRYPTO_KEYBYTES] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const unsigned char nonce[CRYPTO_NPUBBYTES] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void loop() {

  const char message[] = "Hello, ASCON!";
  const char associated_data[] = "AdditionalData";
  String hexCiphertext = "";

  unsigned char ciphertext[MAX_MESSAGE_LEN + CRYPTO_ABYTES];
  unsigned long long ciphertext_len;

  int encrypt_result = crypto_aead_encrypt(
    ciphertext, &ciphertext_len,
    (const unsigned char*)message, strlen(message),
    NULL, 0,
    NULL, nonce, key);

  if (encrypt_result != 0) {
    Serial.println("Encryption failed");
  } else {
    Serial.println("Encryption successful");


    for (size_t i = 0; i < ciphertext_len; i++) {
      if (ciphertext[i] < 16) {
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

    int decrypt_result = crypto_aead_decrypt(
      decrypted_message, &decrypted_message_len,
      NULL, ciphertext, ciphertext_len,
      NULL, 0,
      nonce, key);

    if (decrypt_result != 0) {
      Serial.println("Decryption failed");
    } else {
      Serial.print("Decryption successful. Decrypted Message: ");
      Serial.println((char*)decrypted_message);
    }
  }


  sendPostRequest(hexCiphertext);

  // Để đảm bảo chỉ gửi request một lần, không cần loop nữa
  delay(5000);  // Đợi 5 giây và sau đó kết thúc chương trình
  ESP.restart();
}
