# ESP32 SecureCam – Smart Intrusion Detection Camera

## Project Overview
ESP32 SecureCam is an ESP32-CAM + PIR motion sensor project that detects motion, captures an image, and sends an alert/photo to Telegram over Wi-Fi. It demonstrates a low-cost IoT security device and basic secure alerting.

## Features
- PIR motion detection
- Captures a photo on a motion event
- Sends Telegram alert + image
- Cooldown delay to reduce spam
  
![IMG_1732](https://github.com/user-attachments/assets/beec05cf-43c9-48d8-9886-12c50d0b160f)

## Hardware Used
- ESP32-CAM 
- PIR motion sensor 
- FTDI / USB-to-Serial adapter
- Jumper wires + breadboard
- 
  ![IMG_1731](https://github.com/user-attachments/assets/cb0a01f0-e7d3-4869-a2a0-ec5189b1cb54)
  
## Software Used
- Arduino IDE
- ESP32 board package 
- Telegram Bot API 

## How It Works 
1. PIR detects motion (HIGH signal)
2. ESP32-CAM initializes camera
3. Device captures a JPEG frame
4. Sends message + photo to Telegram
   
<img width="725" height="890" alt="1" src="https://github.com/user-attachments/assets/e2c24fb8-7a63-4d02-815a-ae28081931dd" />

## Full Code

#include "esp_camera.h"
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include "soc/soc.h"
#include "soc/rtc_cntl_reg.h"

const char* WIFI_SSID     = "WiFi";
const char* WIFI_PASSWORD = "999";
String BOT_TOKEN = "8206128912:AAFvBIvuQsQUh2Ah38XV6T_4545454545";
String CHAT_ID   = "644454545";
// ================================================

// Wiring
#define PIR_PIN 13                    // PIR OUT -> GPIO13 (change if needed)
#define FLASH_LED_PIN 4               // ESP32-CAM flash LED (GPIO4)

// ===== Anti-spam tuning =====
const unsigned long PIR_WARMUP_MS   = 1000;  // ignore PIR for 10s after boot
const unsigned long REARM_LOW_MS    = 2000;   // PIR must stay LOW 2s to re-arm
const unsigned long MIN_INTERVAL_MS = 1000;  // at least 5s between alerts
// ============================

WiFiClientSecure client;

bool motionLatched = false;
unsigned long lowSinceMs = 0;
unsigned long bootMs = 0;
unsigned long lastSentMs = 0;

// ---- AI THINKER ESP32-CAM pin map ----
#define PWDN_GPIO_NUM     32
#define RESET_GPIO_NUM    -1
#define XCLK_GPIO_NUM      0
#define SIOD_GPIO_NUM     26
#define SIOC_GPIO_NUM     27

#define Y9_GPIO_NUM       35
#define Y8_GPIO_NUM       34
#define Y7_GPIO_NUM       39
#define Y6_GPIO_NUM       36
#define Y5_GPIO_NUM       21
#define Y4_GPIO_NUM       19
#define Y3_GPIO_NUM       18
#define Y2_GPIO_NUM        5
#define VSYNC_GPIO_NUM    25
#define HREF_GPIO_NUM     23
#define PCLK_GPIO_NUM     22
// -------------------------------------

String urlEncode(const String &s) {
  String out = "";
  const char *hex = "0123456789ABCDEF";
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') ||
        c == '-' || c == '_' || c == '.' || c == '~') {
      out += c;
    } else if (c == ' ') {
      out += "%20";
    } else if (c == '\n') {
      out += "%0A";
    } else {
      out += '%';
      out += hex[(c >> 4) & 0xF];
      out += hex[c & 0xF];
    }
  }
  return out;
}

void ensureWiFi() {
  if (WiFi.status() == WL_CONNECTED) return;

  WiFi.disconnect(true);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 12000) {
    delay(300);
  }
}

bool sendTelegramMessage(const String &text) {
  ensureWiFi();
  if (WiFi.status() != WL_CONNECTED) return false;

  String host = "api.telegram.org";
  String url = "/bot" + BOT_TOKEN + "/sendMessage?chat_id=" + CHAT_ID +
               "&parse_mode=Markdown&text=" + urlEncode(text);

  if (!client.connect(host.c_str(), 443)) return false;

  client.print(String("GET ") + url + " HTTP/1.1\r\n");
  client.print(String("Host: ") + host + "\r\n");
  client.print("Connection: close\r\n\r\n");

  while (client.connected() || client.available()) {
    if (client.available()) client.read();
    delay(1);
  }
  client.stop();
  return true;
}

bool sendPhotoToTelegram(uint8_t *imageData, size_t imageLen, const String &caption) {
  ensureWiFi();
  if (WiFi.status() != WL_CONNECTED) return false;

  String host = "api.telegram.org";
  String boundary = "----ESP32CAMBoundary";

  String startRequest =
    "POST /bot" + BOT_TOKEN + "/sendPhoto HTTP/1.1\r\n" +
    "Host: " + host + "\r\n" +
    "Content-Type: multipart/form-data; boundary=" + boundary + "\r\n";

  String part1 =
    "--" + boundary + "\r\n"
    "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n" +
    CHAT_ID + "\r\n" +

    "--" + boundary + "\r\n"
    "Content-Disposition: form-data; name=\"caption\"\r\n\r\n" +
    caption + "\r\n" +

    "--" + boundary + "\r\n"
    "Content-Disposition: form-data; name=\"photo\"; filename=\"motion.jpg\"\r\n"
    "Content-Type: image/jpeg\r\n\r\n";

  String part2 =
    "\r\n--" + boundary + "--\r\n";

  size_t contentLength = part1.length() + imageLen + part2.length();

  if (!client.connect(host.c_str(), 443)) return false;

  client.print(startRequest);
  client.print("Content-Length: " + String(contentLength) + "\r\n");
  client.print("Connection: close\r\n\r\n");

  client.print(part1);
  client.write(imageData, imageLen);
  client.print(part2);

  unsigned long t = millis();
  while (millis() - t < 8000) {
    while (client.available()) client.read();
    if (!client.connected()) break;
    delay(1);
  }
  client.stop();
  return true;
}

String dramaticAlert() {
  return "🚨⚠️ *MOTION DETECTED* ⚠️🚨\n"
         "👀 Movement captured — sending evidence NOW.";
}

bool initCamera() {
  camera_config_t config;
  config.ledc_channel = LEDC_CHANNEL_0;
  config.ledc_timer   = LEDC_TIMER_0;

  config.pin_d0 = Y2_GPIO_NUM;
  config.pin_d1 = Y3_GPIO_NUM;
  config.pin_d2 = Y4_GPIO_NUM;
  config.pin_d3 = Y5_GPIO_NUM;
  config.pin_d4 = Y6_GPIO_NUM;
  config.pin_d5 = Y7_GPIO_NUM;
  config.pin_d6 = Y8_GPIO_NUM;
  config.pin_d7 = Y9_GPIO_NUM;

  config.pin_xclk = XCLK_GPIO_NUM;
  config.pin_pclk = PCLK_GPIO_NUM;
  config.pin_vsync = VSYNC_GPIO_NUM;
  config.pin_href = HREF_GPIO_NUM;
  config.pin_sccb_sda = SIOD_GPIO_NUM;
  config.pin_sccb_scl = SIOC_GPIO_NUM;

  config.pin_pwdn = PWDN_GPIO_NUM;
  config.pin_reset = RESET_GPIO_NUM;

  config.xclk_freq_hz = 20000000;
  config.pixel_format = PIXFORMAT_JPEG;

  // More reliable settings to reduce "Camera capture fail."
  if (psramFound()) {
    config.frame_size   = FRAMESIZE_QVGA; // smaller + stable
    config.jpeg_quality = 12;
    config.fb_count     = 1;
  } else {
    config.frame_size   = FRAMESIZE_QQVGA;
    config.jpeg_quality = 14;
    config.fb_count     = 1;
  }

  return (esp_camera_init(&config) == ESP_OK);
}

camera_fb_t* capturePhotoSafe(bool useFlash) {
  if (useFlash) {
    digitalWrite(FLASH_LED_PIN, HIGH);
    delay(120);
  }

  camera_fb_t *fb = esp_camera_fb_get();

  if (useFlash) digitalWrite(FLASH_LED_PIN, LOW);

  // Retry once if capture fails
  if (!fb) {
    delay(200);
    if (useFlash) {
      digitalWrite(FLASH_LED_PIN, HIGH);
      delay(120);
    }
    fb = esp_camera_fb_get();
    if (useFlash) digitalWrite(FLASH_LED_PIN, LOW);
  }

  return fb;
}

void setup() {
  WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0); // helps on ESP32-CAM

  Serial.begin(115200);
  delay(300);

  pinMode(PIR_PIN, INPUT); // if your PIR output is unstable, try INPUT_PULLDOWN
  pinMode(FLASH_LED_PIN, OUTPUT);
  digitalWrite(FLASH_LED_PIN, LOW);

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
    delay(300);
  }

  client.setInsecure();

  if (!initCamera()) {
    Serial.println("Camera init FAILED");
    // don't spam telegram on failure
    return;
  }

  bootMs = millis();
  sendTelegramMessage("✅ ESP32-CAM online. PIR armed (warmup 30s).");
}

void loop() {
  // PIR warmup after boot so it doesn't spam immediately
  if (millis() - bootMs < PIR_WARMUP_MS) {
    delay(80);
    return;
  }

  int pir = digitalRead(PIR_PIN);

  // Trigger only once per motion event AND enforce minimum time between alerts
  if (!motionLatched) {
    if (pir == HIGH && (millis() - lastSentMs > MIN_INTERVAL_MS)) {
      motionLatched = true;
      lastSentMs = millis();

      sendTelegramMessage(dramaticAlert());

      // If you suspect power resets, set useFlash=false
      bool useFlash = true;

      camera_fb_t *fb = capturePhotoSafe(useFlash);
      if (!fb) {
        sendTelegramMessage("❌ Camera capture failed");
        return;
      }

      sendPhotoToTelegram(fb->buf, fb->len, "🚨⚠️ MOTION DETECTED ⚠️🚨");
      esp_camera_fb_return(fb);
    }
  } else {
    // Re-arm only after PIR has been LOW continuously for REARM_LOW_MS
    if (pir == LOW) {
      if (lowSinceMs == 0) lowSinceMs = millis();
      if (millis() - lowSinceMs > REARM_LOW_MS) {
        motionLatched = false;
        lowSinceMs = 0;
      }
    } else {
      lowSinceMs = 0; // still high, keep latched
    }
  }

  delay(80);
}

## Video Demo

## Resources
- https://www.youtube.com/watch?v=LBoM_Uoq_nA
- https://randomnerdtutorials.com/esp32-cam-pir-motion-detector-photo-capture/
- https://github.com/LucaTomei/Esp32-Cam-PIR-Telegram?tab=readme-ov-file

## 1) Arduino IDE + ESP32 Board Package
1. Open Arduino IDE → Preferences
2. Add ESP32 boards URL (if needed) in “Additional Boards Manager URLs.”
3. Tools → Board → Boards Manager → install “esp32 by Espressif Systems”

## 2) Board Settings (typical)
- Board: "AI Thinker ESP32-CAM" (or "ESP32 Wrover Module" depending on your setup)
- Partition Scheme: "Huge APP" (if available)
- Upload Speed: 115200 (or 921600 if stable)

## 3) Libraries
- WiFi
- WiFiClientSecure
- esp_camera

## 4) Telegram Bot Setup
1. Create bot with BotFather
2. Copy BOT_TOKEN
3. Get your CHAT_ID 
4. Put token + chat_id into the sketch
<img width="1280" height="833" alt="4b5f1a5c-eaac-481a-8721-d41117372576" src="https://github.com/user-attachments/assets/3eee0e07-949b-48f2-a8fc-8697ba6e6885" />

## 5) Uploading
1. Connect FTDI to ESP32-CAM (5V, GND, U0R, U0T)
2. Put GPIO0 to GND (flash mode)
3. Press RST, then upload
4. Remove GPIO0 from GND, press RST to run
   
![image](https://github.com/user-attachments/assets/4e9f8adc-d39c-4242-8d46-48afaa20d2ec)

## 6) Test
- Open Serial Monitor
- Trigger PIR motion
- Confirm Telegram receives message + photo
docs/TROUBLESHOOTING.md 
md
Copy code
# Troubleshooting Notes

## Problem: Camera init failed 
Fixes:
- Confirm AI Thinker pin config is correct for your ESP32-CAM
- Ensure stable 5V power
- Reduce frame size / quality if memory issues occur
- Re-seat board and check ribbon/antenna connections

## Problem: Upload fails / timeout / no serial output
Fixes:
- GPIO0 must be connected to GND to flash
- Use 5V (not 3.3V) on many ESP32-CAM boards
- Swap RX/TX if needed
- Press RST right when upload begins

## Problem: Telegram message sends but photo fails
Fixes:
- Use WiFiClientSecure with proper TLS handling
- Ensure photo buffer is valid 
- Reduce image size/quality to avoid memory issues
- Add delay + retry logic for network stability

## Problem: PIR triggers constantly / false positives
Fixes:
- Adjust PIR sensitivity + delay knobs
- Add cooldown timer 
- Avoid pointing at heat sources/windows
