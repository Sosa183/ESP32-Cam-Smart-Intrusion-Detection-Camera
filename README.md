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

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include "soc/soc.h"
#include "soc/rtc_cntl_reg.h"
#include "esp_camera.h"

const char* ssid     = "";     
const char* password = ""; 

String token   = "";
String chat_id = "";

 
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

int gpioPIR = 13;   

const int FLASH_PIN  = 4;
const int FLASH_CH   = 3;
const int FLASH_FREQ = 5000;
const int FLASH_RES  = 8;

String alerts2Telegram(String token, String chat_id);

void blinkFlash(int times, int duty = 10, int onMs = 200, int offMs = 200) {
  // ESP32 core 3.x: attach channel like this
  ledcAttachChannel(FLASH_PIN, FLASH_FREQ, FLASH_RES, FLASH_CH);

  for (int i = 0; i < times; i++) {
    ledcWrite(FLASH_PIN, duty);   
    delay(onMs);
    ledcWrite(FLASH_PIN, 0);
    delay(offMs);
  }

  ledcDetach(FLASH_PIN);          
}

void setup()
{
  WRITE_PERI_REG(RTC_CNTL_BROWN_OUT_REG, 0);

  Serial.begin(115200);
  delay(10);

  pinMode(gpioPIR, INPUT_PULLUP);

  WiFi.mode(WIFI_STA);
  Serial.println("");
  Serial.print("Connecting to ");
  Serial.println(ssid);

  WiFi.begin(ssid, password);

  long int StartTime = millis();
  while (WiFi.status() != WL_CONNECTED)
  {
    delay(500);
    if ((StartTime + 10000) < millis()) break;
  }

  Serial.println("");
  Serial.println("STAIP address: ");
  Serial.println(WiFi.localIP());
  Serial.println("");

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("Reset");
    blinkFlash(1);
    delay(1000);
    ESP.restart();
  } else {
    blinkFlash(5);
  }

  camera_config_t config;
  config.ledc_channel = LEDC_CHANNEL_0;
  config.ledc_timer   = LEDC_TIMER_0;
  config.pin_d0       = Y2_GPIO_NUM;
  config.pin_d1       = Y3_GPIO_NUM;
  config.pin_d2       = Y4_GPIO_NUM;
  config.pin_d3       = Y5_GPIO_NUM;
  config.pin_d4       = Y6_GPIO_NUM;
  config.pin_d5       = Y7_GPIO_NUM;
  config.pin_d6       = Y8_GPIO_NUM;
  config.pin_d7       = Y9_GPIO_NUM;
  config.pin_xclk     = XCLK_GPIO_NUM;
  config.pin_pclk     = PCLK_GPIO_NUM;
  config.pin_vsync    = VSYNC_GPIO_NUM;
  config.pin_href     = HREF_GPIO_NUM;
  config.pin_sscb_sda = SIOD_GPIO_NUM;
  config.pin_sscb_scl = SIOC_GPIO_NUM;
  config.pin_pwdn     = PWDN_GPIO_NUM;
  config.pin_reset    = RESET_GPIO_NUM;
  config.xclk_freq_hz = 20000000;
  config.pixel_format = PIXFORMAT_JPEG;

  if (psramFound()) {
    config.frame_size   = FRAMESIZE_VGA;
    config.jpeg_quality = 10;   
    config.fb_count     = 2;
  } else {
    config.frame_size   = FRAMESIZE_QQVGA;
    config.jpeg_quality = 12;
    config.fb_count     = 1;
  }

  
  esp_err_t err = esp_camera_init(&config);
  if (err != ESP_OK) {
    Serial.printf("Camera init failed with error 0x%x", err);
    delay(1000);
    ESP.restart();
  }

  sensor_t * s = esp_camera_sensor_get();
  s->set_framesize(s, FRAMESIZE_XGA);
}

void loop()
{
  int v = digitalRead(gpioPIR);
  Serial.println(v);

  if (v == 1)
  {
    alerts2Telegram(token, chat_id);
    delay(10000);
  }

  delay(1000);
}

String alerts2Telegram(String token, String chat_id)
{
  const char* myDomain = "api.telegram.org";
  String getAll = "", getBody = "";

  camera_fb_t * fb = NULL;
  fb = esp_camera_fb_get();
  if (!fb)
  {
    Serial.println("Camera capture failed");
    delay(1000);
    ESP.restart();
    return "Camera capture failed";
  }

  WiFiClientSecure client_tcp;
  client_tcp.setInsecure(); 

  if (client_tcp.connect(myDomain, 443))
  {
    Serial.println("Connected to " + String(myDomain));

    String head =
      "--India\r\n"
      "Content-Disposition: form-data; name=\"chat_id\"; \r\n\r\n" + chat_id + "\r\n"
      "--India\r\n"
      "Content-Disposition: form-data; name=\"photo\"; filename=\"esp32-cam.jpg\"\r\n"
      "Content-Type: image/jpeg\r\n\r\n";

    String tail = "\r\n--India--\r\n";

    uint16_t imageLen = fb->len;
    uint16_t extraLen = head.length() + tail.length();
    uint16_t totalLen = imageLen + extraLen;

    client_tcp.println("POST /bot" + token + "/sendPhoto HTTP/1.1");
    client_tcp.println("Host: " + String(myDomain));
    client_tcp.println("Content-Length: " + String(totalLen));
    client_tcp.println("Content-Type: multipart/form-data; boundary=India");
    client_tcp.println();
    client_tcp.print(head);

    uint8_t *fbBuf = fb->buf;
    size_t fbLen = fb->len;

    for (size_t n = 0; n < fbLen; n = n + 1024)
    {
      if (n + 1024 < fbLen)
      {
        client_tcp.write(fbBuf, 1024);
        fbBuf += 1024;
      }
      else if (fbLen % 1024 > 0)
      {
        size_t remainder = fbLen % 1024;
        client_tcp.write(fbBuf, remainder);
      }
    }

    client_tcp.print(tail);

    esp_camera_fb_return(fb);

    int waitTime = 10000; 
    long startTime = millis();
    boolean state = false;

    while ((startTime + waitTime) > millis())
    {
      Serial.print(".");
      delay(100);

      while (client_tcp.available())
      {
        char c = client_tcp.read();
        if (c == '\n')
        {
          if (getAll.length() == 0) state = true;
          getAll = "";
        }
        else if (c != '\r')
          getAll += String(c);

        if (state == true) getBody += String(c);
        startTime = millis();
      }

      if (getBody.length() > 0) break;
    }

    client_tcp.stop();
    Serial.println(getBody);
  }
  else
  {
    getBody = "Connection to telegram failed.";
    Serial.println("Connection to telegram failed.");
    esp_camera_fb_return(fb);
  }

  return getBody;
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
