#include <Arduino.h>
#include "PubSubEasy.h"

#define DEBUG == 1 // For debugging logs to print to Serial

const char* ssid = "[YOUR SSID]";
const char* password = "[YOUR WIFI PASSWORD]";

const char* project_name = "[project-1234]";
const char* topic_name = "[project-1234]";
const char* api_url = "https://pubsub.googleapis.com";
// Default should be /gcp_iot.json but you have to put the file under data/gcp_iot.json
const char* service_account_key_path = "/gcp_iot.json";

// const char* caCert = "..."; // Your CA certificate here but pass nullptr for insecure connection (test)
PubSubEasy pubSub(project_name, topic_name, api_url , service_account_key_path, nullptr);

void connectToWiFi() {
  // Connets to WIFI
  Serial.print("Connecting to WiFi SSID: ");
  Serial.println(ssid);
  WiFi.begin(ssid, password);

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 20) { // Retry for a certain number of attempts
    delay(1000);
    Serial.print(".");
    attempts++;
  }

  if(WiFi.status() == WL_CONNECTED) {
    Serial.println("\nWiFi Connected.");
    Serial.print("IP Address: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("\nFailed to connect to WiFi. Please check your settings.");
  }
}

void setup() {
  //Initialize serial and wait for port to open:
  Serial.begin(115200);
  delay(100);

  connectToWiFi();

  topic.init();
  // Now ready to send messages
  PubSubEasy::Attribute attributes[] = {
      {"device_id", "device_1"},
      {"location", "greenhouse"}
  };

  String jsonMessage = "{\"temperature\": 22.5, \"humidity\": 45.2}";

  topic.publish(jsonMessage, attributes, 2);

}

void loop() {
  // Your loop code
}