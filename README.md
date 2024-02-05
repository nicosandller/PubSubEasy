
# PubSubEasy Library for Arduino

The `PubSubEasy` library provides a simplified way to publish messages to Google Cloud Pub/Sub topics from Arduino-based devices. It handles secure connections, JWT authentication, and message publication with optional attributes, making it easier to integrate IoT devices with Google Cloud Pub/Sub.

## Features

- Easy publishing of JSON messages to Google Cloud Pub/Sub.
- Support for adding custom message attributes.
- Integrated JWT authentication handling.
- Secure communication via HTTPS.

## Prerequisites

- An Arduino board with networking capabilities (e.g., ESP8266, ESP32).
- A Google Cloud Platform account and a Pub/Sub topic created.
- A service account with Pub/Sub Publisher role and its JSON key file.

## Installation

1. **Download the Library**: Click on the "Code" button on this GitHub page and select "Download ZIP".

2. **Install in Arduino IDE**:
    - Open the Arduino IDE.
    - Go to `Sketch` > `Include Library` > `Add .ZIP Library...`.
    - Choose the downloaded ZIP file and click "Open" to install.

3. **Using PlatformIO**:
    - Add the library to your `platformio.ini` dependencies.
    - or copy the library files to your project's `lib` directory.
    - or make a `symlink` to the project's `lib` directory:
```
ln -s /path/to/YourLibraryName /path/to/projects/lib/YourLibraryName
```


## Quick Start

1. **Prepare Your Google Cloud Setup**:
    - Ensure you have a Pub/Sub topic created.
    - Download the JSON key file for a service account with permissions to publish to the topic.

2. **Configure Your Device**:
    - Store the service account JSON key in your device's file system (e.g., using SPIFFS or LittleFS).

3. **Basic Usage**:

```cpp
#include <PubSubEasy.h>

// Replace these with your actual configuration values
const char* ssid = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";
const char* projectID = "your-google-cloud-project-id";
const char* topicName = "your-pubsub-topic-name";
const char* serviceAccountKeyPath = "/path/to/service/account/key.json";

PubSubEasy pubSub(projectID, topicName, serviceAccountKeyPath);

void setup() {
  Serial.begin(115200);
  // Connect to WiFi
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }
  
  // Initialize PubSubEasy
  pubSub.init();
  
  // Publish a test message
  String jsonMessage = "{\"temperature\": 22.5, \"humidity\": 45.2}";
  PubSubEasy::Attribute attributes[] = {
      {"sensorId", "sensor_001"},
      {"location", "greenhouse"}
  };
  pubSub.publish(jsonMessage, attributes, 2);
}

void loop() {
  // Your loop code
}
```

## Configuration

- **WiFi Setup**: Ensure your device is connected to the internet via WiFi.
- **Service Account and Key File**: Place your Google Cloud service account key JSON file in the device's file system and provide the path to `PubSubEasy`.

## Documentation

For detailed documentation on all available methods and configurations, please refer to the comments in the `PubSubEasy.h` and `PubSubEasy.cpp` files.

## Support & Contributions

For support, please open an issue in the GitHub repository. Contributions are welcome! If you'd like to contribute, please fork the repository and submit a pull request.

