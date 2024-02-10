/*
  PubSubEasy.h - Library for subscribing and publishing to PubSub.
  Created by Nicolas Sandller, February 4, 2024.
  Released into the public domain.
*/

#ifndef PubSubEasy_h
#define PubSubEasy_h

#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include "tools.h"

/*
  PubSubEasy class facilitates publishing messages to Google Cloud Pub/Sub topics
  with optional message attributes and secure connection handling.
*/
class PubSubEasy {
  public:
    PubSubEasy(
      const char* projectID,
      const char* topicName,
      const char* server,
      const char* key_path,
      const char* test_root_ca = nullptr
    );
    // Represents a key-value pair attribute to include with a published message.
    struct Attribute {
        String key;
        String value;
    };
    bool begin();
    void publish(const String& jsonMessage, const Attribute attributes[], unsigned int numAttributes);
    // Static method to encode in base 64
    static String base64UrlEncode(const uint8_t *input, int length);

  private:
    WiFiClientSecure client;  // Secure client for HTTPS communication.
    HTTPClient http;           // HTTP client for sending requests.
    String access_token;       // Cached access token for authentication.
    String readGcpServiceAccountKey();
    String generate_jwt(const String& key_file_content);
    String getAccessToken(const String& jwt);

    String projectID; // Google Cloud Project ID
    String topicName; // Pub/Sub Topic Name
    String server;
    String key_path; // Path to the GCP service account key
    const char* test_root_ca; // Root CA certificate

    String fullTopicUrl; // Full URL constructed from the above components

    void setupTime();
    void setupHttpClient();
    void connectToServer();
    void constructFullTopicUrl(); // Method to construct the full topic URL

    const char* tokenURL = "https://www.googleapis.com/oauth2/v4/token"; // Token URL
    const char* contentType = "application/x-www-form-urlencoded"; // Content type for the token request
    
};

#endif
