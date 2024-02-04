/*
  PubSubEasy.h - Library for subscribing and publishing to PubSub.
  Created by Nicolas Sandller, February 4, 2024.
  Released into the public domain.
*/

#ifndef PubSubEasy_h
#define PubSubEasy_h

#include <WiFiClientSecure.h>
#include <HTTPClient.h>

class PubSubEasy {
  public:
    PubSubEasy(
      const char* projectID,
      const char* topicName,
      const char* server,
      const char* key_path,
      const char* test_root_ca = nullptr
    );
    
    struct Attribute {
        String key;
        String value;
    };
    void init();
    void publish(const String& jsonMessage, const Attribute attributes[], unsigned int numAttributes);

  private:
    WiFiClientSecure client;
    HTTPClient http;
    String access_token;
    String base64UrlEncode(const uint8_t *input, int length);
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