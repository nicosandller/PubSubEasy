/*
  PubSubEasy.h - Library for subscribing and publishing to PubSub.
  Created by Nicolas Sandller, February 4, 2024.
  Released into the public domain.
*/

#include "PubSubEasy.h"
#include <ArduinoJson.h>
#include <SPIFFS.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>
#include "mbedtls/error.h" 
#include <base64.hpp>

// Change this to if not defined
#if DEBUG == 1
    #define debug(x) Serial.print(x)
    #define debugln(x) Serial.println(x)
#else
    #define debug(x)
    #define debugln(x)
#endif

void debugMbedtlsError(int errCode) {
    char errorBuf[100];
    mbedtls_strerror(errCode, errorBuf, 100);
    debug("Error: ");
    debugln(errorBuf);
}

// Correct constructor definition in PubSub.cpp to match the declaration in PubSub.h
PubSubEasy::PubSubEasy(const char* projectID, const char* topicName, const char* server, const char* key_path, const char* test_root_ca) {
  this->projectID = projectID;
  this->topicName = topicName;
  this->server = server;
  this->key_path = key_path;
  this->test_root_ca = test_root_ca;

  constructFullTopicUrl(); // Construct the full topic URL
}

void PubSubEasy::init() {

  setupTime();
  setupHttpClient();

  String key_file_content = readGcpServiceAccountKey();
  if (key_file_content.length() > 0) {
    debugln("Key file content loaded successfully.");
  }

  String jwt = generate_jwt(key_file_content);
  debugln("JWT: " + jwt);

  access_token = getAccessToken(jwt);
  if (access_token.length() > 0) {
    debugln("Access token obtained: " + access_token);
  } else {
    debugln("Failed to obtain access token");
  }
}

void PubSubEasy::constructFullTopicUrl() {
    // Construct standard Pub/Sub topic URL format
    fullTopicUrl = "https://pubsub.googleapis.com/v1/projects/" + projectID + "/topics/" + topicName + ":publish";
}

void PubSubEasy::connectToServer() {
  debugln("\nStarting connection to server...");
  if (!client.connect(server.c_str(), 443))
    debugln("Connection failed!");
  else
    debugln("Connected to server!");
}

String PubSubEasy::base64UrlEncode(const uint8_t *input, int length) {
  size_t output_length;
  // Determine the length of the encoded string
  mbedtls_base64_encode(NULL, 0, &output_length, input, length);

  // Allocate memory for the output
  unsigned char encoded[output_length + 1]; // +1 for the null terminator
  mbedtls_base64_encode(encoded, output_length, &output_length, input, length);
  encoded[output_length] = '\0'; // Null-terminate the encoded string

  // Convert to URL-safe base64 encoding
  String encodedString = String((char *)encoded);
  encodedString.replace("+", "-");
  encodedString.replace("/", "_");
  encodedString.replace("=", ""); // Strip padding

  return encodedString;
}

void PubSubEasy::setupTime() {
  // Implement NTP time synchronization (ESP = server time)
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");

  time_t now = time(nullptr);
  // Wait for the time to be updated
  while (now < 8 * 3600 * 2) { 
    delay(500);
    debug(".");
    now = time(nullptr);
  }
  struct tm timeinfo;
  gmtime_r(&now, &timeinfo);
  debugln("Current time: ");
  debug(asctime(&timeinfo));
}

void PubSubEasy::setupHttpClient() {
  if (test_root_ca) {
    debugln("Setting HTTP client in SECURE mode.");
    client.setCACert(test_root_ca);
  } else {
    debugln("Setting HTTP client in INSECURE mode.");
    client.setInsecure();
  }

  http.begin(client, tokenURL);
  http.addHeader("Content-Type", contentType); // Assuming contentType is "application/x-www-form-urlencoded"
}

String PubSubEasy::readGcpServiceAccountKey() {
    // Reading of GCP service account key
    // Mounts SPIFFS and reads the JSON key file

    if (!SPIFFS.begin(true)) {
        debugln("Failed to mount SPIFFS file system. Stopping execution.");
        while(true) { delay(1000); } // Halt execution
    }

    File key_file = SPIFFS.open(key_path.c_str(), FILE_READ);
    if (!key_file) {
        debugln("Failed to open GCP service account key file. Stopping execution.");
        while(true) { delay(1000); } // Halt execution
    }

    String key_file_content;
    while (key_file.available()) {
        key_file_content += key_file.readStringUntil('\n');
    }
    key_file.close();

    if(key_file_content.length() == 0) {
        debugln("GCP service account key file is empty. Stopping execution.");
        while(true) { delay(1000); } // Halt execution
    }

    debugln("GCP service account key file read successfully.");
    return key_file_content;
}

String PubSubEasy::generate_jwt(const String& key_file_content) {
  // generate JWT
  debugln("Generating JWT...");

  DynamicJsonDocument key_data(4096);
  // deserializeJson(key_data, key_file_content);
  DeserializationError error = deserializeJson(key_data, key_file_content);

  if (error) {
      debug("Failed to deserialize key file content: ");
      debugln(error.c_str());
      while(true) { delay(1000); } // Halt execution
  }

  debugln("Key data deserialization completed:");
  serializeJsonPretty(key_data, Serial);

  String private_key_pem = key_data["private_key"].as<String>();
  if (private_key_pem.length() == 0) {
      debugln("Private key not found in key data.");
      while(true) { delay(1000); } // Halt execution
  }

  debugln("Private key found.");

  int token_lifetime = 3600; // 1 hour

  StaticJsonDocument<256> payload;
  payload["iat"] = (int)time(NULL);
  payload["exp"] = (int)time(NULL) + token_lifetime;
  payload["iss"] = key_data["client_email"].as<String>();
  payload["aud"] = "https://www.googleapis.com/oauth2/v4/token";
  payload["scope"] = "https://www.googleapis.com/auth/pubsub";
  payload["sub"] = key_data["client_email"].as<String>();

  // print payload
  debugln("Payload before signing: ");
  serializeJsonPretty(payload, Serial);
  debugln();

  // Create header
  String header = R"({"alg":"RS256","typ":"JWT"})";
  // Base64Url encode header and payload
  String encodedHeader = base64UrlEncode((const uint8_t *)header.c_str(), header.length());

  String jsonString;
  serializeJson(payload, jsonString);
  String encodedPayload = base64UrlEncode((const uint8_t *)jsonString.c_str(), jsonString.length());

  // Concatenate header and payload
  String message = encodedHeader + '.' + encodedPayload;

  // Load the private key
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  int ret = mbedtls_pk_parse_key(&pk, (const unsigned char *)private_key_pem.c_str(), private_key_pem.length() + 1, NULL, 0);
  if (ret != 0) {
    debug("mbedtls_pk_parse_key failed: ");
    debugMbedtlsError(ret);
    mbedtls_pk_free(&pk); // Ensure pk is freed on error
    while(true) { delay(1000); } // Halt execution
  }

  // Sign the message with the private key
  unsigned char hash[32];
  mbedtls_sha256((const unsigned char *)message.c_str(), message.length(), hash, 0);

  unsigned char signature[MBEDTLS_MPI_MAX_SIZE];
  size_t signature_len;
  ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), signature, &signature_len, NULL, NULL);
  if (ret != 0) {
    debug("mbedtls_pk_sign failed: ");
    debugMbedtlsError(ret);
    mbedtls_pk_free(&pk); // Ensure pk is freed on error
    while(true) { delay(1000); } // Halt execution
  }

  debugln("Signing completed");

  // Base64Url encode the signature
  String encodedSignature = base64UrlEncode(signature, signature_len);

  // Create the JWT (header.payload.signature)
  String jwt = message + '.' + encodedSignature;

  mbedtls_pk_free(&pk);

  debugln("JWT generation completed");

  return jwt;
}

String PubSubEasy::getAccessToken(const String& jwt) {

  StaticJsonDocument<1536> jsonDoc;

  String payload = "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + jwt;
  debugln("Sending token request with payload: " + payload);

  int httpResponseCode = http.POST(payload);
  if (httpResponseCode != 200) {
      debugln("Failed to obtain access token, HTTP response code: " + String(httpResponseCode));
      debugln("Response: " + http.getString()); // Print the server's response
      http.end(); // End the HTTP connection
      while(true) { delay(1000); } // Halt execution
  }

  debugln("Token request successful, HTTP response code: " + String(httpResponseCode));
  String response = http.getString();
  DeserializationError error = deserializeJson(jsonDoc, response);
  if (error) {
      debugln("Deserialization of the token response failed: " + String(error.c_str()));
      http.end(); // End the HTTP connection
      while(true) { delay(1000); } // Halt execution
  }

  String accessToken = jsonDoc["access_token"].as<String>();
  if (accessToken.length() > 0) {
      debugln("Access token obtained: " + accessToken);
      return accessToken;
  } else {
      debugln("Access token not found in the response.");
      while(true) { delay(1000); } // Halt execution
  }
  http.end(); // End the HTTP connection
}

void PubSubEasy::publish(const String& message, const Attribute attributes[], unsigned int numAttributes) {
    // Sending of push request
    debugln(F("Publishing to pubsub..."));

    StaticJsonDocument<256> message_payload;

    // Convert Arduino String to C-string for base64 encoding
    const char* messageCStr = message.c_str();
    size_t inputLength = strlen(messageCStr);

    // Calculate required buffer size: encoded length + padding + null terminator
    size_t base64BufferSize = ((inputLength + 2 - ((inputLength + 2) % 3)) * 4 / 3) + 1;

    // Dynamically allocate the buffer
    unsigned char* base64 = new unsigned char[base64BufferSize];
    unsigned int base64_length = encode_base64((unsigned char*)messageCStr, strlen(messageCStr), base64);
    base64[base64_length] = '\0'; // Ensure null termination

    message_payload["data"] = base64;

    // Adding attributes
    JsonObject attributesJson = message_payload.createNestedObject("attributes");
    for (unsigned int i = 0; i < numAttributes; ++i) {
        attributesJson[attributes[i].key] = attributes[i].value;
    }

    // Create request body with the message payload
    StaticJsonDocument<512> request_body;
    JsonArray messages = request_body.createNestedArray("messages");
    messages.add(message_payload);

    // Serialize request body
    String request_body_string;
    serializeJson(request_body, request_body_string);

    http.begin(client, fullTopicUrl); // Initialize the HTTPClient with the URL
    http.addHeader("Content-Type", "application/json");
    http.addHeader("Authorization", "Bearer " + access_token);

    // Debug request before its sent
    debugln("---- REQUEST ----");
    debugln("URL: " + fullTopicUrl);
    debugln("Content-Type: " + String(contentType)); // Assuming contentType is a class member or variable
    debugln("Authorization: Bearer " + access_token); // Be cautious with logging tokens in production
    debugln("Request Body:");
    debugln(request_body_string); // Assuming this is your serialized JSON or other data

    int httpCode = http.POST(request_body_string);

    if (httpCode == 200) {
        debugln(F("pubsub - HTTP response Code: 200 OK"));
        String payload = http.getString();
        debugln(F("Response:"));
        debugln(payload);
    } else {
        debug(F("Error on sending POST request: HTTP response Code: "));
        debugln(httpCode); // Make sure to log the actual code
        String response = http.getString(); // Log the error response body if available
        debugln(response);
    }

    // Release base63 buffer
    delete[] base64;
    http.end(); // Close the connection
}