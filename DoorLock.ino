#include "ptldap/ldap.hpp"

#include <ESP8266WiFi.h>
#include <SPI.h>
#include <MFRC522.h>
#include <FastLED.h>

#define RST_PIN D4
#define SS_PIN D8
#define RELAY_PIN D1
MFRC522 mfrc522(SS_PIN, RST_PIN);

std::array<CRGB, 1> leds;
void show_leds(auto ... leds) {
  ::leds = {leds...};
  FastLED.show();
}

// This file is in .gitignore
// You can disallow anonymous access to the badge ID so people can't be impersonated
// It should contain the following values:
/*
#define WIFI_SSID "WIFI_SSID"
#define WIFI_PASSWORD "WIFI_PSK"
#define LDAP_HOSTNAME "ldap.posttenebraslab.ch"
#define LDAP_PORT LDAP_PORT
#define LDAP_LOGIN "cn=DoorLockCN,ou=DoorLockOU,dc=DoorLockDC"
#define LDAP_PASSWORD "DOORLOCK_LDAP_PASSWD"
#define LDAP_GROUP "ou=Members,dc=DoorLockDC"
*/
#include "config.h"

using std::literals::string_view_literals::operator""sv;

struct Hex {
  char const* begin;
  size_t size;
};
void serial_print1(auto&& arg) {
  using Arg = std::decay_t<decltype(arg)>;
  if constexpr (std::is_same_v<Arg, Hex>) {
    for (char c : std::string_view{arg.begin, arg.size}) {
      Serial.print((c >> 4) & 0xf, HEX);
      Serial.print((c >> 0) & 0xf, HEX);
    }
  } else if constexpr (std::is_same_v<Arg, std::string_view>) {
    Serial.write(arg.data(), arg.size());
  } else if constexpr (std::is_enum_v<Arg>) {
    Serial.print(std::underlying_type_t<Arg>(arg));
  } else {
    Serial.print(arg);
  }
}
void serial_print(auto&& ... args) {
  (serial_print1(FWD(args)), ...);
}
void serial_println(auto&& ... args) {
  serial_print(FWD(args)...);
  Serial.println();
}

// WiFiClient client;
BearSSL::WiFiClientSecure client;

struct FatalError: public std::exception {
};
void fatal [[noreturn]] (auto ... args) {
  show_leds(CRGB::White);
  serial_println(FWD(args)...);
  // TODO: reboot
  throw FatalError();
}

struct WiFiError: public std::exception {
};
void wifi_check() {
  if (WiFi.status() != WL_CONNECTED) {
    throw WiFiError();
  }
}

struct ClientError: public std::exception {
};
void client_check() {
  wifi_check();
  if (!client.connected()) {
    throw ClientError();
  }
}

template<auto available>
size_t wait_available() {
  while (true) {
    auto result = (client.*available)();
    if (result > 0) {
      return result;
    }
    yield();
    client_check();
  }
}

template<auto size>
struct Buffer {

  using Array = std::array<char, size>;
  Array array;
  typename Array::iterator begin;
  typename Array::iterator end;

  void reset() {
    begin = end = array.begin();
  }

  void compact() {
    auto zero = array.begin();
    auto readable = this->readable();
    std::memmove(zero, begin, readable);
    begin = zero;
    end = zero + readable;
  }

  size_t readable() const {
    return end - begin;
  }

  size_t writable() const {
    return array.end() - end;
  }

};

Buffer<1024> send_buffer;

void ldap_send(auto const& message) {
  send_buffer.compact();

  struct {
    void write(char c) {
      write({&c, 1});
    }
    void write(std::string_view bytes) {
      if (send_buffer.writable() < bytes.size()) {
        fatal("Send buffer overflow");
      }
      std::memcpy(send_buffer.end, bytes.data(), bytes.size());
      send_buffer.end += bytes.size();
    }
  } writer;
  message.write(writer);

  while (true) {
    auto available = send_buffer.readable();
    if (!available) {
      break;
    }
    available = std::min(available, wait_available<&WiFiClient::availableForWrite>());

    auto written = client.write(reinterpret_cast<uint8_t const*>(send_buffer.begin), available);
    serial_println('>', Hex{send_buffer.begin, written});
    send_buffer.begin += written;
  }
}

Buffer<1024> receive_buffer;

auto ldap_receive(auto expected_message_id) {
  receive_buffer.compact();

  struct {
    std::optional<uint8_t> read() {
      return OPT_TRY(read(1)).front();
    }
    std::optional<std::string_view> read(size_t length) {
      if (receive_buffer.readable() + receive_buffer.writable() < length) {
        fatal("Receive buffer overflow");
      }

      while (receive_buffer.readable() < length) {
        auto available = receive_buffer.writable();
        available = std::min(available, wait_available<&WiFiClient::available>());

        auto read = client.read(reinterpret_cast<uint8_t*>(receive_buffer.end), available);
        serial_println('<', Hex{receive_buffer.end, read});
        receive_buffer.end += read;
      }

      auto result = std::string_view(receive_buffer.begin, length);
      receive_buffer.begin += length;
      return result;
    }
  } reader;

  auto message = LDAP::message.read(reader);
  if (!message) {
    fatal("Expected LDAP message");
  }

  auto [message_id, protocol_op, controls_opt] = *message;
  if (message_id != expected_message_id) {
    fatal("Expected message id ", expected_message_id, " != ", message_id);
  }

  if (controls_opt) {
    serial_println("Got controls");
    auto controls = *controls_opt;
    while (!controls.empty()) {
      auto control = LDAP::control.read(controls);
      if (!control) {
        fatal("Expected control");
      }
      auto [control_type, criticality, control_value] = *control;
      serial_print("Control ", control_type, " ", criticality);
      if (control_value) {
        serial_print(" ", *control_value);
      }
      serial_println();
    }
  }

  return protocol_op;
}

void ldap_bind() {
  auto message_id = 1;

  ldap_send(
    LDAP::message(
      message_id,
      LDAP::bind_request(
        3, // version
        LDAP_LOGIN,
        LDAP::authentication_choice.make<LDAP::AuthenticationChoice::Simple>(
          LDAP_PASSWORD
        )
      ),
      std::nullopt
    )
  );

  auto protocol_op = ldap_receive(message_id);
  if (protocol_op.tag_number != LDAP::ProtocolOp::BindResponse) {
    fatal("Expected bind response ", protocol_op.tag_number);
  }
  auto [result_code, matched_dn, diagnostic_message, referral] = protocol_op.get<LDAP::ProtocolOp::BindResponse>();
  if (result_code != LDAP::ResultCode::Success) {
    fatal("Expected bind response success, got ", result_code, ": ", diagnostic_message);
  }
}

// Search for a LDAP user with the scanned badge NUID
bool ldap_search(std::string_view badgenuid) {
  auto message_id = 2;

  // TODO: add a filter for ptl-active group
  ldap_send(
    LDAP::message(
      message_id,
      LDAP::search_request(
        LDAP_GROUP,
        LDAP::SearchRequestScope::SingleLevel,
        LDAP::SearchRequestDerefAliases::NeverDerefAliases,
        1, // size limit
        0,
        false,
        LDAP::filter.make<LDAP::Filter::ExtensibleMatch>(
          std::nullopt,
          "badgenuid"sv,
          badgenuid,
          std::nullopt
        ),
        LDAP::attribute_selection("cn"sv)
      ),
      std::nullopt
    )
  );

  bool found = false;

  while (true) {
    auto protocol_op = ldap_receive(message_id);
    switch (protocol_op.tag_number) {
    case LDAP::ProtocolOp::SearchResultEntry: {
      found = true;
      auto [object_name, attributes] = protocol_op.get<LDAP::ProtocolOp::SearchResultEntry>();
      serial_println("Object name ", object_name);
      while (!attributes.empty()) {
        auto partial_attribute = LDAP::partial_attribute.read(attributes);
        if (!partial_attribute) {
          fatal("Expected partial attribute");
        }
        auto [type, vals] = *partial_attribute;
        serial_println("Attribute type ", type);
        while (!vals.empty()) {
          auto val = LDAP::attribute_value.read(vals);
          if (!val) {
            fatal("Expected attribute value");
          }
          serial_println("Attribute value ", *val);
        }
      }
      continue;
    }
    case LDAP::ProtocolOp::SearchResultDone: {
      auto [result_code, matched_dn, diagnostic_message, referral] = protocol_op.get<LDAP::ProtocolOp::SearchResultDone>();
      switch (result_code) {
      case LDAP::ResultCode::Success:
      case LDAP::ResultCode::SizeLimitExceeded:
        return found;
      default:
        fatal("Expected search response success, got ", result_code, ": ", diagnostic_message);
      }
    }
    default:
      fatal("Expected search response, got ", protocol_op.tag_number);
    }
  }
}

void loop_with_client() {

  serial_println("binding");
  ldap_bind();
  serial_println("bound");

  while (true) {
    show_leds(CRGB::Blue);
    serial_println("waiting for badge");
    while (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
      yield();
      client_check();
    }

    auto badgenuid = std::string_view(reinterpret_cast<char*>(mfrc522.uid.uidByte), mfrc522.uid.size);
    serial_println("got badge: ", Hex{badgenuid.begin(), badgenuid.size()});

    serial_println("searching");
    auto found = ldap_search(badgenuid);
    serial_println("searched");

    if (!found) {
      show_leds(CRGB::Red);
      serial_println("badge not found");
      delay(2000);
      continue;
    }

    show_leds(CRGB::Green);
    serial_println("badge found, unlocking");
    digitalWrite(RELAY_PIN, HIGH);
    delay(2000);
    serial_println("locking");
    digitalWrite(RELAY_PIN, LOW);
  }

}

void loop_with_wifi() {
  while (true) {

    serial_println("connecting to ", LDAP_HOSTNAME, ':', LDAP_PORT);
    if (!client.connect(LDAP_HOSTNAME, LDAP_PORT)) {
      serial_println("connection failed");
      wifi_check();
      continue;
    }

    serial_println("connected");
    send_buffer.reset();
    receive_buffer.reset();
    try {
      loop_with_client();
    } catch (ClientError&) {
    }

    show_leds(CRGB::Purple);
    serial_println("disconnected");

  }
}

void setup() {
  Serial.begin(115200);
  serial_println();

  // Wait a bit, can help when resetting or reflashing sometimes
  delay(1000);

  FastLED.addLeds<WS2812, D3, GRB>(leds.data(), leds.size());
  show_leds(CRGB::Purple);

  // Init the SPI for the RFID reader
  SPI.begin();
	mfrc522.PCD_Init();
  mfrc522.PCD_DumpVersionToSerial();
  pinMode(RELAY_PIN, OUTPUT);
  digitalWrite(RELAY_PIN, LOW);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  client.setInsecure();
}

void loop() {
  serial_println("Connecting to ", WIFI_SSID);

  while (WiFi.status() != WL_CONNECTED) {
    yield();
  }

  serial_println("WiFi connected, IP: ", WiFi.localIP());

  try {
    loop_with_wifi();
  } catch (WiFiError&) {
  }

  show_leds(CRGB::Purple);
  serial_println("WiFi disconnected");
}
