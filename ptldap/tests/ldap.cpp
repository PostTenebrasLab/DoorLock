#include "../ldap.hpp"

#include <sstream>

#define CATCH_CONFIG_FAST_COMPILE
#include "catch.hpp"

using namespace std;

TEST_CASE("Parse LDAP::DelRequest") {

    auto bytes = "\x30\x35\x02\x01\x05\x4a\x11\x64\x63\x3d\x65\x78\x61\x6d\x70\x6c\x65\x2c\x64\x63\x3d\x63\x6f\x6d\xa0\x1d\x30\x1b\x04\x16\x31\x2e\x32\x2e\x38\x34\x30\x2e\x31\x31\x33\x35\x35\x36\x2e\x31\x2e\x34\x2e\x38\x30\x35\x01\x01\xff"sv;
    auto reader = LDAP::make_reader(BER::make_reader(Bytes::StringViewReader{bytes}));

    auto message = TRY(reader.read_message());
    CHECK(message.message_id == 0x05);
    CHECK(LDAP::tag_number(message.identifier) == LDAP::TagNumber::DelRequest);

    auto del_request = TRY(message.read_del_request());
    CHECK(del_request.dn == "dc=example,dc=com"sv);

    auto controls = TRY(message.read_controls());
    auto control = TRY(controls.read_control());
    CHECK(control.control_type == "1.2.840.113556.1.4.805"sv);
    CHECK(control.criticality == true);
    CHECK(control.control_value == nullopt);

    CHECK(controls.ber.bytes.empty());
    CHECK(message.ber.bytes.empty());
    CHECK(reader.ber.bytes.empty());

    auto writer = LDAP::make_writer(BER::make_writer(Bytes::StringWriter()));
    writer.write_message(0x05, LDAP::DelRequest{"dc=example,dc=com"sv}, LDAP::Control{"1.2.840.113556.1.4.805"sv, true});
    CHECK(writer.ber.bytes.string == bytes);

};
