#include "../ber.hpp"

#include <map>
#include <sstream>

#define CATCH_CONFIG_FAST_COMPILE
#include "catch.hpp"

using namespace std;

TEST_CASE("Read BER::Identifier", "[BER::Identifier]") {

    auto test_identifier = [](string const& section, string_view bytes, BER::TagClass tag_class, BER::Encoding encoding, size_t tag_number) {
        SECTION(section) {
            auto reader = BER::make_reader(Bytes::StringViewReader{bytes});
            auto read = TRY(reader.read_identifier());

            CHECK(read.tag_class == tag_class);
            CHECK(read.encoding == encoding);
            CHECK(read.tag_number == tag_number);
            CHECK(reader.bytes.empty());

            auto writer = BER::make_writer(Bytes::StringWriter());
            writer.write_identifier(read);

            CHECK(writer.bytes.string == bytes);
        }
    };

    test_identifier("simple", "\x02"sv, BER::TagClass::Universal, BER::Encoding::Primitive, BER::TagNumber::Integer);
    test_identifier("constructed", "\x30"sv, BER::TagClass::Universal, BER::Encoding::Constructed, BER::TagNumber::Sequence);
    test_identifier("application", "\x7f\xde\xad\x42"sv, BER::TagClass::Application, BER::Encoding::Constructed, 0x1796c2);

}

void test_length_definite(string const& section, string_view bytes_in, size_t length, string_view bytes_out) {
    SECTION(section) {
        auto reader = BER::make_reader(Bytes::StringViewReader{bytes_in});
        auto read = TRY(reader.read_length());

        CHECK(!read.is_indefinite());
        CHECK(read.length == length);
        CHECK(reader.bytes.empty());

        auto writer = BER::make_writer(Bytes::StringWriter());
        writer.write_length(read);

        CHECK(writer.bytes.string == bytes_out);
    }
};
void test_length_definite(string const& section, string_view bytes, size_t length) {
    test_length_definite(section, bytes, length, bytes);
}

TEST_CASE("Read BER::Length", "[BER::Length]") {

    test_length_definite("Short", "\x7f"sv, 0x7f);
    test_length_definite("Simple Long", "\x81\x01"sv, 1, "\x01");
    test_length_definite("Smol Long", "\x81\xff"sv, 0xff);
    test_length_definite("Normal Long", "\x84\xff\xff\xff\xfe"sv, 0xfffffffe);

    SECTION("Long Long") {
        uint8_t header_size = 1;
        uint8_t data_length_size = 127;

        // Create a string with the first byte (0xff) standing for: long-form, 127 bytes for data length
        // And with 127 bytes of data length, all set to 255 (we are counting all particles in the galaxy quite a few times)
        auto bytes = string(header_size + data_length_size, (char)0xff);
        auto reader = BER::make_reader(Bytes::StringViewReader{bytes});
        auto read = reader.read_length();

        // don't support arbitrary length
        CHECK(!read);
    }

}

TEST_CASE("Write BER::Element", "[BER::Element]") {

    SECTION("Simple Integer") {
        auto writer = BER::make_writer(Bytes::StringWriter());
        writer.write_integer(int32_t(0xdeadbeef));

        CHECK(writer.bytes.string == "\x02\x04\xDE\xAD\xBE\xEF"sv);
    }

}

TEST_CASE("Read BER::Element", "[BER::Element]") {

    SECTION("Simple Integer") {
        auto bytes = "\x02\x04\xDE\xAD\xBE\xEF"sv;
        auto reader = BER::make_reader(Bytes::StringViewReader{bytes});
        auto read = TRY(reader.read_integer<int32_t>());

        CHECK(read == 0xdeadbeef);
        CHECK(reader.bytes.empty());
    }

    SECTION("Simple string") {
        auto bytes = "\x04\x05hello"sv;
        auto reader = BER::make_reader(Bytes::StringViewReader{bytes});
        auto read = TRY(reader.read_octet_string());

        CHECK(read == "hello"sv);
        CHECK(reader.bytes.empty());
    }

}

TEST_CASE("Build BER::UniversalElement", "[BER::UniversalElement]") {

    SECTION("Null") {
        SECTION("Parse a valid null BER element") {
            auto bytes = "\x05\x00"sv;
            auto reader = BER::make_reader(Bytes::StringViewReader{bytes});

            CHECK(reader.read_null());
            CHECK(reader.bytes.empty());
        }

        SECTION("Parse an invalid null BER element") {
            auto bytes = "\x05\x01"sv;
            auto reader = BER::make_reader(Bytes::StringViewReader{bytes});

            CHECK(!reader.read_null());
            CHECK(reader.bytes.empty());
        }

        SECTION("Build a null BER element") {
            auto writer = BER::make_writer(Bytes::StringWriter());
            writer.write_null();

            CHECK(writer.bytes.string == "\x05\x00"sv);
        }
    }

    SECTION("Boolean") {
        SECTION("Parse a valid boolean BER element") {
            auto bytes = "\x01\x01\x01"sv;
            auto reader = BER::make_reader(Bytes::StringViewReader{bytes});
            auto read = TRY(reader.read_boolean());

            CHECK(read == true);
            CHECK(reader.bytes.empty());
        }

        SECTION("Parse an invalid boolean with data shorter than the length from the header") {
            auto bytes = "\x01\x02\x01"sv;
            auto reader = BER::make_reader(Bytes::StringViewReader{bytes});

            CHECK(!reader.read_boolean());
        }

        SECTION("Build a boolean BER element") {
            auto writer = BER::make_writer(Bytes::StringWriter());
            writer.write_boolean(true);

            CHECK(writer.bytes.string == "\x01\x01\xff"sv);
        }
    }

    SECTION("Integers") {
        auto check_length = [](int32_t value, int length) {
            auto writer = BER::make_writer(Bytes::StringWriter());
            writer.write_integer(value);
            CHECK(writer.bytes.string.size() == 2 + length);

            auto reader = BER::make_reader(Bytes::StringViewReader{writer.bytes.string});
            auto read = TRY(reader.template read_integer<int32_t>());
            CHECK(read == value);
            CHECK(reader.bytes.empty());
        };
        // Run the test at the limits
        check_length(INT32_MIN, 4);
        check_length(-(1 << 23) - 1, 4);
        check_length(-(1 << 23), 3);
        check_length(-(1 << 15) - 1, 3);
        check_length(-(1 << 15), 2);
        check_length(-(1 << 7) - 1, 2);
        check_length(-(1 << 7), 1);
        check_length(-1, 1);
        check_length(0, 1);
        check_length(1, 1);
        check_length((1 << 7) - 1, 1);
        check_length((1 << 7), 2);
        check_length((1 << 15) - 1, 2);
        check_length((1 << 15), 3);
        check_length((1 << 23) - 1, 3);
        check_length((1 << 23), 4);
        check_length(INT32_MAX, 4);

        auto check_bytes = [](int32_t value, string_view bytes_expected) {
            SECTION(to_string(value)) {
                auto writer = BER::make_writer(Bytes::StringWriter());
                writer.write_integer(value);
                CHECK(writer.bytes.string == bytes_expected);

                auto reader = BER::make_reader(Bytes::StringViewReader{writer.bytes.string});
                auto read = TRY(reader.template read_integer<int32_t>());
                CHECK(read == value);
                CHECK(reader.bytes.empty());
            }
        };
        // Some more tests from values here: http://luca.ntop.org/Teaching/Appunti/asn1.html
        check_bytes(0, "\x02\x01\x00"sv);
        check_bytes(127, "\x02\x01\x7F"sv);
        check_bytes(128, "\x02\x02\x00\x80"sv);
        check_bytes(256, "\x02\x02\x01\x00"sv);
        check_bytes(-128, "\x02\x01\x80"sv);
        check_bytes(-129, "\x02\x02\xFF\x7F"sv);
    }

    SECTION("Sequence") {
        auto bytes = "\x30\x06\x01\x01\xff\x02\x01\x42"sv;
        auto reader = BER::make_reader(Bytes::StringViewReader{bytes});
        auto sequence = TRY(reader.read_sequence());
        auto element1 = TRY(sequence.read_boolean());
        auto element2 = TRY(sequence.template read_integer<uint8_t>());

        CHECK(element1 == true);
        CHECK(element2 == 0x42);
        CHECK(sequence.bytes.empty());
        CHECK(reader.bytes.empty());
    }

};
