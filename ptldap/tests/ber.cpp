#include "../ber.hpp"

#include "catch.hpp"
#include "tools.hpp"

using namespace std::literals::string_view_literals;
using namespace BER;

bool operator==(Bytes::StringViewReader const& left, Bytes::StringViewReader const& right) {
    return left.string == right.string;
}

template<auto encoding, auto tag_class, auto tag_number>
auto identifier_write_read(auto&& bytes) {
    auto expected = StaticIdentifier<encoding, tag_class, tag_number>{};

    auto writer = Bytes::StringWriter();
    expected.write(writer);
    check_bytes(writer.string, bytes);

    auto reader = Bytes::StringViewReader{bytes};
    auto actual = TRY(decltype(expected)::read(reader));
    CHECK(expected == actual);
    check_bytes(reader.string, ""sv);
};

TEST_CASE("Identifier") {

    identifier_write_read<Encoding::Primitive, TagClass::Universal, decltype(integer.identifier)::dynamic.tag_number>("\x02"sv);
    identifier_write_read<Encoding::Constructed, TagClass::Universal, 0x10>("\x30"sv);
    identifier_write_read<Encoding::Constructed, TagClass::Application, 0x1796c2>("\x7f\xde\xad\x42"sv);

}

void length_read(auto&& bytes, auto&& length) {
    auto reader = Bytes::StringViewReader{bytes};
    CHECK(TRY(Length::read(reader)).length == Length(FWD(length)).length);
    check_bytes(reader.string, ""sv);
};
void length_write_read(auto&& bytes, auto&& length) {
    auto writer = Bytes::StringWriter();
    Length(length).write(writer);
    check_bytes(writer.string, bytes);

    length_read(bytes, length);
};

TEST_CASE("Length") {

    SECTION("definite") {
        length_write_read("\x7f"sv, 0x7f);
        length_write_read("\x01"sv, 1);
        length_read("\x81\x01"sv, 1);
        length_write_read("\x81\xff"sv, 0xff);
        length_write_read("\x84\xff\xff\xff\xfe"sv, 0xfffffffe);
    }

    SECTION("overflow") {
        uint8_t header_size = 1;
        uint8_t data_length_size = 127;

        // Create a string with the first byte (0xff) standing for: long-form, 127 bytes for data length
        // And with 127 bytes of data length, all set to 255 (we are counting all particles in the galaxy quite a few times)
        auto bytes = std::string(header_size + data_length_size, (char)0xff);
        auto reader = Bytes::StringViewReader{bytes};

        // we don't support arbitrary length
        CHECK(!Length::read(reader));
    }

}

auto type_write(auto&& type, auto&& bytes, auto&&... value) {
    auto writer = Bytes::StringWriter();
    FWD(type)(FWD(value)...).write(writer);
    check_bytes(writer.string, FWD(bytes));
}
auto type_read(auto&& type, auto&& bytes, auto&& value, auto&& remainder) {
    auto reader = Bytes::StringViewReader{FWD(bytes)};
    auto actual = TRY(FWD(type).read(reader));
    CHECK(actual == FWD(value));
    check_bytes(reader.string, remainder);
}
auto type_read(auto&& type, auto&& bytes, auto&& value) {
    type_read(FWD(type), FWD(bytes), FWD(value), ""sv);
}
auto type_write_read(auto&& type, auto&& bytes, auto&& value) {
    type_write(FWD(type), FWD(bytes), FWD(value));
    type_read(FWD(type), FWD(bytes), FWD(value));
}
auto type_read_fail(auto&& type, auto&& bytes, auto&& remainder) {
    auto reader = Bytes::StringViewReader{bytes};
    CHECK(!FWD(type).read(reader));
    check_bytes(reader.string, remainder);
}
auto type_read_fail(auto&& type, auto&& bytes) {
    type_read_fail(FWD(type), FWD(bytes), ""sv);
}

TEST_CASE("primitives") {

    type_write_read(boolean, "\x01\x01\x00"sv, false);
    type_write_read(boolean, "\x01\x01\xff"sv, true);
    type_read(boolean, "\x01\x01\x01"sv, true);
    type_read_fail(boolean, "\x01\x02\x01\x42"sv);
    type_write_read(integer, "\x02\x04\x80\x00\x00\x00"sv, INT32_MIN);
    type_write_read(integer, "\x02\x04\xDE\xAD\xBE\xEF"sv, signed(0xdeadbeef));
    type_write_read(integer, "\x02\x04\xff\x7f\xff\xff"sv, -(1 << 23) - 1);
    type_write_read(integer, "\x02\x03\x80\x00\x00"sv, -(1 << 23));
    type_write_read(integer, "\x02\x03\xff\x7f\xff"sv, -(1 << 15) - 1);
    type_write_read(integer, "\x02\x02\x80\x00"sv, -(1 << 15));
    type_write_read(integer, "\x02\x02\xFF\x7F"sv, -129);
    type_write_read(integer, "\x02\x01\x80"sv, -128);
    type_write_read(integer, "\x02\x01\xFF"sv, -1);
    type_write_read(integer, "\x02\x01\x00"sv, 0);
    type_write_read(integer, "\x02\x01\x01"sv, 1);
    type_write_read(integer, "\x02\x01\x7F"sv, (1 << 7) - 1);
    type_write_read(integer, "\x02\x02\x00\x80"sv, (1 << 7));
    type_write_read(integer, "\x02\x02\x01\x00"sv, 256);
    type_write_read(integer, "\x02\x02\x7f\xff"sv, (1 << 15) - 1);
    type_write_read(integer, "\x02\x03\x00\x80\x00"sv, (1 << 15));
    type_write_read(integer, "\x02\x03\x7f\xff\xff"sv, (1 << 23) - 1);
    type_write_read(integer, "\x02\x04\x00\x80\x00\x00"sv, (1 << 23));
    type_write_read(integer, "\x02\x04\x7f\xff\xff\xff"sv, INT32_MAX);
    type_write_read(octet_string, "\x04\x05hello"sv, "hello"sv);
    type_write_read(null, "\x05\x00"sv, nullptr);
    type_read_fail(null, "\x05\x01\x00"sv);
    type_write_read(explicit_(null), "\x20\x02\x05\x00"sv, nullptr);

}

TEST_CASE("sequence") {

    type_write(sequence(boolean), "\x30\x03\x01\x01\x00"sv, false);
    type_write(sequence(boolean, boolean), "\x30\x06\x01\x01\x00\x01\x01\xff"sv, false, true);
    type_write(sequence(boolean, integer), "\x30\x06\x01\x01\x00\x02\x01\x2a"sv, false, 42);
    type_read(sequence(boolean), "\x30\x03\x01\x01\x00"sv, std::tuple(false));
    type_read(sequence(boolean, boolean), "\x30\x06\x01\x01\x00\x01\x01\xff"sv, std::tuple(false, true));
    type_read(sequence(boolean, integer), "\x30\x06\x01\x01\x00\x02\x01\x2a"sv, std::tuple(false, 42));
    type_read_fail(sequence(boolean), "\x30\x02\x01\x01\x00"sv, "\x00"sv);
    type_read_fail(sequence(boolean), "\x30\x04\x01\x01\x00"sv, "\x01\x01\x00"sv);
    type_read_fail(sequence(boolean), "\x30\x04\x01\x01\x00\x00"sv);

}

TEST_CASE("sequence_of") {

    type_write(sequence_of(boolean), "\x30\x03\x01\x01\x00"sv, false);
    type_write(sequence_of(boolean), "\x30\x06\x01\x01\x00\x01\x01\xff"sv, false, true);
    type_read(sequence_of(boolean), "\x30\x03\x01\x01\x00"sv, Bytes::StringViewReader{"\x01\x01\x00"sv});
    type_read(sequence_of(boolean), "\x30\x02\x01\x01\x00"sv, Bytes::StringViewReader{"\x01\x01"sv}, "\x00"sv);
    type_read_fail(sequence_of(boolean), "\x30\x04\x01\x01\x00"sv, "\x01\x01\x00"sv);
    type_read(sequence_of(boolean), "\x30\x04\x01\x01\x00\x00"sv, Bytes::StringViewReader{"\x01\x01\x00\x00"sv});

}

auto optional_read_fail(auto&& type, auto&& bytes) {
    auto reader = Bytes::StringViewReader{bytes};
    auto actual = TRY(FWD(type).read(reader));
    CHECK(!actual.has_value());
    // expect unconsumed input
    check_bytes(reader.string, bytes);
}

TEST_CASE("optional") {

    type_write_read(optional(boolean), "\x01\x01\x00"sv, std::optional(false));
    type_write_read(optional(boolean), "\x01\x01\xff"sv, std::optional(true));
    type_write_read(optional(boolean), ""sv, std::optional<bool>());
    optional_read_fail(optional(boolean), "\x02\x01\x00"sv);
    type_write(optional(boolean), ""sv, std::nullopt);
    type_write(optional(boolean), "\x01\x01\x00"sv, false);

}

template<auto tag_number>
auto choice_read(auto const& type, auto&& value) {
    using Read = std::decay_t<decltype(*type.read(std::declval<Bytes::StringViewReader&>()))>;
    constexpr auto i = std::decay_t<decltype(type)>::template index_of<tag_number>();
    return Read::template indexed<i>(FWD(value));
}

TEST_CASE("choice") {

    SECTION("int") {
        auto type = choice().with<5>(boolean).with<7>(integer);
        type_write(type, "\x85\x01\x00"sv, type.make<5>(false));
        type_read(type, "\x85\x01\x00"sv, choice_read<5>(type, false));
    }

    SECTION("enum") {
        enum class Enum {
            Bool = 1,
            Int1 = 2,
            Int2 = 3,
        };
        auto type = choice<Enum>()
            .with<Enum::Bool>(boolean)
            .with<Enum::Int1>(integer)
            .with<Enum::Int2>(integer);
        type_write(type, "\x81\x01\xff"sv, type.make<Enum::Bool>(true));
        type_write(type, "\x82\x01\x2a"sv, type.make<Enum::Int1>(42));
        type_write(type, "\x83\x01\x2a"sv, type.make<Enum::Int2>(42));
        type_read(type, "\x81\x01\xff"sv, choice_read<Enum::Bool>(type, true));
        type_read(type, "\x82\x01\x2a"sv, choice_read<Enum::Int1>(type, 42));
        type_read(type, "\x83\x01\x2a"sv, choice_read<Enum::Int2>(type, 42));
    }

    SECTION("read") {
        auto type = choice().with<5>(octet_string).with<7>(integer);
        auto read = choice_read<7>(type, 42);
        CHECK(read.tag_number == 7);
        CHECK(read.get<7>() == 42);
    }

}

TEST_CASE("enumerated") {

    enum class Enum {
        Bool = 41,
        Int1 = 42,
        Int2 = 43,
    };
    type_write_read(enumerated<Enum>(), "\x0a\x01\x29"sv, Enum::Bool);

}
