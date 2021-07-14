// ISO/IEC 8825-1:2015
// ASN.1 encoding rules: Specification of Basic Encoding Rules (BER),
// Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)
// https://www.iso.org/standard/68345.html
// https://standards.iso.org/ittf/PubliclyAvailableStandards/c068345_ISO_IEC_8825-1_2015.zip

// Wireshark implementation
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-ldap.c

// A Layman's Guide to a Subset of ASN.1, BER, and DER
// http://luca.ntop.org/Teaching/Appunti/asn1.html

// LDAPv3 Wire Protocol Reference: The ASN.1 Basic Encoding Rules
// https://ldap.com/ldapv3-wire-protocol-reference-asn1-ber/

#include "bytes.hpp"
#include <limits>

namespace BER {

    enum TagClass {
        Universal = 0b00,
        Application = 0b01,
        ContextSpecific = 0b10,
        Private = 0b11,
    };

    enum Encoding {
        Primitive = 0b0,
        Constructed = 0b1,
    };

    enum TagNumber {
        Boolean = 0x01,
        Integer = 0x02,
        BitString = 0x03,
        OctetString = 0x04,
        Null = 0x05,
        ObjectIdentifier = 0x06,
        Sequence = 0x10,
        SequenceOf = 0x10,
        Set = 0x11,
        SetOf = 0x11,
        PrintableString = 0x13,
        T61String = 0x14,
        IA5String = 0x16,
        UTCTime = 0x17,
        ExtendedType = 0x1F,
    };

    struct Identifier {
        TagClass tag_class;
        Encoding encoding;
        size_t tag_number;
    };

    enum LengthForm {
        Short = 0b0,
        Long = 0b1,
    };

    constexpr uint8_t LengthIndefinite = 0b0000000;

    struct Length {
        size_t length;
        bool is_indefinite() const {
            return length == SIZE_MAX;
        }
        explicit Length(size_t length): length(length) {}
        explicit Length(): length(SIZE_MAX) {}
    };

    template<typename T>
    uint8_t count_bits(T value) {
        if (value < 0) value = ~value;

        auto bits = uint8_t{0};
        while (value) {
            ++bits;
            value >>= 1;
        }
        return bits;
    }

    template<typename Bytes>
    struct Reader {

        Bytes bytes;

        std::optional<Identifier> read_identifier() {
            auto byte = OPT_TRY(bytes.read());
            auto tag_class = TagClass((byte & 0b11000000) >> 6);
            auto encoding = Encoding((byte & 0b00100000) >> 5);
            auto tag_number = size_t((byte & 0b00011111) >> 0);

            if (tag_number == TagNumber::ExtendedType) {
                tag_number = 0;
                do {
                    byte = OPT_TRY(bytes.read());
                    tag_number = (tag_number << 7) | ((byte & 0b01111111) >> 0);
                } while ((byte & 0b10000000) >> 7);
            }
            return Identifier{tag_class, encoding, tag_number};
        }

        std::optional<Length> read_length() {
            auto byte = OPT_TRY(bytes.read());

            auto form = (byte & 0b10000000) >> 7;
            if (form == LengthForm::Short) {
                return Length(byte);
            }

            auto count = (byte & 0b01111111) >> 0;
            if (count == LengthIndefinite) {
                return Length();
            }
            OPT_REQUIRE(count <= sizeof(size_t));

            auto length = size_t{0};
            for (auto i = 0u; i < count; ++i) {
                byte = OPT_TRY(bytes.read());
                length = (length << 8) | byte;
            }
            OPT_REQUIRE(length != SIZE_MAX);
            return Length(length);
        }

        template<typename T>
        std::optional<T> read_integer() {
            auto identifier = OPT_TRY(read_identifier());
            OPT_REQUIRE(identifier.tag_class == TagClass::Universal);
            OPT_REQUIRE(identifier.encoding == Encoding::Primitive);
            OPT_REQUIRE(identifier.tag_number == TagNumber::Integer);

            auto length = OPT_TRY(read_length()).length;
            OPT_REQUIRE(length > 0);

            auto first = int8_t(OPT_TRY(bytes.read()));
            if (std::is_unsigned<T>::value && first == 0) {
                OPT_REQUIRE(length - 1 <= sizeof(T));
            } else {
                OPT_REQUIRE(length <= sizeof(T));
            }

            auto value = T(first);
            for (auto shifts = length - 1; shifts; --shifts) {
                auto byte = OPT_TRY(bytes.read());
                value <<= 8;
                value |= byte;
            }
            return std::move(value);
        }

        std::optional<nullptr_t> read_null() {
            auto identifier = OPT_TRY(read_identifier());
            OPT_REQUIRE(identifier.tag_class == TagClass::Universal);
            OPT_REQUIRE(identifier.encoding == Encoding::Primitive);
            OPT_REQUIRE(identifier.tag_number == TagNumber::Null);

            auto length = OPT_TRY(read_length());
            OPT_REQUIRE(length.length == 0);

            return nullptr;
        }

        std::optional<bool> read_boolean() {
            auto identifier = OPT_TRY(read_identifier());
            OPT_REQUIRE(identifier.tag_class == TagClass::Universal);
            OPT_REQUIRE(identifier.encoding == Encoding::Primitive);
            OPT_REQUIRE(identifier.tag_number == TagNumber::Boolean);

            auto length = OPT_TRY(read_length());
            OPT_REQUIRE(length.length == 1);

            return OPT_TRY(bytes.read());
        }

        std::optional<nonstd::string_view> read_octet_string() {
            auto identifier = OPT_TRY(read_identifier());
            OPT_REQUIRE(identifier.tag_class == TagClass::Universal);
            OPT_REQUIRE(identifier.encoding == Encoding::Primitive);
            OPT_REQUIRE(identifier.tag_number == TagNumber::OctetString);

            return read_octet_string(identifier);
        }

        std::optional<nonstd::string_view> read_octet_string(Identifier const& identifier) {
            OPT_REQUIRE(identifier.encoding == Encoding::Primitive);

            auto length = OPT_TRY(read_length());
            OPT_REQUIRE(!length.is_indefinite());

            return bytes.read(length.length);
        }

        std::optional<Reader<Bytes>> read_sequence() {
            auto identifier = OPT_TRY(read_identifier());
            OPT_REQUIRE(identifier.tag_class == TagClass::Universal);
            OPT_REQUIRE(identifier.encoding == Encoding::Constructed);
            OPT_REQUIRE(identifier.tag_number == TagNumber::Sequence);

            return read_sequence(identifier);
        }

        std::optional<Reader<Bytes>> read_sequence(Identifier const& identifier) {
            auto length = OPT_TRY(read_length());
            OPT_REQUIRE(!length.is_indefinite());

            return Reader<Bytes>{OPT_TRY(bytes.reader(length.length))};
        }

    };

    template<typename Bytes>
    auto make_reader(Bytes bytes) {
        return Reader<Bytes>{std::move(bytes)};
    }

    struct BytesCounter {

        size_t count = 0;

        void write(uint8_t byte) {
            ++count;
        }

        void write(std::string_view bytes) {
            count += bytes.size();
        }

    };

    template<typename Bytes>
    struct Writer {

        Bytes bytes;

        void write_identifier(Identifier const& identifier) {
            auto is_low_tag_number = identifier.tag_number < TagNumber::ExtendedType;
            auto tag_number = is_low_tag_number ? identifier.tag_number : TagNumber::ExtendedType;
            bytes.write((identifier.tag_class << 6) | (identifier.encoding << 5) | (tag_number << 0));
            if (is_low_tag_number) return;

            auto shifts = (count_bits(identifier.tag_number) - 1) / 7;
            for (auto shift = shifts * 7; shift; shift -= 7) {
                bytes.write(0b10000000 | (identifier.tag_number >> shift) & 0b01111111);
            }
            bytes.write(0b00000000 | (identifier.tag_number & 0b01111111));
        }

        void write_length(Length const& length) {
            if (length.is_indefinite()) {
                auto count = LengthIndefinite;
                bytes.write((LengthForm::Long << 7) | (count << 0));
                return;
            }

            auto count = length.length;
            if (count <= 0b01111111) {
                bytes.write((LengthForm::Short << 7) | (count << 0));
                return;
            }

            auto shifts = (count_bits(count) - 1) / 8;
            auto length_length = shifts + 1;
            bytes.write((LengthForm::Long << 7) | (length_length << 0));
            for (auto shift = shifts * 8; shift; shift -= 8) {
                bytes.write((count >> shift) & 0b11111111);
            }
            bytes.write(count & 0b11111111);
        }

        void write_null() {
            write_identifier(Identifier{TagClass::Universal, Encoding::Primitive, TagNumber::Null});
            write_length(Length(0));
        }

        void write_boolean(bool value, uint8_t true_byte = 0xff) {
            write_identifier(Identifier{TagClass::Universal, Encoding::Primitive, TagNumber::Boolean});
            write_length(Length(1));
            bytes.write(value ? true_byte : 0x00);
        }

        template<typename T>
        void write_integer(T value) {
            write_identifier(Identifier{TagClass::Universal, Encoding::Primitive, TagNumber::Integer});

            auto shifts = count_bits(value) / 8;
            write_length(Length(shifts + 1));
            for (auto shift = shifts * 8; shift; shift -= 8) {
                bytes.write((value >> shift) & 0b11111111);
            }
            bytes.write(value & 0b11111111);
        }

        template<typename ... Datas>
        void write_sequence(Datas const& ... datas) {
            write_identifier(Identifier{TagClass::Universal, Encoding::Constructed, TagNumber::Sequence});
            auto counter = Writer<BytesCounter>{BytesCounter()};
            counter.write_datas(datas...);
            write_length(Length(counter.bytes.count));
            write_datas(datas...);
        }

        template<typename ... Datas>
        void write_datas() {
        }

        template<typename Data, typename ... Datas>
        void write_datas(Data const& data, Datas const& ... datas) {
            write_data(*this, data);
            write_datas(datas...);
        }

        template<typename Datas>
        void write_sequence_container(Identifier const& identifier, Datas const& datas) {
            write_identifier(identifier);
            auto counter = Writer<BytesCounter>{BytesCounter()};
            counter.write_datas_container(datas);
            write_length(Length(counter.bytes.count));
            write_datas_container(datas);
        }

        template<typename Datas>
        void write_datas_container(Datas const& datas) {
            for (auto const& data : datas) {
                write_data(*this, data);
            }
        }

        void write_octet_string(std::string_view string) {
            write_octet_string(Identifier{TagClass::Universal, Encoding::Primitive, TagNumber::OctetString}, string);
        }

        void write_octet_string(Identifier const& identifier, std::string_view string) {
            write_identifier(identifier);
            write_length(Length(string.size()));
            bytes.write(string);
        }

    };

    template<typename Writer>
    void write_data(Writer& writer, bool b) {
        writer.write_boolean(b);
    }

    template<typename Writer, typename Integer>
    std::enable_if_t<std::is_integral<Integer>::value> write_data(Writer& writer, Integer integer) {
        writer.write_integer(integer);
    }

    template<typename Writer>
    void write_data(Writer& writer, std::string_view string) {
        writer.write_octet_string(string);
    }

    template<typename Bytes>
    auto make_writer(Bytes bytes) {
        return Writer<Bytes>{std::move(bytes)};
    }

}
