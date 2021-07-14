// Lightweight Directory Access Protocol (LDAP): The Protocol
// https://datatracker.ietf.org/doc/html/rfc4511

// LDAPv3 Wire Protocol Reference
// https://ldap.com/ldapv3-wire-protocol-reference/

#include "ber.hpp"

namespace LDAP {

    enum class TagNumber {
        Controls = 0,
        DelRequest = 10,
    };

    struct DelRequest {
        std::string_view dn;
    };

    struct Control {
        std::string_view control_type;
        bool criticality;
        std::optional<std::string_view> control_value;
    };

    template<typename BERReader>
    struct ControlsReader {

        BERReader ber;

        std::optional<Control> read_control() {
            auto sequence = OPT_TRY(ber.read_sequence());
            auto control_type = OPT_TRY(sequence.read_octet_string());
            auto criticality = OPT_TRY(sequence.read_boolean());

            if (sequence.bytes.empty()) {
                return Control{control_type, criticality, std::nullopt};
            }
            auto control_value = OPT_TRY(sequence.read_octet_string());

            OPT_REQUIRE(sequence.bytes.empty());
            return Control{control_type, criticality, control_value};
        }

    };

    TagNumber tag_number(BER::Identifier const& identifier) {
        return static_cast<TagNumber>(identifier.tag_number);
    }

    template<typename BERReader>
    struct MessageReader {

        int32_t message_id;
        BER::Identifier identifier;
        BERReader ber;

        std::optional<DelRequest> read_del_request() {
            OPT_REQUIRE(tag_number(identifier) == TagNumber::DelRequest);
            OPT_REQUIRE(identifier.encoding == BER::Encoding::Primitive);
            auto dn = OPT_TRY(ber.read_octet_string(identifier));
            return DelRequest{dn};
        }

        std::optional<ControlsReader<BERReader>> read_controls() {
            auto identifier = OPT_TRY(ber.read_identifier());
            OPT_REQUIRE(identifier.tag_class == BER::TagClass::ContextSpecific);
            OPT_REQUIRE(identifier.encoding == BER::Encoding::Constructed);
            OPT_REQUIRE(tag_number(identifier) == TagNumber::Controls);

            auto sequence = OPT_TRY(ber.read_sequence(identifier));
            return ControlsReader<BERReader>{std::move(sequence)};
        }

    };

    template<typename BERReader>
    struct Reader {

        BERReader ber;

        std::optional<MessageReader<BERReader>> read_message() {
            auto sequence = OPT_TRY(ber.read_sequence());

            auto message_id = OPT_TRY(sequence.template read_integer<int32_t>());
            OPT_REQUIRE(message_id >= 0);

            auto identifier = OPT_TRY(sequence.read_identifier());
            OPT_REQUIRE(identifier.tag_class == BER::TagClass::Application);

            return MessageReader<BERReader>{message_id, identifier, std::move(sequence)};
        }

    };

    template<typename BERReader>
    auto make_reader(BERReader ber) {
        return Reader<BERReader>{std::move(ber)};
    }

    template<typename BERWriter>
    struct Writer {

        BERWriter ber;

        template<typename ProtocolOp>
        void write_message(int32_t message_id, ProtocolOp const& protocol_op) {
            ber.write_sequence(message_id, protocol_op);
        }

        template<typename ProtocolOp, typename ... Controls>
        void write_message(int32_t message_id, ProtocolOp const& protocol_op, Controls const& ... controls) {
            ber.write_sequence(message_id, protocol_op, std::initializer_list{controls...});
        }

    };

    template<typename BERWriter>
    auto make_writer(BERWriter ber) {
        return Writer<BERWriter>{std::move(ber)};
    }

    BER::Identifier identifier(BER::TagClass tag_class, BER::Encoding encoding, TagNumber tag_number) {
        return {tag_class, encoding, static_cast<BER::TagNumber>(tag_number)};
    }

}

namespace BER {

    template<typename Writer>
    void write_data(Writer& writer, LDAP::DelRequest const& request) {
        writer.write_octet_string(LDAP::identifier(BER::TagClass::Application, BER::Encoding::Primitive, LDAP::TagNumber::DelRequest), request.dn);
    }

    template<typename Writer>
    void write_data(Writer& writer, std::initializer_list<LDAP::Control> const& controls) {
        writer.write_sequence_container(LDAP::identifier(BER::TagClass::ContextSpecific, BER::Encoding::Constructed, LDAP::TagNumber::Controls), controls);
    }

    template<typename Writer>
    void write_data(Writer& writer, LDAP::Control const& control) {
        if (control.control_value) {
            writer.write_sequence(control.control_type, control.criticality, *control.control_value);
        } else {
            writer.write_sequence(control.control_type, control.criticality);
        }
    }

}
