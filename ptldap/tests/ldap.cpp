#include "../ldap.hpp"

#include "catch.hpp"
#include "tools.hpp"

using namespace std;

TEST_CASE("ldap.com") {
    // Examples from https://ldap.com/ldapv3-wire-protocol-reference/

    SECTION("message") {
        // Example from https://ldap.com/ldapv3-wire-protocol-reference-ldap-message/
        auto bytes = "\x30\x35\x02\x01\x05\x4a\x11\x64\x63\x3d\x65\x78\x61\x6d\x70\x6c\x65\x2c\x64\x63\x3d\x63\x6f\x6d\xa0\x1d\x30\x1b\x04\x16\x31\x2e\x32\x2e\x38\x34\x30\x2e\x31\x31\x33\x35\x35\x36\x2e\x31\x2e\x34\x2e\x38\x30\x35\x01\x01\xff"sv;

        SECTION("write") {
            auto writer = Bytes::StringWriter();
            LDAP::message(0x05, LDAP::del_request("dc=example,dc=com"sv), LDAP::controls(LDAP::control("1.2.840.113556.1.4.805"sv, true, std::nullopt))).write(writer);
            check_bytes(writer.string, bytes);
        }

        SECTION("read") {
            auto reader = Bytes::StringViewReader{bytes};

            auto [message_id, protocol_op, controls_opt] = TRY(LDAP::message.read(reader));
            CHECK(message_id == 0x05);
            CHECK(protocol_op.tag_number == LDAP::ProtocolOp::DelRequest);

            auto del_request = protocol_op.get<LDAP::ProtocolOp::DelRequest>();
            CHECK(del_request == "dc=example,dc=com"sv);

            auto controls = TRY(controls_opt);
            auto [control_type, criticality, control_value] = TRY(LDAP::control.read(controls));
            CHECK(control_type == "1.2.840.113556.1.4.805"sv);
            CHECK(criticality == true);
            CHECK(control_value == nullopt);
            check_bytes(controls.string, ""sv);

            check_bytes(reader.string, ""sv);
        }

    }

    SECTION("bind request") {
        // Example from https://ldap.com/ldapv3-wire-protocol-reference-bind/
        auto bytes = "\x30\x39\x02\x01\x01\x60\x34\x02\x01\x03\x04\x24\x75\x69\x64\x3d\x6a\x64\x6f\x65\x2c\x6f\x75\x3d\x50\x65\x6f\x70\x6c\x65\x2c\x64\x63\x3d\x65\x78\x61\x6d\x70\x6c\x65\x2c\x64\x63\x3d\x63\x6f\x6d\x80\x09\x73\x65\x63\x72\x65\x74\x31\x32\x33"sv;

        SECTION("write") {
            auto writer = Bytes::StringWriter();
            LDAP::message(0x01, LDAP::bind_request(3, "uid=jdoe,ou=People,dc=example,dc=com"sv, LDAP::authentication_choice.make<LDAP::AuthenticationChoice::Simple>("secret123"sv)), std::nullopt).write(writer);
            check_bytes(writer.string, bytes);
        }

        SECTION("read") {
            auto reader = Bytes::StringViewReader{bytes};

            auto [message_id, protocol_op, controls_opt] = TRY(LDAP::message.read(reader));
            CHECK(message_id == 0x01);
            CHECK(protocol_op.tag_number == LDAP::ProtocolOp::BindRequest);

            auto [version, name, authentication] = protocol_op.get<LDAP::ProtocolOp::BindRequest>();
            CHECK(version == 3);
            CHECK(name == "uid=jdoe,ou=People,dc=example,dc=com"sv);
            CHECK(authentication.tag_number == LDAP::AuthenticationChoice::Simple);

            auto simple = authentication.get<LDAP::AuthenticationChoice::Simple>();
            CHECK(simple == "secret123"sv);

            CHECK(controls_opt == std::nullopt);

            check_bytes(reader.string, ""sv);
        }

    }

    SECTION("bind response") {
        // Example from https://ldap.com/ldapv3-wire-protocol-reference-bind/
        auto bytes = "\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00"sv;

        SECTION("write") {
            auto writer = Bytes::StringWriter();
            LDAP::message(0x01, LDAP::bind_response(LDAP::ResultCode::Success, ""sv, ""sv, std::nullopt), std::nullopt).write(writer);
            check_bytes(writer.string, bytes);
        }

        SECTION("read") {
            auto reader = Bytes::StringViewReader{bytes};

            auto [message_id, protocol_op, controls_opt] = TRY(LDAP::message.read(reader));
            CHECK(message_id == 0x01);
            CHECK(protocol_op.tag_number == LDAP::ProtocolOp::BindResponse);

            auto [result_code, matched_dn, diagnostic_message, referral] = protocol_op.get<LDAP::ProtocolOp::BindResponse>();
            CHECK(result_code == LDAP::ResultCode::Success);
            CHECK(matched_dn == ""sv);
            CHECK(diagnostic_message == ""sv);
            CHECK(referral == std::nullopt);

            CHECK(controls_opt == std::nullopt);

            check_bytes(reader.string, ""sv);
        }

    }

    SECTION("search request") {
        // Example from https://ldap.com/ldapv3-wire-protocol-reference-search/
        auto bytes = "\x30\x56\x02\x01\x02\x63\x51\x04\x11\x64\x63\x3d\x65\x78\x61\x6d\x70\x6c\x65\x2c\x64\x63\x3d\x63\x6f\x6d\x0a\x01\x02\x0a\x01\x00\x02\x02\x03\xe8\x02\x01\x1e\x01\x01\x00\xa0\x24\xa3\x15\x04\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73\x04\x06\x70\x65\x72\x73\x6f\x6e\xa3\x0b\x04\x03\x75\x69\x64\x04\x04\x6a\x64\x6f\x65\x30\x06\x04\x01\x2a\x04\x01\x2b"sv;

        SECTION("write") {
            auto writer = Bytes::StringWriter();
            LDAP::message(
                0x02,
                LDAP::search_request(
                    "dc=example,dc=com"sv,
                    LDAP::SearchRequestScope::WholeSubtree,
                    LDAP::SearchRequestDerefAliases::NeverDerefAliases,
                    1000, 30, false,
                    LDAP::filter.make<LDAP::Filter::And>(
                        LDAP::filter.make<LDAP::Filter::EqualityMatch>(
                            "objectClass"sv,
                            "person"sv
                        ),
                        LDAP::filter.make<LDAP::Filter::EqualityMatch>(
                            "uid"sv,
                            "jdoe"sv
                        )
                    ),
                    LDAP::attribute_selection("*"sv, "+"sv)
                ),
                std::nullopt
            ).write(writer);
            check_bytes(writer.string, bytes);
        }

        SECTION("read") {
            auto reader = Bytes::StringViewReader{bytes};

            auto [message_id, protocol_op, controls_opt] = TRY(LDAP::message.read(reader));
            CHECK(message_id == 0x02);
            CHECK(protocol_op.tag_number == LDAP::ProtocolOp::SearchRequest);

            auto [base_object, scope, deref_aliases, size_limit, time_limit, types_only, filter, attributes] = protocol_op.get<LDAP::ProtocolOp::SearchRequest>();
            CHECK(base_object == "dc=example,dc=com"sv);
            CHECK(scope == LDAP::SearchRequestScope::WholeSubtree);
            CHECK(deref_aliases == LDAP::SearchRequestDerefAliases::NeverDerefAliases);
            CHECK(size_limit == 1000);
            CHECK(time_limit == 30);
            CHECK(types_only == false);

            CHECK(filter.tag_number == LDAP::Filter::And);
            auto and_ = filter.get<LDAP::Filter::And>();
            {
                auto filter = TRY(LDAP::filter.read(and_));
                CHECK(filter.tag_number == LDAP::Filter::EqualityMatch);
                auto [attribute_description, assertion_value] = filter.get<LDAP::Filter::EqualityMatch>();
                CHECK(attribute_description == "objectClass"sv);
                CHECK(assertion_value == "person"sv);
            }
            {
                auto filter = TRY(LDAP::filter.read(and_));
                CHECK(filter.tag_number == LDAP::Filter::EqualityMatch);
                auto [attribute_description, assertion_value] = filter.get<LDAP::Filter::EqualityMatch>();
                CHECK(attribute_description == "uid"sv);
                CHECK(assertion_value == "jdoe"sv);
            }
            check_bytes(and_.string, ""sv);

            CHECK(TRY(LDAP::ldap_string.read(attributes)) == "*"sv);
            CHECK(TRY(LDAP::ldap_string.read(attributes)) == "+"sv);
            check_bytes(attributes.string, ""sv);

            CHECK(controls_opt == std::nullopt);

            check_bytes(reader.string, ""sv);
        }

    }

    SECTION("search result entry") {
        // Example from https://ldap.com/ldapv3-wire-protocol-reference-search/
        auto bytes = "\x30\x49\x02\x01\x02\x64\x44\x04\x11\x64\x63\x3d\x65\x78\x61\x6d\x70\x6c\x65\x2c\x64\x63\x3d\x63\x6f\x6d\x30\x2f\x30\x1c\x04\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73\x31\x0d\x04\x03\x74\x6f\x70\x04\x06\x64\x6f\x6d\x61\x69\x6e\x30\x0f\x04\x02\x64\x63\x31\x09\x04\x07\x65\x78\x61\x6d\x70\x6c\x65"sv;

        SECTION("write") {
            auto writer = Bytes::StringWriter();
            LDAP::message(
                0x02,
                LDAP::search_result_entry(
                    "dc=example,dc=com"sv,
                    std::tuple(
                        LDAP::partial_attribute(
                            "objectClass"sv,
                            std::tuple("top"sv, "domain"sv)
                        ),
                        LDAP::partial_attribute(
                            "dc"sv,
                            std::tuple("example"sv)
                        )
                    )
                ),
                std::nullopt
            ).write(writer);
            check_bytes(writer.string, bytes);
        }

        SECTION("read") {
            auto reader = Bytes::StringViewReader{bytes};

            auto [message_id, protocol_op, controls_opt] = TRY(LDAP::message.read(reader));
            CHECK(message_id == 0x02);
            CHECK(protocol_op.tag_number == LDAP::ProtocolOp::SearchResultEntry);

            auto [object_name, attributes] = protocol_op.get<LDAP::ProtocolOp::SearchResultEntry>();
            CHECK(object_name == "dc=example,dc=com"sv);

            {
                auto [type, vals] = TRY(LDAP::partial_attribute.read(attributes));
                CHECK(type == "objectClass"sv);
                CHECK(TRY(LDAP::attribute_value.read(vals)) == "top"sv);
                CHECK(TRY(LDAP::attribute_value.read(vals)) == "domain"sv);
            }
            {
                auto [type, vals] = TRY(LDAP::partial_attribute.read(attributes));
                CHECK(type == "dc"sv);
                CHECK(TRY(LDAP::attribute_value.read(vals)) == "example"sv);
            }
            check_bytes(attributes.string, ""sv);

            CHECK(controls_opt == std::nullopt);

            check_bytes(reader.string, ""sv);
        }

    }

    SECTION("search result done") {
        // Example from https://ldap.com/ldapv3-wire-protocol-reference-search/
        auto bytes = "\x30\x0c\x02\x01\x02\x65\x07\x0a\x01\x00\x04\x00\x04\x00"sv;

        SECTION("write") {
            auto writer = Bytes::StringWriter();
            LDAP::message(0x02, LDAP::search_result_done(LDAP::ResultCode::Success, ""sv, ""sv, std::nullopt), std::nullopt).write(writer);
            check_bytes(writer.string, bytes);
        }

        SECTION("read") {
            auto reader = Bytes::StringViewReader{bytes};

            auto [message_id, protocol_op, controls_opt] = TRY(LDAP::message.read(reader));
            CHECK(message_id == 0x02);
            CHECK(protocol_op.tag_number == LDAP::ProtocolOp::SearchResultDone);

            auto [result_code, matched_dn, diagnostic_message, referral] = protocol_op.get<LDAP::ProtocolOp::SearchResultDone>();
            CHECK(result_code == LDAP::ResultCode::Success);
            CHECK(matched_dn == ""sv);
            CHECK(diagnostic_message == ""sv);
            CHECK(referral == std::nullopt);

            CHECK(controls_opt == std::nullopt);

            check_bytes(reader.string, ""sv);
        }

    }

}
