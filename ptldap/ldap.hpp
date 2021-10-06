// Lightweight Directory Access Protocol (LDAP): The Protocol
// https://datatracker.ietf.org/doc/html/rfc4511

// LDAPv3 Wire Protocol Reference
// https://ldap.com/ldapv3-wire-protocol-reference/

#include "ber.hpp"

namespace LDAP {

    enum class ResultCode {
        Success = 0,
        OperationsError = 1,
        ProtocolError = 2,
        TimeLimitExceeded = 3,
        SizeLimitExceeded = 4,
        CompareFalse = 5,
        CompareTrue = 6,
        AuthMethodNotSupported = 7,
        StrongerAuthRequired = 8,
        Referral = 10,
        AdminLimitExceeded = 11,
        UnavailableCriticalExtension = 12,
        ConfidentialityRequired = 13,
        SaslBindInProgress = 14,
        NoSuchAttribute = 16,
        UndefinedAttributeType = 17,
        InappropriateMatching = 18,
        ConstraintViolation = 19,
        AttributeOrValueExists = 20,
        InvalidAttributeSyntax = 21,
        NoSuchObject = 32,
        AliasProblem = 33,
        InvalidDNSyntax = 34,
        AliasDereferencingProblem = 36,
        InappropriateAuthentication = 48,
        InvalidCredentials = 49,
        InsufficientAccessRights = 50,
        Busy = 51,
        Unavailable = 52,
        UnwillingToPerform = 53,
        LoopDetect = 54,
        NamingViolation = 64,
        ObjectClassViolation = 65,
        NotAllowedOnNonLeaf = 66,
        NotAllowedOnRDN = 67,
        EntryAlreadyExists = 68,
        ObjectClassModsProhibited = 69,
        AffectsMultipleDSAs = 71,
        Other = 80
    };

    enum class ProtocolOp {
        BindRequest = 0,
        BindResponse = 1,
        UnbindRequest = 2,
        SearchRequest = 3,
        SearchResultEntry = 4,
        SearchResultDone = 5,
        SearchResultReference = 19,
        ModifyRequest = 6,
        ModifyResponse = 7,
        AddRequest = 8,
        AddResponse = 9,
        DelRequest = 10,
        DelResponse = 11,
        ModifyDNRequest = 12,
        ModifyDNResponse = 13,
        CompareRequest = 14,
        CompareResponse = 15,
        AbandonRequest = 16,
        ExtendedRequest = 23,
        ExtendedResponse = 24,
        IntermediateResponse = 25
    };

    constexpr auto ldapoid = BER::octet_string;

    constexpr auto ldapdn = BER::octet_string;

    constexpr auto ldap_string = BER::octet_string;

    constexpr auto uri = ldap_string;

    constexpr auto referral = BER::sequence_of(uri);

    constexpr auto message_id = BER::integer;

    constexpr auto ldap_result = BER::sequence(
        BER::enumerated<ResultCode>(), ldapdn, ldap_string, BER::optional(referral.context_specific<3>()));

    enum class AuthenticationChoice {
        Simple = 0,
        Sasl = 3,
    };
    constexpr auto authentication_choice = BER::choice<AuthenticationChoice>()
        .with<AuthenticationChoice::Simple>(BER::octet_string);
    constexpr auto bind_request = BER::sequence(
        BER::integer, ldapdn, authentication_choice).application<ProtocolOp::BindRequest>();

    // TODO: SEQUENCE { COMPONENTS OF LDAPResult, serverSaslCreds    [7] OCTET STRING OPTIONAL }
    constexpr auto bind_response = ldap_result.application<ProtocolOp::BindResponse>();

    constexpr auto matching_rule_id = ldap_string;
    constexpr auto attribute_description = ldap_string;
    constexpr auto assertion_value = BER::octet_string;
    constexpr auto attribute_value_assertion = BER::sequence(
        attribute_description, assertion_value);
    constexpr auto matching_rule_assertion = BER::sequence(
        BER::optional(matching_rule_id.context_specific<1>()),
        BER::optional(attribute_description.context_specific<2>()),
        assertion_value.context_specific<3>(),
        BER::optional(BER::boolean.context_specific<4>())
    );

    enum class SubstringFilterSubstrings {
        Initial = 0,
        Any = 1,
        Final = 2,
    };
    constexpr auto substring_filter = BER::sequence(
        attribute_description, BER::sequence_of(
            BER::choice<SubstringFilterSubstrings>()
                .with<SubstringFilterSubstrings::Initial>(assertion_value)
                .with<SubstringFilterSubstrings::Any>(assertion_value)
                .with<SubstringFilterSubstrings::Final>(assertion_value)
        )
    );

    enum class Filter {
        And = 0,
        Or = 1,
        Not = 2,
        EqualityMatch = 3,
        Substrings = 4,
        GreaterOrEqual = 5,
        LessOrEqual = 6,
        Present = 7,
        ApproxMatch = 8,
        ExtensibleMatch = 9,
    };
    constexpr auto filter0 = BER::choice<Filter>()
        .with<Filter::EqualityMatch>(attribute_value_assertion)
        .with<Filter::Substrings>(substring_filter)
        .with<Filter::GreaterOrEqual>(attribute_value_assertion)
        .with<Filter::LessOrEqual>(attribute_value_assertion)
        .with<Filter::Present>(attribute_description)
        .with<Filter::ApproxMatch>(attribute_value_assertion)
        .with<Filter::ExtensibleMatch>(matching_rule_assertion);
    constexpr auto filter = BER::choice<Filter>()
        .with<Filter::And>(BER::set_of(filter0))
        .with<Filter::Or>(BER::set_of(filter0))
        .with<Filter::Not>(BER::explicit_(filter0))
        .with<Filter::EqualityMatch>(attribute_value_assertion)
        .with<Filter::Substrings>(substring_filter)
        .with<Filter::GreaterOrEqual>(attribute_value_assertion)
        .with<Filter::LessOrEqual>(attribute_value_assertion)
        .with<Filter::Present>(attribute_description)
        .with<Filter::ApproxMatch>(attribute_value_assertion)
        .with<Filter::ExtensibleMatch>(matching_rule_assertion);

    constexpr auto attribute_selection = BER::sequence_of(ldap_string);

    enum class SearchRequestScope {
        BaseObject = 0,
        SingleLevel = 1,
        WholeSubtree = 2,
    };
    enum class SearchRequestDerefAliases {
        NeverDerefAliases = 0,
        DerefInSearching = 1,
        DerefFindingBaseObj = 2,
        DerefAlways = 3,
    };
    constexpr auto search_request = BER::sequence(
        ldapdn,
        BER::enumerated<SearchRequestScope>(),
        BER::enumerated<SearchRequestDerefAliases>(),
        BER::integer,
        BER::integer,
        BER::boolean,
        filter,
        attribute_selection
    ).application<ProtocolOp::SearchRequest>();

    constexpr auto attribute_value = BER::octet_string;
    constexpr auto partial_attribute = BER::sequence(
        attribute_description, BER::set_of(attribute_value));
    constexpr auto partial_attribute_list = BER::sequence_of(partial_attribute);
    constexpr auto search_result_entry = BER::sequence(
        ldapdn, partial_attribute_list).application<ProtocolOp::SearchResultEntry>();

    constexpr auto search_result_done = ldap_result.application<ProtocolOp::SearchResultDone>();

    constexpr auto control = BER::sequence(
        ldapoid, BER::boolean, BER::optional(BER::octet_string));

    constexpr auto controls = BER::sequence_of(control).context_specific<0>();

    constexpr auto del_request = ldapdn.application<ProtocolOp::DelRequest>();

    constexpr auto compare_response = ldap_result.application<ProtocolOp::CompareResponse>();

    constexpr auto abandon_request = message_id.application<ProtocolOp::AbandonRequest>();

    constexpr auto extended_request = BER::sequence(
        ldapoid.context_specific<0>(),
        BER::optional(BER::octet_string.context_specific<1>())
    ).template application<ProtocolOp::ExtendedRequest>();

    constexpr auto extended_response = BER::sequence(
        // TODO: COMPONENTS OF LDAPResult,
        BER::optional(ldapoid.context_specific<10>()),
        BER::optional(BER::octet_string.context_specific<11>())
    ).application<ProtocolOp::ExtendedResponse>();

    constexpr auto intermediate_response = BER::sequence(
        BER::optional(ldapoid.context_specific<0>()),
        BER::optional(BER::octet_string.context_specific<1>())
    ).application<ProtocolOp::IntermediateResponse>();

    constexpr auto message = BER::sequence(
        message_id,
        BER::choice<ProtocolOp>()
            .with(bind_request)
            .with(bind_response)
            .with(search_request)
            .with(search_result_entry)
            .with(search_result_done)
            .with(del_request),
        BER::optional(controls)
    );

}
