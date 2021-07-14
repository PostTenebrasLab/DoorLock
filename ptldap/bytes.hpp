#include <optional>
#include <ostream>
#include "string_view.hpp"

#define OPT_REQUIRE(condition) if (!(condition)) return std::nullopt
#define OPT_TRY(optional) ({ auto ref = (optional); OPT_REQUIRE(ref); *ref; })
#define TRY(optional) ({ auto ref = (optional); REQUIRE(ref); *ref; })

namespace Bytes {

    struct StringViewReader {

        std::string_view string;

        bool empty() {
            return string.empty();
        }

        std::optional<uint8_t> read() {
            OPT_REQUIRE(!empty());
            auto result = string.front();
            string.remove_prefix(1);
            return result;
        }

        std::optional<nonstd::string_view> read(size_t length) {
            OPT_REQUIRE(length <= string.size());
            auto result = string.substr(0, length);
            string.remove_prefix(length);
            return result;
        }

        std::optional<StringViewReader> reader(size_t length) {
            return StringViewReader{OPT_TRY(read(length))};
        }

    };

    struct StreamWriter {

        std::ostream& stream;

        void write(uint8_t byte) {
            stream.rdbuf()->sputc(byte);
        }

        void write(std::string_view bytes) {
            stream.rdbuf()->sputn(bytes.data(), bytes.size());
        }

    };

    struct StringWriter {

        std::string string;

        void write(uint8_t byte) {
            string.push_back(char(byte));
        }

        void write(std::string_view bytes) {
            string += bytes;
        }

    };

}
