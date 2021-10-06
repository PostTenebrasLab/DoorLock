/*!
 * @file    tools.h
 *
 * @author     Maxime BORGES <maxime@hedtechnologies.com>
 * @version    0.1.0
 * @copyright  Copyright © 2021 HEDTechnologies
 */

#ifndef PTLDAP_TESTS_TOOLS_H
#define PTLDAP_TESTS_TOOLS_H

#include "catch.hpp"

#include <iomanip>
#include <limits>

template <typename T>
struct Hex
{
    // C++11:
    // static constexpr int Width = (std::numeric_limits<T>::digits + 1) / 4;
    // Otherwise:
    enum { Width = (std::numeric_limits<T>::digits + 1) / 4 };
    const T& value;
    const int width;

    Hex(const T& value, int width = Width)
            : value(value), width(width)
    {}

    void write(std::ostream& stream) const {
        if(std::numeric_limits<T>::radix != 2) stream << value;
        else {
            std::ios_base::fmtflags flags = stream.setf(
                    std::ios_base::hex, std::ios_base::basefield);
            char fill = stream.fill('0');
            stream << "\\x" << std::setw(width) << value;
            stream.fill(fill);
            stream.setf(flags, std::ios_base::basefield);
        }
    }
};

template <typename T>
inline Hex<T> hex(const T& value, int width = Hex<T>::Width) {
    return Hex<T>(value, width);
}

template <typename T>
inline std::ostream& operator << (std::ostream& stream, const Hex<T>& value) {
    value.write(stream);
    return stream;
}

void check_bytes(auto&& left, auto&& right) {
    CHECK(left == right);
    if (left == right) {
        return;
    }

    for (auto i = 0; i < left.size(); ++i) {
        printf("\\x%02x", left[i] & 0xff);
    }
    printf("\n");

    for (auto i = 0; i < right.size(); ++i) {
        printf("\\x%02x", right[i] & 0xff);
    }
    printf("\n");

    printf("\n");
}

#endif //PTLDAP_TESTS_TOOLS_H
