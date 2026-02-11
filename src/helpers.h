/*
===========================================================================

Copyright (c) 2026 LandSandBoat Dev Teams

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/

===========================================================================
*/
#pragma once

#ifndef NOMINMAX
#define NOMINMAX 1
#endif

#include <winsock2.h>
#include <windows.h>

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <limits>
#include <iostream>
#include <sstream>

#include "qrcodegen.hpp"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

template <typename T, typename U>
T& ref(U* buf, std::size_t index)
{
    return *reinterpret_cast<T*>(reinterpret_cast<uint8_t*>(buf) + index);
}

// from https://github.com/nayuki/QR-Code-generator/blob/master/cpp/QrCodeGeneratorDemo.cpp
// Slightly modified
static std::string qrToSvgString(const qrcodegen::QrCode& qr, int border)
{
    if (border < 0)
    {
        throw std::domain_error("Border must be non-negative");
    }

    if (border > std::numeric_limits<int>::max() / 2 || border * 2 > std::numeric_limits<int>::max() - qr.getSize())
    {
        throw std::overflow_error("Border too large");
    }

    std::ostringstream sb;
    sb << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    sb << "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n";
    sb << "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" viewBox=\"0 0 ";
    sb << (qr.getSize() + border * 2) << " " << (qr.getSize() + border * 2) << "\" stroke=\"none\">\n";
    sb << "\t<rect width=\"100%\" height=\"100%\" fill=\"#FFFFFF\"/>\n";
    sb << "\t<path d=\"";
    for (int y = 0; y < qr.getSize(); y++)
    {
        for (int x = 0; x < qr.getSize(); x++)
        {
            if (qr.getModule(x, y))
            {
                if (x != 0 || y != 0)
                    sb << " ";
                sb << "M" << (x + border) << "," << (y + border) << "h1v1h-1z";
            }
        }
    }
    sb << "\" fill=\"#000000\"/>\n";
    sb << "</svg>\n";
    return sb.str();
}

static std::string getTemporaryPath()
{
    return std::filesystem::temp_directory_path().generic_string();
}

// Return filename for later deletion
// Only input filename as "name.ext" and don't include the path
static std::string writeSvgToDisk(std::string filename, std::string contents)
{
    filename = getTemporaryPath() + filename;
    std::ofstream svg(filename, std::ios::out | std::ios::trunc);

    svg.write(contents.c_str(), contents.length());

    svg.flush();
    svg.close();

    return filename;
}

template <typename T>
struct always_false : std::false_type
{
};

template <typename T>
inline constexpr bool always_false_v = always_false<T>::value;

template <typename T>
inline std::optional<T> jsonGet(const json& jsonInput, std::string key)
{
    if (!jsonInput.contains(key))
    {
        return std::nullopt;
    }

    // Check types first, boolean can match a number
    if constexpr (std::is_same_v<T, std::string>)
    {
        if (!jsonInput[key].is_string())
        {
            return std::nullopt;
        }
    }
    else if constexpr (std::is_same_v<T, bool>)
    {
        if (!jsonInput[key].is_boolean())
        {
            return std::nullopt;
        }
    }
    else if constexpr (std::is_floating_point<T>::value)
    {
        if (!jsonInput[key].is_number_float())
        {
            return std::nullopt;
        }
    }
    else if constexpr (std::is_signed<T>::value)
    {
        if (!jsonInput[key].is_number_unsigned())
        {
            return std::nullopt;
        }
    }
    else if constexpr (std::is_unsigned<T>::value)
    {
        if (!jsonInput[key].is_number_unsigned())
        {
            return std::nullopt;
        }
    }
    else
    {
        static_assert(always_false_v<T>, "Trying to extract unsupported type from jsonGet");
    }

    return jsonInput[key].get<T>();
}

// Required partial specialization for size arg
template <typename T, uint32_t size>
inline typename std::optional<std::array<T, size>> jsonGet(const json& jsonInput, std::string key)
{
    if (!jsonInput.contains(key))
    {
        return std::nullopt;
    }

    if (!jsonInput[key].is_array())
    {
        return std::nullopt;
    }

    if (jsonInput[key].size() != size)
    {
        return std::nullopt;
    }

    for (uint32_t i = 0; i < size; i++)
    {
        // JSON arrays can support mixed types, so make sure EVERY index is correct.
        if constexpr (std::is_signed<T>::value)
        {
            if (!jsonInput[key][i].is_number())
            {
                return std::nullopt;
            }
        }
        else if constexpr (std::is_unsigned<T>::value)
        {
            if (!jsonInput[key][i].is_number_unsigned())
            {
                return std::nullopt;
            }
        }
        else
        {
            static_assert(always_false_v<T>, "Trying to extract unsupported type from jsonGetArray");
        }
    }

    return jsonInput[key].get<std::array<T, size>>();
}
