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

#include <windows.h>
#include <winsock2.h>

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

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
