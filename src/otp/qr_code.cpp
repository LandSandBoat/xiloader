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

#include "qr_code.h"

#include "console.h"

#include <shellapi.h>

#include <filesystem>
#include <fstream>
#include <limits>
#include <sstream>

#include "qrcodegen.hpp"

namespace
{

constexpr const char* kQrCodeFileName = "temp.svg";

// from https://github.com/nayuki/QR-Code-generator/blob/master/cpp/QrCodeGeneratorDemo.cpp
// Slightly modified
auto qrToSvgString(const qrcodegen::QrCode& qr, const int border) -> std::string
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

auto getTemporaryPath() -> std::string
{
    return std::filesystem::temp_directory_path().generic_string();
}

// Return filename for later deletion
// Only input filename as "name.ext" and don't include the path
auto writeSvgToDisk(std::string filename, const std::string contents) -> std::string
{
    filename = getTemporaryPath() + filename;
    std::ofstream svg(filename, std::ios::out | std::ios::trunc);

    svg.write(contents.c_str(), contents.length());

    svg.flush();
    svg.close();

    return filename;
}

} // namespace

namespace xiloader::otp
{

auto writeQrCode(const std::string& uri) -> std::string
{
    const qrcodegen::QrCode qrCode = qrcodegen::QrCode::encodeText(uri.c_str(), qrcodegen::QrCode::Ecc::LOW);

    return writeSvgToDisk(kQrCodeFileName, qrToSvgString(qrCode, 4));
}

void openQrCode(const std::string& path)
{
    // ShellExecuteA returns a value above 32 on success
    const auto opened = reinterpret_cast<INT_PTR>(ShellExecuteA(nullptr, "open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL));
    if (opened <= 32)
    {
        xiloader::console::output(xiloader::color::error, "Failed to open the QR code (error %d). Open %s manually.", static_cast<int>(opened), path.c_str());
    }
}

void removeQrCode()
{
    const std::string svgFilePath = getTemporaryPath() + kQrCodeFileName;
    if (std::filesystem::exists(svgFilePath))
    {
        std::filesystem::remove(svgFilePath);
    }
}

} // namespace xiloader::otp
