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

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace xiloader::ui
{

// One input of a form: a line of text, or a checkbox when checked is set
struct Field
{
    std::string  label;
    std::string* text    = nullptr;
    bool*        checked = nullptr;
    bool         hidden  = false; // Don't echo the text

    // The field isn't asked for while this returns true
    std::function<bool()> skipped = {};
};

// How the menus and forms are drawn. prompts.h builds every prompt out of these.
class Menu
{
public:
    virtual ~Menu() = default;

    // Shows a numbered menu and returns the selected index. Entries are expected to be prefixed "1) ", "2) ", ...
    virtual auto pick(const std::vector<std::string>& entries) -> int = 0;

    // Asks for each field in order. A non-empty note is shown with the form.
    virtual void form(const std::vector<Field>& fields, const std::function<std::string()>& note = {}) = 0;
};

auto makeFtxuiMenu() -> std::unique_ptr<Menu>;
auto makePlainMenu() -> std::unique_ptr<Menu>;

// The plain menu when asked for or under Wine, FTXUI otherwise
auto makeMenu(bool plain) -> std::unique_ptr<Menu>;

} // namespace xiloader::ui
