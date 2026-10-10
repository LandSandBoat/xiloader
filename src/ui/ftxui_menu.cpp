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

#include "menu.h"

#include "ftxui/component/captured_mouse.hpp"     // for ftxui
#include "ftxui/component/component.hpp"          // for Menu
#include "ftxui/component/component_options.hpp"  // for MenuOption
#include "ftxui/component/screen_interactive.hpp" // for ScreenInteractive

namespace
{

using namespace ftxui;
using xiloader::ui::Field;

class FtxuiMenu final : public xiloader::ui::Menu
{
public:
    auto pick(const std::vector<std::string>& entries) -> int override
    {
        const auto count = static_cast<int>(entries.size());

        auto screen   = ScreenInteractive::TerminalOutput();
        int  selected = 0; // Container::Vertical requires `int` input

        Components items;
        for (const auto& entry : entries)
        {
            items.push_back(MenuEntry(entry));
        }

        auto menu = Container::Vertical(items, &selected);

        menu |= border; // Add border

        menu |= CatchEvent([&](Event event)
                           {
                               if (event.is_character())
                               {
                                   const auto c = event.character()[0];
                                   if (c >= '1' && c < '1' + count)
                                   {
                                       selected = c - '1';
                                       screen.Exit();
                                       return true;
                                   }
                               }
                               else if (event == Event::Return)
                               {
                                   screen.Exit();
                                   return true;
                               }

                               return false;
                           });

        screen.Loop(menu);

        return selected;
    }

    void form(const std::vector<Field>& fields, const std::function<std::string()>& note) override
    {
        InputOption hiddenOption;
        hiddenOption.password = true;

        Components inputs;
        for (const auto& field : fields)
        {
            if (field.checked)
            {
                inputs.push_back(Checkbox(field.label, field.checked));
            }
            else
            {
                if (field.hidden)
                {
                    inputs.push_back(Input(field.text, "", hiddenOption));
                }
                else
                {
                    inputs.push_back(Input(field.text, ""));
                }
            }
        }

        auto component = Container::Vertical(inputs);
        auto screen    = ScreenInteractive::TerminalOutput();

        const auto skipped = [&](const std::size_t index)
        {
            return fields[index].skipped && fields[index].skipped();
        };

        // Enter moves to the next field that isn't skipped, and leaves the form from the last one
        component |= CatchEvent([&](Event event)
                                {
                                    if (event != Event::Return)
                                    {
                                        return false;
                                    }

                                    std::size_t current = 0;
                                    while (current < inputs.size() && !inputs[current]->Focused())
                                    {
                                        ++current;
                                    }

                                    for (auto next = current + 1; next < inputs.size(); ++next)
                                    {
                                        if (!skipped(next))
                                        {
                                            inputs[next]->TakeFocus();
                                            return true;
                                        }
                                    }

                                    screen.Exit();
                                    return true;
                                });

        // Tweak how the component tree is rendered:
        auto renderer = Renderer(component, [&]
                                 {
                                     Elements rows;
                                     for (std::size_t i = 0; i < fields.size(); ++i)
                                     {
                                         auto row = hbox(text("  " + fields[i].label + ": "), inputs[i]->Render());
                                         if (fields[i].checked)
                                         {
                                             row = hbox(text("  "), inputs[i]->Render());
                                         }

                                         if (skipped(i))
                                         {
                                             row = row | color(Color::GrayDark);
                                         }

                                         rows.push_back(row);
                                     }

                                     std::string message;
                                     if (note)
                                     {
                                         message = note();
                                     }

                                     if (!message.empty())
                                     {
                                         rows.push_back(text("  " + message) | color(Color::Green));
                                     }

                                     return vbox(rows) | border;
                                 });

        screen.Loop(renderer);
    }
};

} // namespace

namespace xiloader::ui
{

auto makeFtxuiMenu() -> std::unique_ptr<Menu>
{
    return std::make_unique<FtxuiMenu>();
}

} // namespace xiloader::ui
