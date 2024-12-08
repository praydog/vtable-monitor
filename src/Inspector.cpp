#include <imgui.h>
#include <utility/String.hpp>

#include "StringReferences.hpp"
#include "VtableManager.hpp"
#include "Inspector.hpp"

void Inspector::render_window_for_main_target() {
    if (ImGui::Begin("Inspector")) {
        render_inner(m_main_target);
        ImGui::End();
    }
}

void Inspector::render_window(uintptr_t* vtable) {
    if (ImGui::Begin(std::format("Inspector: 0x{:x}", (uintptr_t)vtable).c_str())) {
        render_inner(vtable);
        ImGui::End();
    }
}

void Inspector::render_inner(uintptr_t* vtable) {
    if (vtable == nullptr) {
        ImGui::Text("No vtable selected");
        return;
    }

    ImGui::Columns(4, "vtablefunctions", true);
    ImGui::Separator();
    ImGui::Text("Index");
    ImGui::NextColumn();
    ImGui::Text("Address");
    ImGui::NextColumn();
    ImGui::Text("ASCII Refs");
    ImGui::NextColumn();
    ImGui::Text("Unicode Refs");
    ImGui::NextColumn();
    ImGui::Separator();

    auto& string_references = StringReferences::get();
    auto& vtable_manager = VtableManager::get();    

    size_t count = vtable_manager.count(vtable);

    for (size_t i = 0; i < count; ++i) {
        ImGui::Text("%zu", i);
        ImGui::NextColumn();

        uintptr_t fn = vtable[i];
        ImGui::Text("0x%llx", fn);
        ImGui::NextColumn();

        auto ascii_strs = string_references.ascii_references(fn);
        auto unicode_strs = string_references.unicode_references(fn);

        // ASCII
        ImGui::BeginGroup();
        if (!ascii_strs.empty()) {
            for (const auto& str : ascii_strs) {
                ImGui::Text("%s", str.ascii);
            }
        } else {
            ImGui::Text("No ASCII refs");
        }
        ImGui::EndGroup();

        ImGui::NextColumn();

        // Unicode
        ImGui::BeginGroup();
        if (!unicode_strs.empty()) {
            for (const auto& str : unicode_strs) {
                ImGui::Text("%s", utility::narrow(str.unicode).c_str());
            }
        } else {
            ImGui::Text("No Unicode refs");
        }
        ImGui::EndGroup();

        ImGui::NextColumn();
    }
}