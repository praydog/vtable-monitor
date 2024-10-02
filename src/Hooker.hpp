#pragma once

#include <shared_mutex>
#include <iostream>

#include <spdlog/spdlog.h>

#include <safetyhook.hpp>

#include <utility/RTTI.hpp>
#include <utility/Memory.hpp>
#include <utility/PointerHook.hpp>
#include <utility/Thread.hpp>
#include <utility/Scan.hpp>

class Hooker { // haw haw real funny
public:
    static inline bool s_ignore_vtable_mismatch{};
    struct Hook;

    static void generic_hook(safetyhook::Context& ctx, Hook* hook);

    struct Hook {
        Hooker* parent{};
        uintptr_t target{};
        safetyhook::MidHook impl{};
        std::unique_ptr<uint8_t[]> stub_code{};
        size_t index{};
        std::atomic<size_t> calls{};
        std::atomic<uintptr_t> last_return_address{};
        std::atomic<std::chrono::high_resolution_clock::time_point> last_call{};
        std::atomic<std::chrono::nanoseconds> delta{};
        struct SensitiveData {
            std::shared_mutex mutex{};
            std::vector<uintptr_t> callstack{};  
        } sensitive_data{};
        std::optional<uint8_t> original_byte{};

        // Returns a copy of the callstack.
        std::vector<uintptr_t> get_callstack() {
            std::shared_lock _{sensitive_data.mutex};
            return sensitive_data.callstack;
        }

        void insert_ret() {
            if (!original_byte.has_value()) {
                original_byte = *reinterpret_cast<uint8_t*>(target);
            }

            DWORD old_protect{};
            if (!VirtualProtect((void*)target, 1, PAGE_EXECUTE_READWRITE, &old_protect)) {
                spdlog::error("Failed to set memory protection for ret instruction at 0x{:x}", target);
                return;
            }

            *reinterpret_cast<uint8_t*>(target) = 0xC3;

            if (!VirtualProtect((void*)target, 1, old_protect, &old_protect)) {
                spdlog::error("Failed to restore memory protection for ret instruction at 0x{:x}", target);
            }

            spdlog::info("Inserted ret instruction at index: {} (0x{:x})", index, target);
        }

        void restore() {
            if (!original_byte.has_value()) {
                return;
            }

            DWORD old_protect{};
            if (!VirtualProtect((void*)target, 1, PAGE_EXECUTE_READWRITE, &old_protect)) {
                spdlog::error("Failed to set memory protection for ret instruction at 0x{:x}", target);
                return;
            }

            *reinterpret_cast<uint8_t*>(target) = original_byte.value();

            if (!VirtualProtect((void*)target, 1, old_protect, &old_protect)) {
                spdlog::error("Failed to restore memory protection for ret instruction at 0x{:x}", target);
            }

            spdlog::info("Restored original instruction at index: {} (0x{:x})", index, target);
        }
    };

    std::shared_ptr<Hook> find_hook(size_t vtable_index) {
        for (const auto& hook : m_hooks) {
            if (hook->index == vtable_index) {
                return hook;
            }
        }

        return nullptr;
    }

public:
    static size_t count(uintptr_t* vtable);

    Hooker(uintptr_t* vtable);

    virtual ~Hooker() {
        spdlog::info("Unhooking vtable at 0x{:x}", (uintptr_t)m_target);

        for (const auto& hook : m_hooks) {
            hook->restore();
        }
    }

    auto& get_hooks() const {
        return m_hooks;
    }

    uintptr_t get_target() const {
        return (uintptr_t)m_target;
    }

private:
    static std::unique_ptr<uint8_t[]> create_stub(uint32_t vtable_index, void* hook_data);

    uintptr_t* m_target{};
    std::type_info* m_type_info{};

    std::vector<std::shared_ptr<Hook>> m_hooks{};
    std::unordered_map<size_t, std::shared_ptr<Hook>> m_hook_map{};

    safetyhook::InlineHook m_special_hook{};
};

static inline std::unique_ptr<Hooker> g_hooker{};