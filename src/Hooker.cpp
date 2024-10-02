#include <array>

#include <utility/Module.hpp>

#include "Hooker.hpp"

Hooker::Hooker(uintptr_t* vtable) 
    : m_target(vtable),
    m_type_info(utility::rtti::get_type_info(&vtable))
{
    spdlog::info("Hooking vtable at 0x{:x}", (uintptr_t)vtable);

    for (size_t i = 0; ; ++i) {
        uintptr_t& entry = vtable[i];

        if (entry == 0 || IsBadReadPtr((void*)entry, sizeof(uintptr_t))) {
            break;
        }

        // If the code is not even executable, we've hit the end of the vtable.
        if (!utility::isGoodCodePtr(entry, sizeof(void*))) {
            break;
        }

        // If the next pointer is a vtable, we've hit the end of the vtable.
        if (utility::rtti::is_vtable((const void*)&vtable[i+1])) {
            break;
        }

        uint8_t* instructions = (uint8_t*)entry;

        // Ignore ret instructions
        if (utility::is_stub_code(instructions)) {
            continue;
        }

        spdlog::info("Hooking {} at 0x{:x}", i, entry);

        auto& hook = m_hooks.emplace_back(std::make_shared<Hook>());
        m_hook_map[i] = hook;

        hook->parent = this;
        hook->target = entry;
        hook->stub_code = create_stub(i, hook.get());
        hook->index = i;
        hook->impl = safetyhook::create_mid(entry, (safetyhook::MidHookFn)hook->stub_code.get(), safetyhook::MidHook::Flags::StartDisabled);
    }

    // Enable all the hooks now, is more thread safe.
    for (auto& hook : m_hooks) {
        if (auto err = hook->impl.enable(); !err.has_value()) {
            spdlog::error("Failed to enable hook for index: {}, error: {}", hook->index, (int32_t)err.error().type);
        }
    }

    spdlog::info("Done hooking vtable at 0x{:x}", (uintptr_t)vtable);
}

void Hooker::generic_hook(safetyhook::Context& ctx, Hook* hook) {
    auto hooker = hook->parent;
    // This is a function belonging to another vtable, ignore it.
    if (!s_ignore_vtable_mismatch && *(uintptr_t*)ctx.rcx != hooker->get_target()) {
        return;
    }

    if (++hook->calls == 1) {
        spdlog::info("Hook {} called for the first time!", hook->index);
    }
    
    hook->last_return_address = *reinterpret_cast<uintptr_t*>(ctx.rsp);

    const auto now = std::chrono::high_resolution_clock::now();
    const auto last_call = hook->last_call.load();

    hook->delta = now - last_call;
    hook->last_call = now;

    // Callstack capture using RtlVirtualUnwind
    CONTEXT context{};
    context.ContextFlags = CONTEXT_FULL;

    // Populate the CONTEXT structure with the current register values
    context.Rip = hook->target; // The original ctx.rip is not accurate because its points to a hook stub.
    context.Rsp = ctx.rsp;
    context.Rbp = ctx.rbp;
    context.Rax = ctx.rax;
    context.Rbx = ctx.rbx;
    context.Rcx = ctx.rcx;
    context.Rdx = ctx.rdx;
    context.Rsi = ctx.rsi;
    context.Rdi = ctx.rdi;
    context.R8 = ctx.r8;
    context.R9 = ctx.r9;
    context.R10 = ctx.r10;
    context.R11 = ctx.r11;
    context.R12 = ctx.r12;
    context.R13 = ctx.r13;
    context.R14 = ctx.r14;
    context.R15 = ctx.r15;

    std::array<void*, 128> callstack{};
    size_t count = 0;

    while (count < callstack.size()) {
        callstack[count++] = reinterpret_cast<void*>(context.Rip);
        const auto module_within = (DWORD64)utility::get_module_within(context.Rip).value_or(nullptr);

        auto runtime_function = utility::find_function_entry(context.Rip); // My custom implementation
        if (runtime_function == nullptr) {
            if (hook->calls == 1) {
                spdlog::warn("Failed to find runtime function for 0x{:x}", context.Rip);
            }
            
            break;
        }

        void* handler_data = nullptr;
        ULONG64 establisher_frame = 0;

        RtlVirtualUnwind(UNW_FLAG_NHANDLER, module_within,
                        context.Rip, runtime_function, &context, &handler_data,
                        &establisher_frame, nullptr);

        // If we reach an invalid RIP, stop the unwinding
        if (context.Rip == 0) {
            break;
        }
    }

    // Store the callstack
    {
        std::unique_lock _{hook->sensitive_data.mutex};
        hook->sensitive_data.callstack.clear();

        for (size_t i = 0; i < count; ++i) {
            hook->sensitive_data.callstack.push_back(reinterpret_cast<uintptr_t>(callstack[i]));
        }
    }
}

size_t Hooker::count(uintptr_t* vtable) {
    if (vtable == nullptr) {
        return 0;
    }

    size_t result = 0;

    for (size_t i = 0; ; ++i) {
        uintptr_t& entry = vtable[i];

        if (entry == 0 || IsBadReadPtr((void*)entry, sizeof(uintptr_t))) {
            return result;
        }

        // If the code is not even executable, we've hit the end of the vtable.
        if (!utility::isGoodCodePtr(entry, sizeof(void*))) {
            return result;
        }

        // If the next pointer is a vtable, we've hit the end of the vtable.
        if (utility::rtti::is_vtable((const void*)&vtable[i+1])) {
            return result;
        }

        uint8_t* instructions = (uint8_t*)entry;

        // Ignore ret instructions
        if (utility::is_stub_code(instructions)) {
            continue;
        }

        ++result;
    }

    return result;
}

std::unique_ptr<uint8_t[]> Hooker::create_stub(uint32_t vtable_index, void* hook_data) {
    std::vector<uint8_t> initial_data {
        0x48, 0x8B, 0x15, 0x0E, 0x00, 0x00, 0x00, // mov rdx, [rip + 14]
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp [rip + 0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ptr to generic_hook
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ptr to hook data
    };

    *(uintptr_t*)&initial_data[13] = (uintptr_t)&generic_hook;
    *(uintptr_t*)&initial_data[21] = (uintptr_t)hook_data;

    auto new_data = std::make_unique<uint8_t[]>(initial_data.size());
    DWORD old_protect{};
    if (!VirtualProtect(new_data.get(), initial_data.size(), PAGE_EXECUTE_READWRITE, &old_protect)) {
        spdlog::error("Failed to set memory protection for stub code at 0x{:x}", (uintptr_t)new_data.get());
    }

    std::copy(initial_data.begin(), initial_data.end(), new_data.get());

    return new_data;
}