#pragma once

#include <memory>

class Inspector {
public:
    static Inspector& get() {
        static std::unique_ptr<Inspector> instance = std::make_unique<Inspector>();
        return *instance;
    }

public:
    void render_window_for_main_target();
    void render_window(uintptr_t* vtable);
    void render_inner(uintptr_t* vtable);

    void set_main_target(uintptr_t* target) {
        m_main_target = target;
    }

    uintptr_t* get_main_target() const {
        return m_main_target;
    }

public:
    uintptr_t* m_main_target{};
};