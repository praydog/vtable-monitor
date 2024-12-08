#pragma once

#include <shared_mutex>
#include <unordered_map>
#include <memory>

class VtableManager {
public:
    static VtableManager& get() {
        static std::unique_ptr<VtableManager> instance = std::make_unique<VtableManager>();
        return *instance;
    }

public:
    size_t count(uintptr_t* vtable);

private:
    std::shared_mutex m_mutex{};
    std::unordered_map<uintptr_t*, size_t> m_vtable_counts{};
};