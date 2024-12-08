#include "Hooker.hpp"
#include "VtableManager.hpp"

size_t VtableManager::count(uintptr_t* vtable) {
    {
        std::shared_lock _{m_mutex};
        auto it = m_vtable_counts.find(vtable);

        if (it != m_vtable_counts.end()) {
            return it->second;
        }
    }

    auto count = Hooker::count((uintptr_t*)vtable);

    {
        std::unique_lock _{m_mutex};
        m_vtable_counts[vtable] = count;
    }

    return count;
}