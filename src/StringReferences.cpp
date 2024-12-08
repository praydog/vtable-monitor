#include "StringReferences.hpp"

void StringReferences::populate_ascii(FunctionStart start, size_t max_size, const utility::StringReferenceOptions& options) {
    {
        std::shared_lock _{m_mutex};
        if (m_ascii_references.contains(start)) {
            return;
        }
    }
    
    auto result = utility::collect_ascii_string_references(start, max_size, options);

    std::unique_lock _{m_mutex};

    if (result.empty()) {
        m_ascii_references[start] = {};
        return;
    }
    
    m_ascii_references[start] = std::move(result);
}

void StringReferences::populate_unicode(FunctionStart start, size_t max_size, const utility::StringReferenceOptions& options) {
    {
        std::shared_lock _{m_mutex};
        if (m_unicode_references.contains(start)) {
            return;
        }
    }
    
    auto result = utility::collect_unicode_string_references(start, max_size, options);

    std::unique_lock _{m_mutex};
    if (result.empty()) {
        m_unicode_references[start] = {};
        return;
    }

    m_unicode_references[start] = std::move(result);
}

StringReferences::StringReferencesList StringReferences::ascii_references(FunctionStart start) {
    {
        std::shared_lock _{m_mutex};
        auto it = m_ascii_references.find(start);

        if (it != m_ascii_references.end()) {      
            return it->second;
        }
    }

    populate_ascii(start);
    return ascii_references(start);
}

StringReferences::StringReferencesList StringReferences::unicode_references(FunctionStart start) {
    {
        std::shared_lock _{m_mutex};
        auto it = m_unicode_references.find(start);

        if (it != m_unicode_references.end()) {     
            return it->second;
        }
    }

    populate_unicode(start);
    return unicode_references(start);
}