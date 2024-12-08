#pragma once

#include <shared_mutex>
#include <memory>
#include <unordered_map>
#include <vector>

#include <utility/Scan.hpp>

class StringReferences {
public:
    static StringReferences& get() {
        static std::unique_ptr<StringReferences> instance = std::make_unique<StringReferences>();
        return *instance;
    }

public:
    using FunctionStart = uintptr_t;
    using StringReferencesList = std::vector<utility::StringReference>;

    void populate_ascii(FunctionStart start, size_t max_size = 100, const utility::StringReferenceOptions& options = utility::StringReferenceOptions{}.with_min_length(4));
    void populate_unicode(FunctionStart start, size_t max_size = 100, const utility::StringReferenceOptions& options = utility::StringReferenceOptions{}.with_min_length(4));

    StringReferencesList ascii_references(FunctionStart start);
    StringReferencesList unicode_references(FunctionStart start);

private:
    mutable std::shared_mutex m_mutex{};
    std::unordered_map<FunctionStart, StringReferencesList> m_ascii_references{};
    std::unordered_map<FunctionStart, StringReferencesList> m_unicode_references{};
};