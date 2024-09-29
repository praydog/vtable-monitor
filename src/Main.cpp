#include <iostream>
#include <array>
#include <deque>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/base_sink.h>
#include <safetyhook.hpp>

#include <utility/RTTI.hpp>
#include <utility/Memory.hpp>
#include <utility/PointerHook.hpp>
#include <utility/Thread.hpp>
#include <utility/Module.hpp>
#include <utility/String.hpp>
#include <utility/ScopeGuard.hpp>

#include <windows.h>

#define USE_GLFW
#include <glad/glad.h> // Initialize with gladLoadGL()
#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>

#include "Hooker.hpp"


HMODULE g_hModule = NULL;

#if 0
HMODULE choose_module() {
    HMODULE dll = nullptr;

    do {
        std::string dll_name{};
        std::getline(std::cin, dll_name);

        dll = GetModuleHandle(dll_name.c_str());

        if (dll == nullptr) {
            spdlog::info("Failed to find module: {}, try again:", dll_name);
        }
    } while(dll == nullptr);

    return dll;
}

void start() {
    {
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        freopen("CONIN$", "r", stdin);
        SetConsoleTitle("Debug Console");

        spdlog::set_pattern("[%H:%M:%S] [%^%l%$] %v");
        spdlog::set_level(spdlog::level::info);

        spdlog::info("Hello, World!");

        spdlog::info("Enter a DLL name to find all vtables in it:");

        HMODULE dll = choose_module();

        const auto all_vtables = utility::rtti::find_all_vtables(dll);

        if (all_vtables.empty()) {
            spdlog::info("No vtables found in the module!");
            FreeConsole();
            FreeLibraryAndExitThread(g_hModule, 0);
            return;
        }

        spdlog::info("Done! found {} vtables", all_vtables.size());

        std::string line{};

        while (std::getline(std::cin, line)) {
            if (line == "exit") {
                break;
            }

            if (line == "dll") {
                dll = choose_module();
                continue;
            }

            if (line == "unhook") {
                g_hooker.reset();
                continue;
            }

            if (line == "flip") {
                Hooker::s_ignore_vtable_mismatch = !Hooker::s_ignore_vtable_mismatch;
                spdlog::info("Ignore vtable mismatch: {}", Hooker::s_ignore_vtable_mismatch);
                continue;
            }

            if (line == "stats" && g_hooker != nullptr) {
                const auto& hooks = g_hooker->get_hooks();

                for (const auto& hook : hooks) {
                    spdlog::info("{} called {} times", hook->index, hook->calls.load());
                }

                continue;
            }

            if (line == "stats --sorted" && g_hooker != nullptr) {
                const auto& hooks = g_hooker->get_hooks();

                std::vector<std::shared_ptr<Hooker::Hook>> sorted_hooks{hooks.begin(), hooks.end()};
                std::sort(sorted_hooks.begin(), sorted_hooks.end(), [](const auto& a, const auto& b) {
                    return a->calls.load() > b->calls.load();
                });

                for (const auto& hook : sorted_hooks) {
                    if (hook->calls.load() == 0) {
                        continue;
                    }

                    const auto delta = hook->delta.load();
                    double times_per_second = 1.0 / (delta.count() / 1'000'000'000.0);

                    spdlog::info("{} called {} times ({} times per second)", hook->index, hook->calls.load(), times_per_second);
                }

                continue;
            }

            if (line.starts_with("ret ") && g_hooker != nullptr) try {
                const auto index = std::stoi(line.substr(4));
                auto hook = g_hooker->find_hook(index);

                if (hook == nullptr) {
                    spdlog::info("Hook not found for index: {}", index);
                    continue;
                }

                hook->insert_ret();
                continue;
            } catch (...) {
                spdlog::info("Invalid index: {}", line.substr(4));
            }

            if (line.starts_with("restore ") && g_hooker != nullptr) try {
                const auto index = std::stoi(line.substr(8));
                auto hook = g_hooker->find_hook(index);

                if (hook == nullptr) {
                    spdlog::info("Hook not found for index: {}", index);
                    continue;
                }

                hook->restore();
                continue;
            } catch (...) {
                spdlog::info("Invalid index: {}", line.substr(8));
            }
            
            if (line.starts_with("retaddr ") && g_hooker != nullptr) {
                const auto index = std::stoi(line.substr(8));
                auto hook = g_hooker->find_hook(index);

                if (hook == nullptr) {
                    spdlog::info("Hook not found for index: {}", index);
                    continue;
                }

                spdlog::info("Last return address for hook {} is 0x{:x}", index, hook->last_return_address.load());
                continue;
            }

            const auto vtables = utility::rtti::find_vtables(dll, line);

            if (!vtables.empty()) {
                if (vtables.size() == 1) {
                    spdlog::info("VTable: 0x{:x} ({})", vtables[0], line);
                    g_hooker = std::make_unique<Hooker>((uintptr_t*)vtables[0]);
                } else {
                    spdlog::info("Multiple found, which vtable would you like to hook?");

                    for (size_t i = 0; i < vtables.size(); ++i) {
                        spdlog::info("{}: 0x{:x}, {} functions", i, vtables[i], Hooker::count((uintptr_t*)vtables[i]));
                    }

                    size_t index{};
                    std::cin >> index;

                    if (index >= vtables.size()) {
                        spdlog::info("Invalid index: {}", index);
                        continue;
                    }

                    spdlog::info("VTable: 0x{:x} ({})", vtables[index], line);
                    g_hooker = std::make_unique<Hooker>((uintptr_t*)vtables[index]);
                }
            } else {
                spdlog::info("VTable not found for: {}", line);
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        spdlog::info("Exiting...");
    }

    if (g_hModule != nullptr) {
        FreeConsole();
        FreeLibraryAndExitThread(g_hModule, 0);
    }
}
#endif

class ImGuiLogSink : public spdlog::sinks::base_sink<std::mutex> {
public:
    static inline auto sink = std::make_shared<ImGuiLogSink>();

    static std::shared_ptr<ImGuiLogSink>& get() {
        return sink;
    }

    auto& get_mutex() {
        return mutex_;
    }

    auto& get_messages() {
        return m_log_messages;
    }

    void render_log_window() {
        ImGui::SetNextWindowSize(ImVec2(500, 300), ImGuiCond_FirstUseEver);
        if (ImGui::Begin("Log Window", nullptr, ImGuiWindowFlags_AlwaysVerticalScrollbar)) {
            std::lock_guard<std::mutex> lock(this->mutex_);
            for (const auto& message : this->m_log_messages) {
                ImGui::TextUnformatted(message.c_str());
            }

            // Automatically scroll to the bottom when new messages are added
            if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
                ImGui::SetScrollHereY(1.0f);
            }

            ImGui::End();
        }
    }

protected:
    void sink_it_(const spdlog::details::log_msg& msg) override {
        spdlog::memory_buf_t formatted;
        base_sink<std::mutex>::formatter_->format(msg, formatted);

        auto str = fmt::to_string(formatted);

        if (m_log_messages.size() >= max_messages) {
            m_log_messages.pop_front(); // Remove oldest log if we exceed max size.
        }
        m_log_messages.emplace_back(str);
        std::cout << str << std::endl;
    }

    void flush_() override {
        // No need to implement flushing, as logs will be updated automatically in the deque.
    }

private:
    std::deque<std::string> m_log_messages{};
    static constexpr inline size_t max_messages = 1000; // Keep a limit on how many messages to store.
};

std::string selected_module_name{};
HMODULE selected_module{}; // The selected module

void render_module_vtables() {
    auto all_vtables = utility::rtti::find_all_vtables(selected_module);

    if (all_vtables.empty()) {
        ImGui::Text("No vtables found in the module!");
        return;
    }

    // Optional search bar
    static std::array<char, 512> search_buffer{};
    ImGui::InputText("Search", search_buffer.data(), search_buffer.size());

    const auto search_view = std::string_view{search_buffer.data()};
    const auto should_search = !search_view.empty();

    // Filter the vtables
    if (should_search) {
        std::erase_if(all_vtables, [&](const uintptr_t vtable) {
            const auto ti = utility::rtti::get_type_info(&vtable);
            return ti == nullptr || ti->name() == nullptr || std::string_view{ti->name()}.find(search_view) == std::string_view::npos;
        });
    }

    // Create a table for the vtables
    // Layout: Name | Num Functions | Address | Hook button
    ImGui::Columns(4, "vtables", true);
    ImGui::Separator();
    ImGui::Text("Name");
    ImGui::NextColumn();
    ImGui::Text("Count");
    ImGui::NextColumn();
    ImGui::Text("Address");
    ImGui::NextColumn();
    ImGui::Text("Hook");
    ImGui::NextColumn();
    ImGui::Separator();

    static std::unordered_map<uintptr_t, size_t> vtable_counts{};

    for (const auto vtable : all_vtables) {
        const auto ti = utility::rtti::get_type_info(&vtable);
        ImGui::Text("%s", (ti != nullptr && ti->name() != nullptr) ? ti->name() : "Unknown");
        ImGui::NextColumn();
        size_t count = 0;
        if (vtable_counts.contains(vtable)) {
            count = vtable_counts[vtable];
        } else {
            count = Hooker::count((uintptr_t*)vtable);
            vtable_counts[vtable] = count;
        }

        ImGui::Text("%zu", count);
        ImGui::NextColumn();
        ImGui::Text("0x%llx", vtable);
        ImGui::NextColumn();
        ImGui::PushID((void*)vtable);
        if (ImGui::Button("Hook")) {
            g_hooker = std::make_unique<Hooker>((uintptr_t*)vtable);
        }
        ImGui::PopID();
        ImGui::NextColumn();
    }
}

bool render_gui() {
    ImGuiLogSink::get()->render_log_window();

    // Create the GUI interface for Hooker
    bool open = true;
    if (ImGui::Begin("Hook Manager", &open)) {
        if (ImGui::Button("Toggle VTable Mismatch Ignore")) {
            Hooker::s_ignore_vtable_mismatch = !Hooker::s_ignore_vtable_mismatch;
        }

        if (g_hooker != nullptr) {
            const auto target = g_hooker->get_target();
            const auto ti_target = utility::rtti::get_type_info(&target);

            if (ti_target != nullptr && ti_target->name() != nullptr) {
                ImGui::Text("Target: %s", ti_target->name());
            } else {
                ImGui::Text("Target: Unknown");
            }

            const auto& hooks = g_hooker->get_hooks();
            
            ImGui::Columns(4, "hooks", true);
            ImGui::Separator();
            ImGui::Text("Index");
            ImGui::NextColumn();
            ImGui::Text("Calls");
            ImGui::NextColumn();
            ImGui::Text("Last Retaddr");
            ImGui::NextColumn();
            ImGui::Text("Actions");
            ImGui::NextColumn();
            ImGui::Separator();

            for (const auto& hook : hooks) {
                ImGui::Text("%zu", hook->index);
                ImGui::NextColumn();
                ImGui::Text("%zu", hook->calls.load());
                ImGui::NextColumn();
                //ImGui::Text("0x%llx", hook->last_return_address.load());
                if (ImGui::TreeNode(std::format("0x{:x}", hook->last_return_address.load()).c_str())) {
                     const auto callstack = hook->get_callstack();

                    for (const auto addr : callstack) {
                        const auto module_within = utility::get_module_within(addr);

                        if (module_within) {
                            const auto rel = addr - (uintptr_t)*module_within;
                            const auto module_path = utility::get_module_path(*module_within);

                            if (module_path.has_value()) {
                                const auto module_name = module_path->substr(module_path->find_last_of('\\') + 1);
                                ImGui::Text("%s+0x%llx", module_name.c_str(), rel);
                            } else {
                                ImGui::Text("0x%llx", addr);
                            }
                        } else {
                            ImGui::Text("0x%llx", addr);
                        }
                    }

                    ImGui::TreePop();
                }
                ImGui::NextColumn();
                ImGui::PushID((void*)hook.get());
                if (ImGui::Button("Insert Ret")) {
                    hook->insert_ret();
                }

                ImGui::SameLine();

                if (ImGui::Button("Restore")) {
                    hook->restore();
                }

                ImGui::PopID();
                ImGui::NextColumn();
            }
        }

        ImGui::End();
    }

    if (ImGui::Begin("Module Selection", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        auto modules = utility::get_loaded_module_names();

        if (selected_module_name.empty() && !modules.empty()) {
            selected_module_name = utility::narrow(modules[0]); // Usually the first module is the executable.
            selected_module = GetModuleHandleA(selected_module_name.c_str());
        }

        std::sort(modules.begin(), modules.end());

        ImGui::Text("Selected module: %s", selected_module_name.c_str());

        if (ImGui::BeginCombo("Modules", selected_module_name.c_str())) {
            for (const auto& module : modules) {
                const auto narrow_module = utility::narrow(module);
                bool is_selected = (selected_module_name == narrow_module);
                if (ImGui::Selectable(narrow_module.c_str(), is_selected)) {
                    selected_module_name = narrow_module;
                    selected_module = GetModuleHandleA(selected_module_name.c_str());
                }
                if (is_selected) {
                    ImGui::SetItemDefaultFocus();
                }
            }
            ImGui::EndCombo();
        }

        ImGui::End();
    }

    ImGui::SetNextWindowSize(ImVec2(500, 400), ImGuiCond_FirstUseEver);

    if (ImGui::Begin("Module VTables")) {
        render_module_vtables();

        ImGui::End();
    }

    return !open;
}

void start_gui() {
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONIN$", "r", stdin);
    SetConsoleTitle("Debug Console");

    spdlog::set_default_logger(std::make_shared<spdlog::logger>("imgui_logger", ImGuiLogSink::get()));

    spdlog::set_pattern("[%H:%M:%S] [%^%l%$] %v");
    spdlog::set_level(spdlog::level::info);

    spdlog::info("Hello, World!");

#ifdef USE_SDL
    // Initialize SDL
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0) {
        spdlog::error("Failed to initialize SDL: {}", SDL_GetError());
        return;
    }

    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);   // Request OpenGL version 3.x
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 3);   // Request OpenGL 3.3 or higher
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);

    // Set other attributes
    SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);  // Enable double buffering
    SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 24);   // 24-bit depth buffer
    SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 8);  // 8-bit stencil buffer

    // Create an SDL window
    SDL_Window* window = SDL_CreateWindow("Hook Manager", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED, 1280, 720, SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE);

    if (window == nullptr) {
        spdlog::error("Failed to create SDL window: {}", SDL_GetError());
        return;
    }

    SDL_GLContext gl_context = SDL_GL_CreateContext(window);

    if (auto result = SDL_GL_MakeCurrent(window, gl_context); result != 0) {
        spdlog::error("Failed to make OpenGL context current: {}", SDL_GetError());
        return;
    }

    SDL_GL_SetSwapInterval(1); // Enable vsync

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();

    if (ImGui::CreateContext() == nullptr) {
        spdlog::error("Failed to initialize ImGui context");
        return;
    }

    ImGuiIO& io = ImGui::GetIO(); (void)io;

    // Initialize OpenGL loader (Glad, etc.)
    if (gladLoadGL() == 0) {
        spdlog::error("Failed to initialize OpenGL loader");
        return;
    }

    // Setup Platform/Renderer bindings
    if (!ImGui_ImplSDL2_InitForOpenGL(window, gl_context)) {
        spdlog::error("Failed to initialize ImGui SDL2 OpenGL");
        return;
    }
    if (!ImGui_ImplOpenGL3_Init()) {
        spdlog::error("Failed to initialize ImGui OpenGL3");
        return;
    }

    // Main loop
    bool running = true;
    while (running) {
        // Poll SDL events
        SDL_Event event;
        while (SDL_PollEvent(&event)) {
            if (event.type == SDL_QUIT) {
                running = false;
            }
            ImGui_ImplSDL2_ProcessEvent(&event);
        }

        // Start ImGui frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplSDL2_NewFrame(window);
        ImGui::NewFrame();

        // Render the GUI
        render_gui();

        // Render ImGui
        ImGui::Render();
        glViewport(0, 0, 1280, 720);
        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        SDL_GL_SwapWindow(window);
    }

    // Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplSDL2_Shutdown();
    ImGui::DestroyContext();

    SDL_GL_DeleteContext(gl_context);
    SDL_DestroyWindow(window);
    SDL_Quit();
#else if defined(USE_GLFW)
    // Initialize GLFW
    if (!glfwInit()) {
        spdlog::error("Failed to initialize GLFW");
        return;
    }

    // Create GLFW window
    GLFWwindow* window = glfwCreateWindow(1280, 720, "Hook Manager", NULL, NULL);
    if (!window) {
        spdlog::error("Failed to create window");
        glfwTerminate();
        return;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    // Setup ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;

    // Initialize OpenGL loader (Glad, etc.)
    if (gladLoadGL() == 0) {
        spdlog::error("Failed to initialize OpenGL loader");
        return;
    }

    // Setup Platform/Renderer bindings
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    auto cleanupguard = utility::ScopeGuard { [&window]() {
        ImGui_ImplOpenGL3_Shutdown();
        ImGui_ImplGlfw_Shutdown();
        ImGui::DestroyContext();
        glfwDestroyWindow(window);
        glfwTerminate();

        if (g_hModule != nullptr) {
            FreeConsole();
            FreeLibraryAndExitThread(g_hModule, 0);
        }
    }};
    

    // Main loop
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        // Start ImGui frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // Render the GUI
        bool wants_exit = render_gui();

        // Render ImGui
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.1f, 0.1f, 0.1f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);

        if (wants_exit) {
            break;
        }
    }
#endif
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        g_hModule = hModule;
        auto h = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)start_gui, 0, 0, 0);
        if (h != nullptr) {
            CloseHandle(h);
        }
        break;
    }
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}