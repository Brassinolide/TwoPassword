﻿#include "imgui/imgui.h"
#include "imgui/imgui_stdlib.h"
#include "imgui/imgui_impl_glfw.h"
#include "imgui/imgui_impl_opengl3.h"
#define GL_SILENCE_DEPRECATION
#if defined(IMGUI_IMPL_OPENGL_ES2)
    #include <GLES2/gl2.h>
#endif
#include <GLFW/glfw3.h>

#include <string>
#include <array>
#include "tpcs.h"
#include "config.h"
#include "gui.h"
#include "vivoSans-Light.h"

#ifdef _WIN32

    #define GLFW_EXPOSE_NATIVE_WIN32
    #include <GLFW/glfw3native.h>

    #include <windows.h>
    #include <shlobj.h>

    #pragma execution_character_set("utf-8")
    #pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" )

    #ifndef _WIN64
        #error 不再维护32位
    #endif

static std::string SelectFileToOpen_utf8() {
    OPENFILENAMEW ofn = { sizeof(ofn) };
    wchar_t szFile[MAX_PATH] = { 0 };
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFile;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = sizeof(szFile) / sizeof(wchar_t);
    ofn.lpstrFilter = L"All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameW(&ofn) == TRUE) {
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, ofn.lpstrFile, -1, 0, 0, 0, 0);
        std::string utf8(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, ofn.lpstrFile, -1, &utf8[0], size_needed, 0, 0);
        return utf8;
    }
    return "";
}

static std::wstring SelectFileToSave_utf16() {
    OPENFILENAMEW ofn = { sizeof(ofn) };
    wchar_t szFile[MAX_PATH] = { 0 };
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFile;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = sizeof(szFile) / sizeof(wchar_t);
    ofn.lpstrFilter = L"All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT;

    if (GetSaveFileNameW(&ofn) == TRUE) {
        return std::wstring(ofn.lpstrFile);
    }
    return L"";
}

static std::wstring SelectDirectory_utf16() {
    wchar_t szDir[MAX_PATH] = { 0 };
    BROWSEINFOW bi = { 0 };
    bi.hwndOwner = NULL;
    bi.pidlRoot = NULL;
    bi.pszDisplayName = szDir;
    bi.lpszTitle = L"选择保存目录";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    bi.lpfn = NULL;
    bi.lParam = 0;

    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (pidl != NULL) {
        if (SHGetPathFromIDListW(pidl, szDir)) {
            std::wstring result = szDir;
            CoTaskMemFree(pidl);
            return result;
        }
        CoTaskMemFree(pidl);
    }
    return L"";
}

#else
    #error 目前仅支持windows系统
#endif

using namespace std;

static double shannon_entropy(const uint8_t* data, size_t size) {
    if (!data || !size) {
        return 0.0;
    }

    std::array<size_t, 256> frequency = { 0 };
    for (size_t i = 0; i < size; ++i) {
        frequency[data[i]]++;
    }

    double entropy = 0.0;
    for (size_t count : frequency) {
        if (count > 0) {
            double probability = static_cast<double>(count) / size;
            entropy -= probability * log2(probability);
        }
    }

    secure_erase_array(frequency);
    return entropy;
}

void imgui_passfile_selector(int& selected, std::vector<std::string>& passfile) {
    for (int i = 0; i < passfile.size(); i++) {
        ImGui::PushID(i);

        if (ImGui::Selectable(passfile[i].c_str(), selected == i)) {
            selected = i;
        }

        if (selected != -1) {
            if (ImGui::BeginPopupContextItem()) {
                ImGui::Text("%s", passfile[selected].c_str());
                ImGui::Separator();

                if (ImGui::MenuItem("删除")) {
                    passfile.erase(passfile.begin() + selected);
                    selected = -1;
                    ImGui::CloseCurrentPopup();
                }

                ImGui::EndPopup();
            }
        }

        if (ImGui::BeginDragDropSource(ImGuiDragDropFlags_SourceAllowNullID)) {
            ImGui::SetDragDropPayload("change_passfile_order", &i, sizeof(int));

            ImGui::Text("调整顺序 \"%s\"", passfile[i].c_str());
            ImGui::EndDragDropSource();
        }

        if (ImGui::BeginDragDropTarget()) {
            if (const ImGuiPayload* payload = ImGui::AcceptDragDropPayload("change_passfile_order")) {
                int payload_n = *(const int*)payload->Data;

                std::swap(passfile[i], passfile[payload_n]);

                if (selected == payload_n)
                    selected = i;
                else if (selected == i)
                    selected = payload_n;
            }
            ImGui::EndDragDropTarget();
        }

        ImGui::PopID();
    }

    if (ImGui::Button("添加密码文件")) {
        std::string str = SelectFileToOpen_utf8();
        if (str.length()) {
            passfile.push_back(str);
        }
    }
}

bool ImMessageBox_show = false;
const char* ImMessageBox_text = nullptr, * ImMessageBox_caption = nullptr;
void ImMessageBox(const char* text, const char* caption) {
    ImMessageBox_text = text;
    ImMessageBox_caption = caption;
    ImMessageBox_show = true;
}

void ImMessageBox_error(const char* text, bool additional_winapi = false, bool additional_openssl = false, const char* caption = "错误") {
    // 非线程安全，如果需要线程安全请改为TLS变量
    static string err;
    err.clear();
    err = text;

    if (additional_winapi || additional_openssl) {
        err += "\n\n以下是附加错误信息\n";
        if (additional_winapi) {
            err += "WinAPI：";
            err += winapi_get_last_error_utf8();
        }
        if (additional_openssl) {
            err += "OpenSSL：";
            err += openssl_get_last_error_utf8();
        }
    }

    ImMessageBox(err.c_str(), caption);
}

namespace var {
    namespace window {
        bool about = false;
        bool setting = false;
        bool create_password_library = false;
        bool password_generator = false;
        bool passfile_generator = false;
    };
    namespace session {
        namespace add_record {
            string common_name;
            string website;
            string username;
            string password;
            string description;
            void safe_clean() {
                secure_erase_string(common_name);
                secure_erase_string(website);
                secure_erase_string(username);
                secure_erase_string(password);
                secure_erase_string(description);
            }
        };

        namespace search_record {
            string search_keyword;
            bool search_common_name = true;
            bool search_website = true;
            bool search_username = false;
            bool search_description = false;
            int selected = -1;
            int last_selected = 0x7fffffff;

            void safe_clean() {
                secure_erase_string(search_keyword);

                selected = -1;
                last_selected = 0x7fffffff;

                search_common_name = true;
                search_website = true;
                search_username = false;
                search_description = false;
            }
        };

        bool opened = false;
        bool to_exit_session = false;
        string password_lib_path_utf8;
        wstring password_lib_path_utf16;
        uint8_t key[64];
        PasswordLibrary* lib;
        std::string password_utf8;
        std::vector<std::string> passfile_utf8;

        void exit_session() {
            memset(key, 0, 64);
            secure_erase_string(password_lib_path_utf8);
            secure_erase_wstring(password_lib_path_utf16);
            secure_erase_string(password_utf8);
            secure_erase_vector(passfile_utf8);
            PasswordLibrary_free(lib);

            add_record::safe_clean();
            search_record::safe_clean();

            opened = false;
            to_exit_session = false;
        }
    };
};

static void glfw_error_callback(int error, const char* description) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

bool RenderGUI() {
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) {
        return false;
    }

#if defined(IMGUI_IMPL_OPENGL_ES2)
    // GL ES 2.0 + GLSL 100 (WebGL 1.0)
    const char* glsl_version = "#version 100";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 2);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
    glfwWindowHint(GLFW_CLIENT_API, GLFW_OPENGL_ES_API);
#elif defined(IMGUI_IMPL_OPENGL_ES3)
    // GL ES 3.0 + GLSL 300 es (WebGL 2.0)
    const char* glsl_version = "#version 300 es";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
    glfwWindowHint(GLFW_CLIENT_API, GLFW_OPENGL_ES_API);
#elif defined(__APPLE__)
    // GL 3.2 + GLSL 150
    const char* glsl_version = "#version 150";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);  // 3.2+ only
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);            // Required on Mac
#else
    // GL 3.0 + GLSL 130
    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
    //glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);  // 3.2+ only
    //glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);            // 3.0+ only
#endif

    GLFWwindow* window = glfwCreateWindow(1898, 1144, "TwoPassword", nullptr, nullptr);
    if (window == nullptr) {
        return false;
    }

    // 窗口反截图
#if defined(_WIN32) && !defined(_DEBUG)
    SetWindowDisplayAffinity(glfwGetWin32Window(window), WDA_MONITOR);
#endif
   
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;

    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    io.Fonts->Clear();

    ImFont* font = io.Fonts->AddFontFromMemoryCompressedTTF(font_vivoSans_Light, font_vivoSans_Light_size, 25.0f * io.DisplayFramebufferScale.y, nullptr, io.Fonts->GetGlyphRangesChineseFull());
    if (!font) {
        return false;
    }
    io.Fonts->Build();

    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        if (glfwGetWindowAttrib(window, GLFW_ICONIFIED) != 0) {
            ImGui_ImplGlfw_Sleep(10);
            continue;
        }
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();
        {
            ImGui::Begin("HashMe", 0, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar);
            ImGui::SetWindowPos(ImVec2(0, 0), ImGuiCond_Always);
            ImGui::SetWindowSize(ImVec2(ImGui::GetIO().DisplaySize.x, ImGui::GetIO().DisplaySize.y), ImGuiCond_Always);

            if (ImGui::BeginMenuBar())
            {
                if (ImGui::BeginMenu("TwoPassword"))
                {
                    if (ImGui::MenuItem("设置")) {
                        var::window::setting = true;
                    }
                    if (ImGui::MenuItem("关于")) {
                        var::window::about = true;
                    }
                    ImGui::Separator();
                    if (ImGui::MenuItem("安全退出")) {
                        safe_exit();
                    }
                    ImGui::EndMenu();
                }
                if (ImGui::BeginMenu("工具"))
                {
                    if (ImGui::MenuItem("创建密码库")) {
                        var::window::create_password_library = true;
                    }
                    ImGui::Separator();
                    if (ImGui::MenuItem("密码生成器")) {
                        var::window::password_generator = true;
                    }
                    if (ImGui::MenuItem("密码文件生成器")) {
                        var::window::passfile_generator = true;
                    }
                    ImGui::EndMenu();
                }
                ImGui::EndMenuBar();
            }

            if (var::session::opened) {
                ImGui::Text("当前密码库：%s", var::session::password_lib_path_utf8.c_str());
                ImGui::Text("创建时间：%s", tpcs4_get_create_time_utc_iso8601(var::session::lib).c_str());
                ImGui::Text("更新时间：%s", tpcs4_get_update_time_utc_iso8601(var::session::lib).c_str());
                ImGui::Text("密码记录数：%d", tpcs4_get_records_size(var::session::lib));
                if (ImGui::Button("添加")) {
                    ImGui::OpenPopup("add_password_record");
                }

                if (ImGui::BeginPopup("add_password_record"))
                {
                    ImGui::InputText("友好名称", &var::session::add_record::common_name);
                    if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                        ImGui::SetTooltip("友好名称的显示优先级大于网站地址");
                    ImGui::InputText("*网站地址", &var::session::add_record::website);
                    ImGui::InputText("*用户名", &var::session::add_record::username);
                    ImGui::InputText("*密码", &var::session::add_record::password);
                    ImGui::InputTextMultiline("备注", &var::session::add_record::description);

                    do
                    {
                        if (ImGui::Button("添加")) {
                            if (var::session::add_record::website.empty() || var::session::add_record::username.empty() || var::session::add_record::password.empty()) {
                                ImMessageBox_error("必填项未填");
                                break;
                            }
                            PasswordRecord* rec = tpcs4_create_record(var::session::add_record::website, var::session::add_record::username, var::session::add_record::password, var::session::add_record::description, var::session::add_record::common_name);
                            if (!rec || !tpcs4_append_record(var::session::lib, rec)) {
                                ImMessageBox_error("无法创建记录", false, true);
                                break;
                            }

                            var::session::add_record::safe_clean();

                            ImGui::CloseCurrentPopup();
                        }
                    } while (false);

                    ImGui::EndPopup();
                }

                ImGui::SameLine();
                if (ImGui::Button("保存")) {
                    do
                    {
                        uint8_t salt[48] = { 0 };
                        if (RAND_bytes(salt, 48) != 1) {
                            ImMessageBox_error("无法保存密码库", false, true);
                            break;
                        }

                        // 每次保存都用不同的盐，所以每次保存都需要派生一次密钥
                        if (!tocs4_save_library_kdf(var::session::password_lib_path_utf16.c_str(), var::session::lib, var::session::key, var::session::passfile_utf8, var::session::password_utf8)) {
                            ImMessageBox_error("无法保存密码库", true, true);
                            break;
                        }

                        ImMessageBox("保存成功", "成功");
                    } while (false);
                }
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                    ImGui::SetTooltip("会短暂卡顿，请耐心等待");

                ImGui::SameLine();
                if (ImGui::Button("退出")) {
                    var::session::to_exit_session = true;
                }

                ImGui::InputText("搜索", &var::session::search_record::search_keyword);
                ImGui::TextUnformatted("搜索范围：");
                ImGui::SameLine();
                ImGui::Checkbox("友好名称", &var::session::search_record::search_common_name);
                ImGui::SameLine();
                ImGui::Checkbox("网站地址", &var::session::search_record::search_website);
                ImGui::SameLine();
                ImGui::Checkbox("用户名", &var::session::search_record::search_username);
                ImGui::SameLine();
                ImGui::Checkbox("备注", &var::session::search_record::search_description);

                ImGui::BeginChild("left pane", ImVec2(200, 0), ImGuiChildFlags_Borders | ImGuiChildFlags_ResizeX);

                std::vector<int> filtered_indices;
                for (int i = 0; i < tpcs4_get_records_size(var::session::lib); i++) {
                    string_PasswordRecord search_rec;
                    tpcs4_get_record(var::session::lib, search_rec, i);

                    std::string search_data;
                    if (var::session::search_record::search_common_name) {
                        search_data += search_rec.common_name;
                    }
                    if (var::session::search_record::search_website) {
                        search_data += search_rec.website;
                    }
                    if (var::session::search_record::search_username) {
                        search_data += search_rec.username;
                    }
                    if (var::session::search_record::search_description) {
                        search_data += search_rec.description;
                    }

                    std::transform(search_data.begin(), search_data.end(), search_data.begin(), ::tolower);
                    std::transform(var::session::search_record::search_keyword.begin(), var::session::search_record::search_keyword.end(), var::session::search_record::search_keyword.begin(), ::tolower);

                    if (var::session::search_record::search_keyword.empty() || search_data.find(var::session::search_record::search_keyword) != std::string::npos) {
                        filtered_indices.push_back(i);
                    }
                    secure_erase_string(search_data);
                    secure_erase_string_PasswordRecord(search_rec);
                }

                for (int display_id = 0; display_id < filtered_indices.size(); display_id++) {
                    int i = filtered_indices[display_id];
                    ImGui::PushID(display_id);

                    string_PasswordRecord display_rec;
                    tpcs4_get_record(var::session::lib, display_rec, i);

                    const char* show_name = display_rec.common_name.empty() ? display_rec.website.c_str() : display_rec.common_name.c_str();

                    if (ImGui::Selectable(show_name, var::session::search_record::selected == i)) {
                        var::session::search_record::selected = i;
                    }

                    if (ImGui::BeginPopupContextItem()) {
                        ImGui::TextUnformatted(show_name);
                        ImGui::Separator();

                        if (ImGui::MenuItem("删除")) {
                            tpcs4_delete_record(var::session::lib, i);
                            var::session::search_record::selected = -1;
                            var::session::search_record::last_selected = 0x7fffffff;
                            ImGui::CloseCurrentPopup();
                        }

                        ImGui::EndPopup();
                    }

                    secure_erase_string_PasswordRecord(display_rec);

                    ImGui::PopID();
                }
                ImGui::EndChild();

                ImGui::SameLine();

                ImGui::BeginChild("item view", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
                if (var::session::search_record::selected != -1 && var::session::search_record::selected < tpcs4_get_records_size(var::session::lib)) {
                    static string_PasswordRecord selected_rec;
                    if (var::session::search_record::last_selected != var::session::search_record::selected) {
                        tpcs4_get_record(var::session::lib, selected_rec, var::session::search_record::selected);
                        var::session::search_record::last_selected = var::session::search_record::selected;
                    }

                    const char* show_name = selected_rec.common_name.empty() ? selected_rec.website.c_str() : selected_rec.common_name.c_str();
                    ImGui::TextUnformatted(show_name);

                    ImGui::Separator();

                    static bool readonly = true;
                    ImGui::Checkbox("只读", &readonly);
                    ImGui::InputText("友好名称", &selected_rec.common_name, readonly ? ImGuiInputTextFlags_ReadOnly : 0);
                    ImGui::InputText("网站地址", &selected_rec.website, readonly ? ImGuiInputTextFlags_ReadOnly : 0);
                    ImGui::InputText("用户名", &selected_rec.username, readonly ? ImGuiInputTextFlags_ReadOnly : 0);
                    ImGui::InputText("密码", &selected_rec.password, readonly ? ImGuiInputTextFlags_ReadOnly : 0);
                    ImGui::InputTextMultiline("备注", &selected_rec.description, ImVec2(0, 0), readonly ? ImGuiInputTextFlags_ReadOnly : 0);

                    if (!readonly) {
                        if (ImGui::Button("更新")) {
                            tpcs4_update_record(var::session::lib, selected_rec, var::session::search_record::selected);
                        }
                    }
                }

                if (var::session::to_exit_session) {
                    var::session::exit_session();
                }

                ImGui::EndChild();
            }
            else {
                ImGui::InputText("密码库", &var::session::password_lib_path_utf8);
                ImGui::SameLine();
                if (ImGui::Button("选择")) {
                    std::string str = SelectFileToOpen_utf8();
                    if (str.length()) {
                        var::session::password_lib_path_utf8 = str;

                        var::session::password_lib_path_utf16.clear();
                        utf8::utf8to16(str.begin(), str.end(), back_inserter(var::session::password_lib_path_utf16));
                    }
                }

                ImGui::Separator();

                static bool show_password = false;
                ImGui::InputText("密码", &var::session::password_utf8, show_password ? 0 : ImGuiInputTextFlags_Password);
                ImGui::Checkbox("显示密码", &show_password);

                ImGui::Separator();

                static int selected = -1;
                imgui_passfile_selector(selected, var::session::passfile_utf8);

                ImGui::Separator();

                do
                {
                    if (ImGui::Button("打开", ImVec2(50, 50))) {
                        var::session::lib = tpcs4_read_library_kdf(var::session::password_lib_path_utf16.c_str(), var::session::key, var::session::passfile_utf8, var::session::password_utf8);
                        if (!var::session::lib) {
                            ImMessageBox_error("无法打开密码库", true, true);
                            break;
                        }
                        var::session::opened = true;
                    }
                } while (false);

                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                    ImGui::SetTooltip("会短暂卡顿，请耐心等待");
            }

            if (var::window::setting) {
                ImGui::Begin("设置", &var::window::setting, ImGuiWindowFlags_AlwaysAutoResize);

                static int memsafe = -1;
                if (memsafe == -1) {
                    memsafe = config.config_get_int("memsafe", 0, 2, 0);
                }
                ImGui::Combo("内存安全选项", &memsafe, "无内存安全\0灵活\0严格\0\0");
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                    ImGui::SetTooltip("重启程序后生效");

                if (ImGui::Button("保存")) {
                    config.config_set_int("memsafe", memsafe);

                    if (!config.save_config_file()) {
                        ImMessageBox_error("保存失败", true);
                    }
                    else {
                        ImMessageBox("保存成功", "成功");
                    }
                }

                ImGui::End();
            }

            if (var::window::create_password_library) {
                ImGui::Begin("创建密码库", &var::window::create_password_library, ImGuiWindowFlags_AlwaysAutoResize);

                static std::string password;
                static std::string repassword;
                static bool use_password = true;
                ImGui::Checkbox("使用密码", &use_password);
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                    ImGui::SetTooltip("建议使用中文、英文、数字、全角符号、半角符号混合的强密码（例如某句易记的名人名言）\n密码丢失后无法找回！");

                if (use_password) {
                    static bool show_password = false;
                    ImGui::InputText("密码", &password, show_password ? 0 : ImGuiInputTextFlags_Password);
                    ImGui::InputText("再次输入密码", &repassword, show_password ? 0 : ImGuiInputTextFlags_Password);
                    ImGui::Checkbox("显示密码", &show_password);
                    ImGui::Text("密码长度（UTF-8）：%d", password.length());
                    ImGui::Text("密码香农熵：%f", shannon_entropy((const uint8_t*)password.c_str(), password.length()));
                }

                ImGui::Separator();

                static std::vector<std::string> passfile;
                static bool use_passfile = false;
                ImGui::Checkbox("使用密码文件", &use_passfile);
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                    ImGui::SetTooltip("只有前8 KiB有效\n顺序敏感");
                if (use_passfile) {
                    static int selected = -1;
                    imgui_passfile_selector(selected, passfile);
                }

                ImGui::Separator();

                do {
                    if (ImGui::Button("创建", ImVec2(50, 50))) {
                        if (!use_password && !use_passfile) {
                            ImMessageBox_error("请至少选择一种认证方式");
                            break;
                        }

                        if (use_password) {
                            if (password != repassword) {
                                ImMessageBox_error("两次输入的密码不相同，请检查后重试");
                                break;
                            }

                            if (password.length() < 3) {
                                ImMessageBox_error("密码过短");
                                break;
                            }
                        }

                        if (use_passfile) {
                            if (!passfile.size()) {
                                ImMessageBox_error("请选择至少一个密钥文件");
                                break;
                            }
                        }

                        PasswordLibrary* lib = tpcs4_create_library();
                        if (!tocs4_save_library_kdf(SelectFileToSave_utf16().c_str(), lib, nullptr, passfile, password)) {
                            ImMessageBox_error("无法创建密码库", true, true);
                            break;
                        }
                        PasswordLibrary_free(lib);
                        secure_erase_string(password);
                        secure_erase_string(repassword);
                        secure_erase_vector(passfile);

                        ImMessageBox("密码库创建成功", "创建成功");

                        var::window::create_password_library = false;
                    }
                } while (false);

                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                    ImGui::SetTooltip("会短暂卡顿，请耐心等待");

                ImGui::End();
            }

            if (var::window::about) {
                ImGui::Begin("关于", &var::window::about, ImGuiWindowFlags_AlwaysAutoResize);
                ImGui::TextUnformatted("TwoPassword | 安全的密码管理器");
                ImGui::Separator();
                ImGui::Text("程序版本：%s\nImGui版本：%s\nOpenSSL版本：%s", "0.0.1", IMGUI_VERSION, OpenSSL_version(OPENSSL_VERSION));
                ImGui::Text("UI刷新率：%.3f ms/frame (%.1f FPS)", 1000.0f / io.Framerate, io.Framerate);
                ImGui::TextLinkOpenURL("开源地址", "https://github.com/Brassinolide/TwoPassword");
                ImGui::End();
            }

            if (var::window::passfile_generator) {
                ImGui::Begin("密码文件生成器", &var::window::passfile_generator, ImGuiWindowFlags_AlwaysAutoResize);

                static int length = 1;
                ImGui::SliderInt("生成数量", &length, 1, 100);

                if (ImGui::Button("生成")) {
                    wstring path = SelectDirectory_utf16();
                    for (int i = 0; i < length; ++i) {
                        uint8_t buffer[8_KiB] = { 0 };
                        if (RAND_bytes(buffer, 8_KiB) != 1) {
                            continue;
                        }

                        wstring saveto = path + L"\\" + to_wstring(i) + L".passfile";

                        HANDLE hFile = CreateFileW(saveto.c_str(), GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
                        if (hFile == INVALID_HANDLE_VALUE) {
                            continue;
                        }

                        DWORD dwWrite = 0;
                        WriteFile(hFile, buffer, 8_KiB, &dwWrite, 0);
                        CloseHandle(hFile);
                    }
                }
                ImGui::End();
            }

            if (var::window::password_generator) {
                ImGui::Begin("密码生成器", &var::window::password_generator, ImGuiWindowFlags_AlwaysAutoResize);
                static bool alpha = true;
                ImGui::Checkbox("字母", &alpha);
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                    ImGui::SetTooltip("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

                ImGui::SameLine();

                static bool number = true;
                ImGui::Checkbox("数字", &number);
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                    ImGui::SetTooltip("0123456789");

                ImGui::SameLine();

                static bool common_symbol = true;
                ImGui::Checkbox("常见特殊符号（转义友好、文件名友好）", &common_symbol);
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                    ImGui::SetTooltip("~!=+-_,[]{}@#$%^;");

                static int length = 16;
                ImGui::SliderInt("长度", &length, 3, 100);

                ImGui::Separator();

                static string password;
                if (ImGui::Button("生成")) {
                    string chars = "";
                    if (alpha) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
                    if (number) chars += "0123456789";
                    if (common_symbol) chars += "~!=+-_,[]{}@#$%^;";

                    if (chars.empty()) {
                        password = "请至少选择一种字符集";
                    }
                    else {
                        unsigned char* rand_bytes = new unsigned char[length];
                        if (RAND_bytes(rand_bytes, length) == 1) {
                            password.clear();
                            for (int i = 0; i < length; i++) {
                                size_t index = rand_bytes[i] % chars.length();
                                password += chars[index];
                            }
                        }
                        else {
                            password = "随机数生成失败";
                        }
                        delete[] rand_bytes;
                    }
                }

                ImGui::InputText("密码", &password, ImGuiInputTextFlags_ReadOnly);

                ImGui::Text("密码香农熵：%f", shannon_entropy((const uint8_t*)password.c_str(), password.length()));
                ImGui::End();
            }

            if (ImMessageBox_show) {
                if (ImGui::BeginPopupModal(ImMessageBox_caption, NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                    ImGui::TextUnformatted(ImMessageBox_text);
                    ImGui::Separator();
                    if (ImGui::Button("确定", ImVec2(120, 0))) { ImMessageBox_show = false; ImGui::CloseCurrentPopup(); }
                    ImGui::EndPopup();
                }
                ImGui::OpenPopup(ImMessageBox_caption);
            }

            ImGui::End();
        }

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(clear_color.x * clear_color.w, clear_color.y * clear_color.w, clear_color.z * clear_color.w, clear_color.w);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
