#pragma execution_character_set("utf-8")
#include <d3d9.h>
#include <array>
#include <shlobj.h>
#include <algorithm>
#include "imgui/imgui.h"
#include "imgui/imgui_impl_dx9.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_stdlib.h"
#include "vivoSans-Light.h"
#include "tpcs.h"
#include "config.h"

using namespace std;

#define RGBA_TO_IMVEC4(r, g, b, a) ImVec4((float)r / 255.0f, (float)g / 255.0f, (float)b / 255.0f, (float)a / 255.0f)

static LPDIRECT3D9              g_pD3D = nullptr;
static LPDIRECT3DDEVICE9        g_pd3dDevice = nullptr;
static bool                     g_DeviceLost = false;
static UINT                     g_ResizeWidth = 0, g_ResizeHeight = 0;
static D3DPRESENT_PARAMETERS    g_d3dpp = {};

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void ResetDevice();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

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

static std::string SelectFileToOpen_utf8(){
    OPENFILENAMEW ofn = { sizeof(ofn) };
    wchar_t szFile[MAX_PATH] = {0};
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

    if (GetOpenFileNameW(&ofn) == TRUE){
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
    bi.lpszTitle = L"ѡ�񱣴�Ŀ¼";
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

                if (ImGui::MenuItem("ɾ��")) {
                    passfile.erase(passfile.begin() + selected);
                    selected = -1;
                    ImGui::CloseCurrentPopup();
                }

                ImGui::EndPopup();
            }
        }

        if (ImGui::BeginDragDropSource(ImGuiDragDropFlags_SourceAllowNullID)) {
            ImGui::SetDragDropPayload("change_passfile_order", &i, sizeof(int));

            ImGui::Text("����˳�� \"%s\"", passfile[i].c_str());
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

    if (ImGui::Button("��������ļ�")) {
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

void ImMessageBox_error(const char* text, bool additional_winapi = false, bool additional_openssl = false, const char* caption = "����") {
    // ���̰߳�ȫ�������Ҫ�̰߳�ȫ���ΪTLS����
    static string err;
    err.clear();
    err = text;

    if (additional_winapi || additional_openssl) {
        err += "\n\n�����Ǹ��Ӵ�����Ϣ\n";
        if (additional_winapi) {
            err += "WinAPI��";
            err += winapi_get_last_error_utf8();
        }
        if (additional_openssl) {
            err += "OpenSSL��";
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
            string search;
            bool search_common_name = true;
            bool search_website = true;
            bool search_username = false;
            bool search_description = false;
            int selected = -1;
            int last_selected = 0x7fffffff;

            void safe_clean() {
                secure_erase_string(search);

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
            memset(var::session::key, 0, 64);
            secure_erase_string(var::session::password_lib_path_utf8);
            secure_erase_wstring(var::session::password_lib_path_utf16);
            secure_erase_string(var::session::password_utf8);
            secure_erase_vector(var::session::passfile_utf8);
            PasswordLibrary_free(var::session::lib);

            var::session::add_record::safe_clean();
            var::session::search_record::safe_clean();

            var::session::opened = false;
            var::session::to_exit_session = false;
        }
    };
};

bool RenderGUI() {
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"TwoPassword", nullptr };
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"TwoPassword", WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800, nullptr, nullptr, wc.hInstance, nullptr);

#ifndef _DEBUG
    SetWindowDisplayAffinity(hwnd, WDA_MONITOR);
#endif 

    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return false;
    }

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;

    ImGui::StyleColorsDark();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX9_Init(g_pd3dDevice);

    // AI�����������Ż��������������ļ�����ϳ��������⣨����ģ������С������ȣ�����issue

    ImFontConfig fontConfig;
    fontConfig.RasterizerMultiply = 1.2f; // ��ǿ�Աȶȣ�����ģ����
    fontConfig.OversampleH = 3;   // ˮƽ�����������ֿ���ݣ�Ĭ��ֵ 3
    fontConfig.OversampleV = 1;   // ��ֱ��������Ĭ��ֵ 1
    fontConfig.PixelSnapH = false; // ��ǿ�����ض��룬���������ƽ����

    // ���������С
    float baseFontSize = 16.0f; // ���������С
    float scale = io.DisplayFramebufferScale.x; // ��ȡ DPI ���ű���
    float fontSize = baseFontSize * scale; // ���� DPI ����
    fontSize = max(std::round(fontSize), 18.0f); // ��С 18.0f ���������뵽����

    // ��������
    io.Fonts->Clear(); // ���֮ǰ�����壨�����Ҫ��̬������
    io.Fonts->AddFontFromMemoryCompressedTTF(font_vivoSans_Light, font_vivoSans_Light_size, fontSize, &fontConfig, io.Fonts->GetGlyphRangesChineseFull());
    io.Fonts->Build(); // ��������

    bool show_demo_window = true;
    bool show_another_window = false;
    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

    bool done = false;
    while (!done) {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done)
            break;

        if (g_DeviceLost)
        {
            HRESULT hr = g_pd3dDevice->TestCooperativeLevel();
            if (hr == D3DERR_DEVICELOST)
            {
                ::Sleep(10);
                continue;
            }
            if (hr == D3DERR_DEVICENOTRESET)
                ResetDevice();
            g_DeviceLost = false;
        }

        if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
            g_d3dpp.BackBufferWidth = g_ResizeWidth;
            g_d3dpp.BackBufferHeight = g_ResizeHeight;
            g_ResizeWidth = g_ResizeHeight = 0;
            ResetDevice();
        }

        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        {
            ImGui::Begin("HashMe", 0, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoScrollbar);
            ImGui::SetWindowPos(ImVec2(0, 0), ImGuiCond_Always);
            ImGui::SetWindowSize(ImVec2(ImGui::GetIO().DisplaySize.x, ImGui::GetIO().DisplaySize.y), ImGuiCond_Always);

            if (ImGui::BeginMenuBar())
            {
                if (ImGui::BeginMenu("TwoPassword"))
                {
                    if (ImGui::MenuItem("����")) {
                        var::window::setting = true;
                    }
                    if (ImGui::MenuItem("����")) {
                        var::window::about = true;
                    }
                    ImGui::Separator();
                    if (ImGui::MenuItem("��ȫ�˳�")) {
                        safe_exit();
                    }
                    ImGui::EndMenu();
                }
                if (ImGui::BeginMenu("����"))
                {
                    if (ImGui::MenuItem("���������")) {
                        var::window::create_password_library = true;
                    }
                    ImGui::Separator();
                    if (ImGui::MenuItem("����������")) {
                        var::window::password_generator = true;
                    }
                    if (ImGui::MenuItem("�����ļ�������")) {
                        var::window::passfile_generator = true;
                    }
                    ImGui::EndMenu();
                }
                ImGui::EndMenuBar();
            }

            if (var::session::opened) {
                ImGui::Text("��ǰ����⣺%s", var::session::password_lib_path_utf8.c_str());
                ImGui::Text("����ʱ�䣺%s", tpcs4_get_create_time_utc_iso8601(var::session::lib).c_str());
                ImGui::Text("����ʱ�䣺%s", tpcs4_get_update_time_utc_iso8601(var::session::lib).c_str());
                ImGui::Text("�����¼����%d", tpcs4_get_records_size(var::session::lib));
                if (ImGui::Button("���")) {
                    ImGui::OpenPopup("add_password_record");
                }

                if (ImGui::BeginPopup("add_password_record"))
                {
                    ImGui::InputText("�Ѻ�����", &var::session::add_record::common_name);
                    if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                        ImGui::SetTooltip("�Ѻ����Ƶ���ʾ���ȼ�������վ��ַ");
                    ImGui::InputText("*��վ��ַ", &var::session::add_record::website);
                    ImGui::InputText("*�û���", &var::session::add_record::username);
                    ImGui::InputText("*����", &var::session::add_record::password);
                    ImGui::InputTextMultiline("��ע", &var::session::add_record::description);

                    do
                    {
                        if (ImGui::Button("���")) {
                            if (var::session::add_record::website.empty() || var::session::add_record::username.empty() || var::session::add_record::password.empty()) {
                                ImMessageBox_error("������δ��");
                                break;
                            }
                            PasswordRecord * rec = tpcs4_create_record(var::session::add_record::website, var::session::add_record::username, var::session::add_record::password, var::session::add_record::description, var::session::add_record::common_name);
                            if (!rec || !tpcs4_append_record(var::session::lib, rec)) {
                                ImMessageBox_error("�޷�������¼", false, true);
                                break;
                            }

                            var::session::add_record::safe_clean();

                            ImGui::CloseCurrentPopup();
                        }
                    } while (false);

                    ImGui::EndPopup();
                }

                ImGui::SameLine();
                if (ImGui::Button("����")) {
                    do
                    {
                        uint8_t salt[48] = { 0 };
                        if (RAND_bytes(salt, 48) != 1) {
                            ImMessageBox_error("�޷����������", false, true);
                            break;
                        }

                        // ÿ�α��涼�ò�ͬ���Σ�����ÿ�α��涼��Ҫ����һ����Կ
                        if (!tocs4_save_library_kdf(var::session::password_lib_path_utf16.c_str(), var::session::lib, var::session::key, var::session::passfile_utf8, var::session::password_utf8)) {
                            ImMessageBox_error("�޷����������", true, true);
                            break;
                        }

                        ImMessageBox("����ɹ�", "�ɹ�");
                    } while (false);
                }
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                    ImGui::SetTooltip("����ݿ��٣������ĵȴ�");

                ImGui::SameLine();
                if (ImGui::Button("�˳�")) {
                    var::session::to_exit_session = true;
                }

                ImGui::InputText("����", &var::session::search_record::search);
                ImGui::TextUnformatted("������Χ��");
                ImGui::SameLine();
                ImGui::Checkbox("�Ѻ�����", &var::session::search_record::search_common_name);
                ImGui::SameLine();
                ImGui::Checkbox("��վ��ַ", &var::session::search_record::search_website);
                ImGui::SameLine();
                ImGui::Checkbox("�û���", &var::session::search_record::search_username);
                ImGui::SameLine();
                ImGui::Checkbox("��ע", &var::session::search_record::search_description);

                ImGui::BeginChild("left pane", ImVec2(200, 0), ImGuiChildFlags_Borders | ImGuiChildFlags_ResizeX);

                std::vector<int> filtered_indices;
                for (int i = 0; i < tpcs4_get_records_size(var::session::lib); i++) {
                    string_PasswordRecord search_rec;
                    tpcs4_get_record(var::session::lib, search_rec, i);

                    std::string to_search;
                    if (var::session::search_record::search_common_name) {
                        to_search += search_rec.common_name;
                    }
                    if (var::session::search_record::search_website) {
                        to_search += search_rec.website;
                    }
                    if (var::session::search_record::search_username) {
                        to_search += search_rec.username;
                    }
                    if (var::session::search_record::search_description) {
                        to_search += search_rec.description;
                    }

                    std::transform(to_search.begin(), to_search.end(), to_search.begin(), ::tolower);
                    std::string search_lower = var::session::search_record::search;
                    std::transform(search_lower.begin(), search_lower.end(), search_lower.begin(), ::tolower);

                    if (var::session::search_record::search.empty() || to_search.find(search_lower) != std::string::npos) {
                        filtered_indices.push_back(i);
                    }
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

                        if (ImGui::MenuItem("ɾ��")) {
                            tpcs4_delete_record(var::session::lib, i);
                            var::session::search_record::selected = -1;
                            var::session::search_record::last_selected = 0x7fffffff;
                            ImGui::CloseCurrentPopup();
                        }

                        ImGui::EndPopup();
                    }

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
                    ImGui::Checkbox("ֻ��", &readonly);
                    ImGui::InputText("�Ѻ�����", &selected_rec.common_name, readonly ? ImGuiInputTextFlags_ReadOnly : 0);
                    ImGui::InputText("��վ��ַ", &selected_rec.website, readonly ? ImGuiInputTextFlags_ReadOnly : 0);
                    ImGui::InputText("�û���", &selected_rec.username, readonly ? ImGuiInputTextFlags_ReadOnly : 0);
                    ImGui::InputText("����", &selected_rec.password, readonly ? ImGuiInputTextFlags_ReadOnly : 0);
                    ImGui::InputTextMultiline("��ע", &selected_rec.description, ImVec2(0, 0), readonly ? ImGuiInputTextFlags_ReadOnly : 0);
                    
                    if (!readonly) {
                        if (ImGui::Button("����")) {
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
                ImGui::InputText("�����", &var::session::password_lib_path_utf8);
                ImGui::SameLine();
                if (ImGui::Button("ѡ��")) {
                    std::string str = SelectFileToOpen_utf8();
                    if (str.length()) {
                        var::session::password_lib_path_utf8 = str;

                        var::session::password_lib_path_utf16.clear();
                        utf8::utf8to16(str.begin(), str.end(), back_inserter(var::session::password_lib_path_utf16));
                    }
                }

                ImGui::Separator();

                static bool show_password = false;
                ImGui::InputText("����", &var::session::password_utf8, show_password ? 0 : ImGuiInputTextFlags_Password);
                ImGui::Checkbox("��ʾ����", &show_password);

                ImGui::Separator();

                static int selected = -1;
                imgui_passfile_selector(selected, var::session::passfile_utf8);

                ImGui::Separator();

                do
                {
                    if (ImGui::Button("��", ImVec2(50, 50))) {
                        var::session::lib = tpcs4_read_library_kdf(var::session::password_lib_path_utf16.c_str(), var::session::key, var::session::passfile_utf8, var::session::password_utf8);
                        if (!var::session::lib) {
                            ImMessageBox_error("�޷��������", true, true);
                            break;
                        }
                        var::session::opened = true;
                    }
                } while (false);

                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                    ImGui::SetTooltip("����ݿ��٣������ĵȴ�");
            }

            if (var::window::setting) {
                ImGui::Begin("����", &var::window::setting, ImGuiWindowFlags_AlwaysAutoResize);

                static int memsafe = -1;
                if (memsafe == -1) {
                    memsafe = config.config_get_int("memsafe", 0, 2, 0);
                }
                ImGui::Combo("�ڴ氲ȫѡ��", &memsafe, "���ڴ氲ȫ\0���\0�ϸ�\0\0");
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                    ImGui::SetTooltip("�����������Ч");

                if (ImGui::Button("����")) {
                    config.config_set_int("memsafe", memsafe);

                    if (!config.save_config_file()) {
                        ImMessageBox_error("����ʧ��", true);
                    }
                    else {
                        ImMessageBox("����ɹ�", "�ɹ�");
                    }
                }

                ImGui::End();
            }

            if (var::window::create_password_library) {
                ImGui::Begin("���������", &var::window::create_password_library, ImGuiWindowFlags_AlwaysAutoResize);

                static std::string password;
                static std::string repassword;
                static bool use_password = true;
                ImGui::Checkbox("ʹ������", &use_password);
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                    ImGui::SetTooltip("����ʹ�����ġ�Ӣ�ġ����֡�ȫ�Ƿ��š���Ƿ��Ż�ϵ�ǿ���루����ĳ���׼ǵ��������ԣ�\n���붪ʧ���޷��һأ�");

                if (use_password) {
                    static bool show_password = false;
                    ImGui::InputText("����", &password, show_password ? 0 : ImGuiInputTextFlags_Password);
                    ImGui::InputText("�ٴ���������", &repassword, show_password ? 0 : ImGuiInputTextFlags_Password);
                    ImGui::Checkbox("��ʾ����", &show_password);
                    ImGui::Text("���볤�ȣ�UTF-8����%d", password.length());
                    ImGui::Text("������ũ�أ�%f", shannon_entropy((const uint8_t*)password.c_str(), password.length()));
                }

                ImGui::Separator();

                static std::vector<std::string> passfile;
                static bool use_passfile = false;
                ImGui::Checkbox("ʹ�������ļ�", &use_passfile);
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                    ImGui::SetTooltip("ֻ��ǰ8 KiB��Ч\n˳������");
                if (use_passfile) {
                    static int selected = -1;
                    imgui_passfile_selector(selected, passfile);
                }

                ImGui::Separator();

                do {
                    if (ImGui::Button("����", ImVec2(50, 50))) {
                        if (!use_password && !use_passfile) {
                            ImMessageBox_error("������ѡ��һ����֤��ʽ");
                            break;
                        }

                        if (use_password) {
                            if (password != repassword) {
                                ImMessageBox_error("������������벻��ͬ�����������");
                                break;
                            }

                            if (password.length() < 3) {
                                ImMessageBox_error("�������");
                                break;
                            }
                        }

                        if (use_passfile) {
                            if (!passfile.size()) {
                                ImMessageBox_error("��ѡ������һ����Կ�ļ�");
                                break;
                            }
                        }

                        PasswordLibrary* lib = tpcs4_create_library();
                        if (!tocs4_save_library_kdf(SelectFileToSave_utf16().c_str(), lib, nullptr, passfile, password)) {
                            ImMessageBox_error("�޷����������", true, true);
                            break;
                        }
                        PasswordLibrary_free(lib);
                        secure_erase_string(password);
                        secure_erase_string(repassword);
                        secure_erase_vector(passfile);

                        ImMessageBox("����ⴴ���ɹ�", "�����ɹ�");

                        var::window::create_password_library = false;
                    }
                } while (false);

                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                    ImGui::SetTooltip("����ݿ��٣������ĵȴ�");

                ImGui::End();
            }

            if (var::window::about) {
                ImGui::Begin("����", &var::window::about, ImGuiWindowFlags_AlwaysAutoResize);
                ImGui::TextUnformatted("TwoPassword | ��ȫ�����������");
                ImGui::Separator();
                ImGui::Text("����汾��%s\nImGui�汾��%s\nOpenSSL�汾��%s", "0.0.1", IMGUI_VERSION, OpenSSL_version(OPENSSL_VERSION));
                ImGui::Text("UIˢ���ʣ�%.3f ms/frame (%.1f FPS)", 1000.0f / io.Framerate, io.Framerate);
                ImGui::TextLinkOpenURL("��Դ��ַ", "https://github.com/Brassinolide/TwoPassword");
                ImGui::End();
            }

            if (var::window::passfile_generator) {
                ImGui::Begin("�����ļ�������", &var::window::passfile_generator, ImGuiWindowFlags_AlwaysAutoResize);

                static int length = 1;
                ImGui::SliderInt("��������", &length, 1, 100);

                if (ImGui::Button("����")) {
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
                ImGui::Begin("����������", &var::window::password_generator, ImGuiWindowFlags_AlwaysAutoResize);
                static bool alpha = true;
                ImGui::Checkbox("��ĸ", &alpha);
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                    ImGui::SetTooltip("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

                ImGui::SameLine();

                static bool number = true;
                ImGui::Checkbox("����", &number);
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                    ImGui::SetTooltip("0123456789");

                ImGui::SameLine();

                static bool common_symbol = true;
                ImGui::Checkbox("����������ţ�ת���Ѻá��ļ����Ѻã�", &common_symbol);
                if (ImGui::IsItemHovered(ImGuiHoveredFlags_DelayNone))
                    ImGui::SetTooltip("~!=+-_,[]{}@#$%^;");

                static int length = 16;
                ImGui::SliderInt("����", &length, 3, 100);

                ImGui::Separator();

                static string password;
                if (ImGui::Button("����")) {
                    string chars = "";
                    if (alpha) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
                    if (number) chars += "0123456789";
                    if (common_symbol) chars += "~!=+-_,[]{}@#$%^;";

                    if (chars.empty()) {
                        password = "������ѡ��һ���ַ���";
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
                            password = "���������ʧ��";
                        }
                        delete[] rand_bytes;
                    }
                }

                ImGui::InputText("����", &password, ImGuiInputTextFlags_ReadOnly);

                ImGui::Text("������ũ�أ�%f", shannon_entropy((const uint8_t*)password.c_str(), password.length()));
                ImGui::End();
            }

            if (ImMessageBox_show) {
                if (ImGui::BeginPopupModal(ImMessageBox_caption, NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                    ImGui::TextUnformatted(ImMessageBox_text);
                    ImGui::Separator();
                    if (ImGui::Button("ȷ��", ImVec2(120, 0))) { ImMessageBox_show = false; ImGui::CloseCurrentPopup(); }
                    ImGui::EndPopup();
                }
                ImGui::OpenPopup(ImMessageBox_caption);
            }

            ImGui::End();
        }

        ImGui::EndFrame();
        g_pd3dDevice->SetRenderState(D3DRS_ZENABLE, FALSE);
        g_pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
        g_pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);
        D3DCOLOR clear_col_dx = D3DCOLOR_RGBA((int)(clear_color.x * clear_color.w * 255.0f), (int)(clear_color.y * clear_color.w * 255.0f), (int)(clear_color.z * clear_color.w * 255.0f), (int)(clear_color.w * 255.0f));
        g_pd3dDevice->Clear(0, nullptr, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, clear_col_dx, 1.0f, 0);
        if (g_pd3dDevice->BeginScene() >= 0) {
            ImGui::Render();
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
            g_pd3dDevice->EndScene();
        }
        HRESULT result = g_pd3dDevice->Present(nullptr, nullptr, nullptr, nullptr);
        if (result == D3DERR_DEVICELOST)
            g_DeviceLost = true;
    }

    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    if (config.config_get_int("memsafe", 0, 2, 0) != 0) {
        safe_exit();
    }
}

bool CreateDeviceD3D(HWND hWnd) {
    if ((g_pD3D = Direct3DCreate9(D3D_SDK_VERSION)) == nullptr)
        return false;

    ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
    g_d3dpp.Windowed = TRUE;
    g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
    g_d3dpp.EnableAutoDepthStencil = TRUE;
    g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
    g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;
    if (g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hWnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &g_d3dpp, &g_pd3dDevice) < 0)
        return false;

    return true;
}

void CleanupDeviceD3D() {
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
    if (g_pD3D) { g_pD3D->Release(); g_pD3D = nullptr; }
}

void ResetDevice() {
    ImGui_ImplDX9_InvalidateDeviceObjects();
    HRESULT hr = g_pd3dDevice->Reset(&g_d3dpp);
    if (hr == D3DERR_INVALIDCALL)
        IM_ASSERT(0);
    ImGui_ImplDX9_CreateDeviceObjects();
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED)
            return 0;
        g_ResizeWidth = (UINT)LOWORD(lParam);
        g_ResizeHeight = (UINT)HIWORD(lParam);
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU)
            return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
