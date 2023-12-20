#pragma once
#pragma once
#include <d3d9.h>
#include "../ImGui/imgui.h"
#include "../ImGui/imgui_impl_win32.h"
#include "../ImGui/imgui_impl_dx9.h"
#include <stdexcept>
#include "hooks/memory.hpp"

LPDIRECT3D9             g_pD3D = nullptr;
LPDIRECT3DDEVICE9       g_pd3dDevice = nullptr;
D3DPRESENT_PARAMETERS   g_d3dpp;
HWND                    main_hwnd = nullptr;
WNDCLASSEX              wc;

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
void ResetD3DDevice()
{
    ImGui_ImplDX9_InvalidateDeviceObjects();
    const HRESULT hr = g_pd3dDevice->Reset(&g_d3dpp);
    if (hr == D3DERR_INVALIDCALL)
        IM_ASSERT(0);
    ImGui_ImplDX9_CreateDeviceObjects();
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, message, wParam, lParam))
        return true;

    switch (message)
    {
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

bool CreateD3DDevice()
{
    if ((g_pD3D = Direct3DCreate9(D3D_SDK_VERSION)) == nullptr)
        return false;

    ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
    g_d3dpp.Windowed = TRUE;
    g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
    g_d3dpp.EnableAutoDepthStencil = TRUE;
    g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
    g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;
    if (g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, main_hwnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &g_d3dpp, &g_pd3dDevice) < 0)
        return false;

    return true;
}

void CleanupD3DDevice()
{
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
    if (g_pD3D) { g_pD3D->Release(); g_pD3D = nullptr; }
    UnregisterClass(wc.lpszClassName, wc.hInstance);
}

void CreateOverlayWindow()
{
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, "CodeCave Hook", nullptr };
    wc.style = WS_EX_TOOLWINDOW;
    RegisterClassEx(&wc);
    main_hwnd = CreateWindow(wc.lpszClassName, "CodeCave Hook", WS_POPUP, 0, 0, 5, 5, NULL, NULL, wc.hInstance, NULL);

    if (!CreateD3DDevice()) {
        CleanupD3DDevice();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return;
    }
    ShowWindow(main_hwnd, SW_HIDE);
    UpdateWindow(main_hwnd);
}



DWORD_PTR loginRVA1, loginRVA2, integrityRVA1, integrityRVA2, target_nop;
char integrityRVA1Str[64];
char integrityRVA2Str[64];
char loginRVA1Str[64];
char loginRVA2Str[64];
void rendermenu()
{
    config->LoadConfig("config.json");

    RECT rect{};
    SystemParametersInfo(SPI_GETWORKAREA, 0, &rect, 0);
    const int screenWidth = rect.right - rect.left;
    [[maybe_unused]] int screenHeight = rect.bottom - rect.top;
    const ImVec2 windowSize(800, 0);

    ImGui::SetNextWindowPos(ImVec2((screenWidth / 2) - (windowSize.x / 2), 0));
    ImGui::SetNextWindowSize(windowSize);

    ImGui::Begin("[codecave hook] Main Menu || developer : Seemo/byte2mov", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);

    ImGui::Text("Enter RVAs for Login and Integrity:");

    ImGui::InputScalar("Login RVA 1", ImGuiDataType_U64, &loginRVA1, NULL, NULL, "%016llX", ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::InputScalar("Login RVA 2", ImGuiDataType_U64, &loginRVA2, NULL, NULL, "%016llX", ImGuiInputTextFlags_CharsHexadecimal);

    ImGui::InputScalar("Integrity RVA 1", ImGuiDataType_U64, &integrityRVA1, NULL, NULL, "%016llX", ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::InputScalar("Integrity RVA 2", ImGuiDataType_U64, &integrityRVA2, NULL, NULL, "%016llX", ImGuiInputTextFlags_CharsHexadecimal);


    if (ImGui::Button("Bypass Keyauth"))
    {
        mem_hook->start_crack(loginRVA1, loginRVA2, integrityRVA1, integrityRVA2);
    }

    ImGui::Separator();
    ImGui::Text("Hooking:");

    if (ImGui::Button("Hook BlockInput"))
    {
        hooks->HookInput();
    }
    if (ImGui::Button("Hook CURL"))
    {
        hooks->hookcurl();
    }
    if (ImGui::Button("Hook FindWindowA & System Searchers"))
    {
        hooks->hookfind();
    }
    if (ImGui::Button("Hook Debugger Checks"))
    {
        mem_hook->hook_NTGlobalFlag();
        hooks->hookdebuggercheck();
        
    }
    if (ImGui::Button("Hook CMD Commands & CreateProcess"))
    {
        hooks->HookCreateProcess();
    }
    if (ImGui::Button("Anti BSOD"))
    {
        hooks->HookBSOD();
    }
    if (ImGui::Button("Hook URLDownloadA"))
    {
        hooks->hook_url_download_A();
    }
    if (ImGui::Button("Hook Exit Calls"))
    {
        hooks->hook_exit_function();
    }
    if (ImGui::Button("Hook GlobalAddAtomA"))
    {
        hooks->hookatoms();
    }
    if (ImGui::Button("Hook Keyauth Login"))
    {
        hooks->InstallHook();
    }
    if (ImGui::Button("Hook CreateFileW"))
    {
        hooks->hook_file_drop_remove();
    }
    ImGui::Separator();

    ImGui::Text("Dumping:");

    if (ImGui::Button("Dump Process Hollowing"))
    {
        hooks->hook_process_hollowing();
    }
    if (ImGui::Button("DLL Dumper"))
    {
        hooks->dump_dlls();
    }
    if (ImGui::Button("Dump Drivers"))
    {
        hooks->dump_drivers();
    }
    if (ImGui::Button("Dump LoadLibrary"))
    {
        hooks->LoadLibrary_hook();
    }
    ImGui::Separator();

    ImGui::Text("Memory:");

    ImGui::InputScalar("Target RVA to NOP", ImGuiDataType_U64, &target_nop, NULL, NULL, "%016llX", ImGuiInputTextFlags_CharsHexadecimal);
    
    ImGui::SameLine();

    if (ImGui::Button("Nop Memory at RVA"))
    {
        DWORD_PTR base = mem_hook->GetModuleBase("codecave_victim.exe") + target_nop;
        mem_hook->NopMemory(base);
    }

    char searchText[256] = "";
    ImGui::InputText("Search In Memory", searchText, IM_ARRAYSIZE(searchText));
    ImGui::SameLine();
    if (ImGui::Button("Search")) {
        mem_hook->scan_text(searchText);
    }
    static const int defaultStartRange = 0;
    static const int defaultEndRange = 0;
    static const int thread = 0;
    static int startRange = defaultStartRange;
    static int endRange = defaultEndRange;
    static int endthread = thread;

    ImGui::PushItemWidth(100);
    ImGui::InputScalar("Start Range", ImGuiDataType_S32, &startRange);
    ImGui::SameLine();
    ImGui::InputScalar("End Range", ImGuiDataType_S32, &endRange);
    ImGui::SameLine();
    ImGui::InputScalar("Thread Count", ImGuiDataType_S32, &endthread);
    ImGui::SameLine();
    ImGui::PopItemWidth();
    if (ImGui::Button("Scan Memory for Keyauth Download"))
    {
        mem_hook->scan_keyauth_download_parallel(startRange, endRange, endthread);
    }
    std::string current_pid = "PID : " + std::to_string(hooks->g_victim_pid);
    ImGui::Text(current_pid.c_str());
    std::stringstream ss;
    uintptr_t base_address = mem_hook->GetModuleBase("codecave_victim.exe");
    ss << "Base Address : 0x" << std::hex << std::uppercase << base_address;
    std::string current_base = ss.str();
    ImGui::Text(current_base.c_str());

    ImGui::Separator();
    ImGui::Text("Preset Configurations:");

    static std::string selectedPreset;
    static char presetNameInput[64] = ""; 
    ImGui::InputText("Config Name", presetNameInput, IM_ARRAYSIZE(presetNameInput));

    if (ImGui::Button("Create Preset") && presetNameInput[0] != '\0') {
        nlohmann::json presetData;
        presetData["loginRVA1"] = loginRVA1;
        presetData["loginRVA2"] = loginRVA2;
        presetData["integrityRVA1"] = integrityRVA1;
        presetData["integrityRVA2"] = integrityRVA2;
        presetData["target_nop"] = target_nop;


        config->SetPreset(presetNameInput, presetData);

        selectedPreset = presetNameInput;

        presetNameInput[0] = '\0'; 

        config->SaveConfig("config.json");

    }
    if (ImGui::BeginCombo("Select Preset", selectedPreset.c_str())) {
        for (auto& preset : config->data.items()) {
            const std::string& presetName = preset.key();
            bool isSelected = (presetName == selectedPreset);
            if (ImGui::Selectable(presetName.c_str(), isSelected)) {
                selectedPreset = presetName;
            }
            if (isSelected) {
                ImGui::SetItemDefaultFocus();
            }
        }
        ImGui::EndCombo();
    }

    if (ImGui::Button("Load Preset")) {
        nlohmann::json presetData = config->GetPreset(selectedPreset);
        loginRVA1 = presetData.value("loginRVA1", 0);
        loginRVA2 = presetData.value("loginRVA2", 0);
        integrityRVA1 = presetData.value("integrityRVA1", 0);
        integrityRVA2 = presetData.value("integrityRVA2", 0);
        target_nop = presetData.value("target_nop", 0);
    }

    if (ImGui::Button("Save Preset")) {
        nlohmann::json presetData;
        presetData["loginRVA1"] = loginRVA1;
        presetData["loginRVA2"] = loginRVA2;
        presetData["integrityRVA1"] = integrityRVA1;
        presetData["integrityRVA2"] = integrityRVA2;
        presetData["target_nop"] = target_nop;

        config->SetPreset(selectedPreset, presetData);
        config->SaveConfig("config.json");


    }

    ImGui::End();

}

DWORD WINAPI RenderThread([[maybe_unused]] LPVOID lpParameter)
{
    
    CreateOverlayWindow();

    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;


    ImFont* customFont = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\impact.ttf", 14);
    io.FontDefault = customFont;  // Set it as the default font

    ImGui::StyleColorsDark();

    ImGui_ImplWin32_Init(main_hwnd);
    ImGui_ImplDX9_Init(g_pd3dDevice);

    MSG msg;
    ZeroMemory(&msg, sizeof(msg));

    while (msg.message != WM_QUIT) {

        if (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        rendermenu();

        ImGui::EndFrame();
        const HRESULT Clear = g_pd3dDevice->Clear(0, nullptr, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, 0, 1.0f, 0);
        if (Clear != D3D_OK)
            throw std::runtime_error("Clear didn't return D3D_OK");

        if (g_pd3dDevice->BeginScene() >= 0)
        {
            ImGui::Render();
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
            const HRESULT EndScene = g_pd3dDevice->EndScene();
            if (EndScene != D3D_OK)
                throw std::runtime_error("EndScene didn't return D3D_OK");
        }

        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

        const HRESULT result = g_pd3dDevice->Present(nullptr, nullptr, nullptr, nullptr);
        if (result == D3DERR_DEVICELOST && g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET) {
            ResetD3DDevice();
        }

    }

    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupD3DDevice();

    return 0;
}
