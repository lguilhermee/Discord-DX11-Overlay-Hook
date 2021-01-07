
#include <windows.h>
#include <Discord.h>
#include <d3d11.h>
#include <iostream>
#include "Helper.h"
#include "Imgui/imgui.h"
#include "Imgui/imgui_impl_dx11.h"
#include "Imgui/imgui_impl_win32.h"



// PresentScene template
typedef HRESULT (__stdcall*Td3D11Present)(IDXGISwapChain* pSwapChain, UINT syncInterval, UINT flags);
Td3D11Present              OPresent = nullptr;
// ------------------------------------------------------------------------------------------------------------------------

// Dx Variables
ID3D11Device*           pD11Device           = nullptr;
ID3D11DeviceContext*    pD11DeviceContext    = nullptr;
ID3D11RenderTargetView* pD11RenderTargetView = nullptr;
// ------------------------------------------------------------------------------------------------------------------------

// Function Prototype
void    StartHooking();
HRESULT HookedPresentScene(IDXGISwapChain* dxSwapChain, UINT syncInterval, UINT flags);
// ------------------------------------------------------------------------------------------------------------------------


// ********************************************************************************
/// <summary>
/// This our hooked function, we will manipulate parameters, do our logic, or even draw things on screen on this part. Then we call original PresentScene to complete its jobs.
/// </summary>
/// <param name="dxSwapChain">The function has two parameters, but since its a function from a class, the first parameters its the class Instance.</param>
/// <param name="syncInterval">An integer that specifies how to synchronize presentation of a frame with the vertical blank.</param>
/// <param name="flags">An integer value that contains swap-chain presentation options.</param>
/// <returns>Possible return values include: S_OK, DXGI_ERROR_DEVICE_RESET or DXGI_ERROR_DEVICE_REMOVED </returns>
// ********************************************************************************
HRESULT HookedPresentScene(IDXGISwapChain* dxSwapChain, const UINT syncInterval, UINT flags)
{
    static bool showDemoWindow = true;

    // Verify if key was pressed. (Its checking if the key was pressed since we are checking bit 1)
    // If we need to see if the key its currently down, we should check for & 0x8000
    if(DISCORD.GetAsyncKeyState(VK_F1) & 1)
    {
        // Simple Message Sample.
        std::cout << "I'm hooked \n";
        showDemoWindow = !showDemoWindow;
    }
    
    // Its setup the Imgui Instance. This is executed only once.
    if (!pD11Device || !pD11DeviceContext)
    {
        // Create ImguiContext
        ImGui::CreateContext();

        // Retrieve Imgui Contect
        if (SUCCEEDED(dxSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&pD11Device)))
        {
            dxSwapChain->GetDevice(__uuidof(pD11Device), (void**)&pD11Device);
            pD11Device->GetImmediateContext(&pD11DeviceContext);
        }


        // We retrieve WindowHandle directly from DX. We could use also FindWindow function overhere.
        DXGI_SWAP_CHAIN_DESC desc;
        dxSwapChain->GetDesc(&desc);

        // Setup DirectX Input and Others variables.
        ImGui_ImplWin32_Init(desc.OutputWindow);
        ImGui_ImplDX11_Init(pD11Device, pD11DeviceContext);
    }
    else
    {
        // This will be executed on every loop. The reason that we are doing it, its because we free/release it after its used. That way, we can resize or window without crashing.
        ID3D11Texture2D* renderTargetTexture = nullptr;
        if (!pD11RenderTargetView)
        {
            if (SUCCEEDED(dxSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), reinterpret_cast<LPVOID*>(&renderTargetTexture))))
            {
                pD11Device->CreateRenderTargetView(renderTargetTexture, nullptr, &pD11RenderTargetView);
                renderTargetTexture->Release();
            }
        }
    }

    // Feed the input to Imgui, and start a new frame
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    // --------------------------------------------------- DRAW HERE --------------------------------------------------

    // Everything that we want to on the screen, should be put overhere. 

    ImGui::ShowDemoWindow(&showDemoWindow); // This open the demo window from DirectX

    // --------------------------------------------------- END DRAWING --------------------------------------------------


    // Bind one or more render targets atomically. And ends frame with Imgui:Render()
    pD11DeviceContext->OMSetRenderTargets(1, &pD11RenderTargetView, nullptr);
    ImGui::Render();

    // Release and free resources to setup again on the next loop.
    if (pD11RenderTargetView)
    {
        pD11RenderTargetView->Release();
        pD11RenderTargetView = nullptr;
    }

    // Draw everything.
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

    // Return calling the origianl function providing the original parameters. 
    return OPresent(dxSwapChain, syncInterval, flags);
}


void StartHooking()
{
    // OpenConsole
    Helper::OpenConsole();

    // PresentScene Adress.
    auto presentSceneAdress = Helper::PatternScan(Discord::GetDiscordModuleBase(),
                                                  "56 57 53 48 83 EC 30 44 89 C6");


    // Hook Present scene, and enable it.
    DISCORD.HookFunction(presentSceneAdress, (uintptr_t)HookedPresentScene, (uintptr_t)&OPresent);
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        StartHooking();
    default:
        break;
    }
    return TRUE;
}
