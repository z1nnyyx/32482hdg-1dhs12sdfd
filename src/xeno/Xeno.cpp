#include <future>

#include "worker.hpp"
#include "server/server.h"
#include "utils/ntdll.h"

extern std::vector<std::shared_ptr<RBXClient>> Clients;
std::mutex clientsMtx;

std::unordered_set<DWORD> closedClients;
std::unordered_set<DWORD> initializingClients;

static void newClient(DWORD pid) {
    // Protect the host from any exception thrown deep inside the Xeno
    // worker: offsets that no longer match the Roblox build cause
    // out-of-range reads, which throw std::out_of_range/std::bad_alloc
    // and would otherwise terminate the whole process via std::terminate.
    try {
        if (closedClients.find(pid) != closedClients.end())
            return;
        initializingClients.insert(pid);
        std::shared_ptr<RBXClient> client = std::make_shared<RBXClient>(pid);
        {
            std::lock_guard<std::mutex> lock(clientsMtx);
            Clients.push_back(std::move(client));
            initializingClients.erase(pid);
        }
    } catch (const std::exception& e) {
        std::cerr << "[xeno] client " << pid << " init threw: " << e.what() << "\n";
        std::lock_guard<std::mutex> lock(clientsMtx);
        initializingClients.erase(pid);
        closedClients.insert(pid); // don't retry — same crash will repeat
    } catch (...) {
        std::cerr << "[xeno] client " << pid << " init threw unknown\n";
        std::lock_guard<std::mutex> lock(clientsMtx);
        initializingClients.erase(pid);
        closedClients.insert(pid);
    }
}

static void init() {
    // Upstream Xeno would terminate every other process named like
    // itself here. VoidTrace runs standalone — removed, so launching a
    // second VoidTrace.exe never kills the first.

    while (true) {
        try {
        std::vector<DWORD> client_pids = GetProcessIDsByName(L"RobloxPlayerBeta.exe");
        std::vector<DWORD> shader_pids = GetProcessIDsByName(L"eurotrucks2.exe");

        client_pids.insert(client_pids.end(), shader_pids.begin(), shader_pids.end());

        std::unordered_set<DWORD> current_pids(client_pids.begin(), client_pids.end());
        {
            std::lock_guard<std::mutex> lock(clientsMtx);

            Clients.erase(std::remove_if(Clients.begin(), Clients.end(), [&](const std::shared_ptr<RBXClient>& client) {
                if (current_pids.find(client->PID) == current_pids.end() || !client->isProcessAlive()) {
                    closedClients.insert(client->PID);
                    return true;
                }
                return false;
            }), Clients.end());

            for (const DWORD& pid : client_pids) {
                if (std::none_of(Clients.begin(), Clients.end(),
                    [&](const std::shared_ptr<RBXClient>& client) {return client->PID == pid;}) && initializingClients.find(pid) == initializingClients.end())
                {
                    std::thread(newClient, pid).detach();
                }
            }
        }
        } catch (const std::exception& e) {
            std::cerr << "[xeno] init tick threw: " << e.what() << "\n";
        } catch (...) {
            std::cerr << "[xeno] init tick threw unknown\n";
        }
        Sleep(250);
    }
}

extern "C" {
    __declspec(dllexport) ClientInfo* GetClients() {
        static std::vector<ClientInfo> simpleClients;
        {
            std::lock_guard<std::mutex> lock(clientsMtx);
            simpleClients.clear();

            for (const auto& client : Clients) {
                simpleClients.push_back({client->Version.c_str() /*Version*/, client->Username.c_str() /*Username*/, static_cast<int>(client->PID) /*Process ID*/});
            }

            simpleClients.push_back({ nullptr, nullptr, 0 });
        }
        return simpleClients.data();
    }

    __declspec(dllexport) void Initialize() {
        // Open a diagnostic console so [xeno/trace] std::cout lines are
        // visible — otherwise all the step-by-step logging goes nowhere.
        FILE* conOut;
        AllocConsole();
        SetConsoleTitleA("VoidTrace :: Xeno backend trace");
        freopen_s(&conOut, "CONOUT$", "w", stdout);
        freopen_s(&conOut, "CONOUT$", "w", stderr);
        std::cout << "[xeno/trace] Initialize begin\n";
        
        HMODULE ntdll = LoadLibraryA("ntdll.dll");
        if (!ntdll) {
            std::cerr << "Could not load ntdll.dll\n";
            return;
        }
        NTDLL_INIT_FCNS(ntdll);

        std::thread(init).detach();
        std::thread(setup_connection).detach();
    }

    __declspec(dllexport) void Execute(const char* script_source, const char** client_users, int num_users) {
        std::string source(script_source);
        std::lock_guard<std::mutex> lock(clientsMtx);
        for (int i = 0; i < num_users; ++i) {
            for (const auto& client : Clients) {
                if (strcmp(client_users[i], client->Username.c_str()) == 0) {
                    client->execute(source);
                    break;
                }
            }
        }
    }

    __declspec(dllexport) const char* Compilable(const char* script_source) {
        std::string source(script_source);
        std::string result = compilable(source);
        char* result_cstr = new char[result.length() + 1];
        strcpy_s(result_cstr, result.length() + 1, result.c_str());
        return result_cstr;
    }
}