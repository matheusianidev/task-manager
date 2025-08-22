#define UNICODE
#define _UNICODE

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <algorithm>
#include <limits>

using namespace std;

// ===== Cores ANSI =====
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define CYAN    "\033[36m"

// Habilita cores
void EnableAnsiColors() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;
    DWORD mode = 0;
    if (GetConsoleMode(hOut, &mode)) {
        SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }
}

// Conversão wide (UTF-16) → UTF-8
std::string to_utf8(const wchar_t* wstr) {
    if (!wstr) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) return "";
    std::string str(size_needed - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str.data(), size_needed, nullptr, nullptr);
    return str;
}

// Lista de processos “protegidos” que não devem ser finalizados
vector<string> protectedProcesses = {
    "explorer.exe",
    "svchost.exe",
    "System",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe"
};

// Função auxiliar para comparação case-insensitive simples
bool equals_ignore_case(const string& a, const string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return false;
    return true;
}

// ===== Funções principais =====

void ListProcesses() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        cerr << "Erro ao tirar snapshot dos processos.\n";
        return;
    }

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(pe32);

    if (!Process32FirstW(snapshot, &pe32)) {
        cerr << "Erro ao acessar primeiro processo.\n";
        CloseHandle(snapshot);
        return;
    }

    cout << CYAN << left
         << setw(30) << "Processo"
         << setw(10) << "PID"
         << "Memória (MB)" << RESET << "\n";
    cout << "------------------------------------------------------\n";

    do {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
        SIZE_T memKB = 0;
        if (hProcess) {
            PROCESS_MEMORY_COUNTERS pmc{};
            if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                memKB = pmc.WorkingSetSize / 1024;
            }
            CloseHandle(hProcess);
        }

        string procName = to_utf8(pe32.szExeFile);
        bool isProtected = false;
        for (const auto& p : protectedProcesses)
            if (equals_ignore_case(procName, p)) { isProtected = true; break; }

        const char* color = isProtected ? GREEN : YELLOW;
        cout << color << left
             << setw(30) << procName
             << setw(10) << pe32.th32ProcessID
             << fixed << setprecision(1)
             << (memKB / 1024.0) << " MB" << RESET << "\n";

    } while (Process32NextW(snapshot, &pe32));

    CloseHandle(snapshot);
}

void SearchProcessByName(const string& name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(pe32);

    if (!Process32FirstW(snapshot, &pe32)) { CloseHandle(snapshot); return; }

    bool found = false;
    do {
        string procName = to_utf8(pe32.szExeFile);
        if (equals_ignore_case(procName, name)) {
            cout << GREEN << "Encontrado: " << procName
                 << " | PID: " << pe32.th32ProcessID << RESET << "\n";
            found = true;
        }
    } while (Process32NextW(snapshot, &pe32));

    if (!found) cout << RED << "Nenhum processo com nome '" << name << "' encontrado." << RESET << "\n";

    CloseHandle(snapshot);
}

void KillProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) { cout << RED << "Não foi possível abrir PID " << pid << RESET << "\n"; return; }
    if (TerminateProcess(hProcess, 0)) cout << RED << "Processo " << pid << " finalizado!" << RESET << "\n";
    else cout << RED << "Erro ao finalizar PID " << pid << RESET << "\n";
    CloseHandle(hProcess);
}

void CleanUnnecessaryProcesses() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(pe32);

    if (!Process32FirstW(snapshot, &pe32)) { CloseHandle(snapshot); return; }

    do {
        string procName = to_utf8(pe32.szExeFile);
        bool isProtected = false;
        for (const auto& p : protectedProcesses)
            if (equals_ignore_case(procName, p)) { isProtected = true; break; }

        if (!isProtected) {
            cout << RED << "Finalizando " << procName
                 << " (PID: " << pe32.th32ProcessID << ")..." << RESET << "\n";
            KillProcess(pe32.th32ProcessID);
        }

    } while (Process32NextW(snapshot, &pe32));

    CloseHandle(snapshot);
}

// ===== Menu principal =====
int main() {
    SetConsoleOutputCP(CP_UTF8);
    EnableAnsiColors();

    int opcao;
    do {
        cout << CYAN << "\n===== Monitor de Processos @matheusianidev =====" << RESET << "\n";
        cout << "1 - Listar processos\n";
        cout << "2 - Buscar processo por nome\n";
        cout << "3 - Finalizar processo por PID\n";
        cout << "4 - Finalizar processos não essenciais\n";
        cout << "0 - Sair\n";
        cout << "Escolha uma opção: ";
        cin >> opcao;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        switch (opcao) {
            case 1: ListProcesses(); break;
            case 2: {
                string nome;
                cout << "Digite o nome do processo: ";
                getline(cin, nome);
                SearchProcessByName(nome);
                break;
            }
            case 3: {
                DWORD pid;
                cout << "Digite o PID do processo: ";
                cin >> pid;
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                KillProcess(pid);
                break;
            }
            case 4:
                cout << YELLOW << "⚠️ Atenção: pode encerrar programas importantes!" << RESET << "\n";
                CleanUnnecessaryProcesses();
                break;
            case 0:
                cout << "Saindo...\n"; break;
            default:
                cout << "Opção inválida!\n";
        }
    } while (opcao != 0);

    return 0;
}
