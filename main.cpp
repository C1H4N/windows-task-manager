#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <algorithm>
#include <map>
#include <thread>
#include <chrono>
#include <sstream>
#include <wtsapi32.h>
#include <userenv.h>
#include <limits>
#include <clocale>
#include <locale>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")

struct ProcessInfo {
    DWORD processId;
    std::wstring processName;
    SIZE_T memoryUsage;
    double cpuUsage;
    int priority;
    std::wstring priorityStr;
    std::wstring userName;
    std::wstring startTime;
    std::wstring commandLine;
    DWORD threadCount;
    SIZE_T peakMemoryUsage;
};

class CPUTracker {
private:
    std::map<DWORD, ULARGE_INTEGER> lastCPUUsage;
    
    ULARGE_INTEGER getProcessCPUTime(HANDLE hProcess) {
        ULARGE_INTEGER now;
        FILETIME creation_time, exit_time, kernel_time, user_time;
        
        if (GetProcessTimes(hProcess, &creation_time, &exit_time, &kernel_time, &user_time)) {
            now.LowPart = kernel_time.dwLowDateTime + user_time.dwLowDateTime;
            now.HighPart = kernel_time.dwHighDateTime + user_time.dwHighDateTime;
            return now;
        }
        now.QuadPart = 0;
        return now;
    }

    DWORD getProcessorCount() {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        return sysInfo.dwNumberOfProcessors;
    }

public:
    double getProcessCPUUsage(DWORD processId) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess == NULL) return 0.0;

        ULARGE_INTEGER current = getProcessCPUTime(hProcess);
        CloseHandle(hProcess);

        if (lastCPUUsage.find(processId) == lastCPUUsage.end()) {
            lastCPUUsage[processId] = current;
            return 0.0;
        }

        ULARGE_INTEGER last = lastCPUUsage[processId];
        lastCPUUsage[processId] = current;

        if (current.QuadPart <= last.QuadPart) return 0.0;

        ULARGE_INTEGER sys_time;
        sys_time.QuadPart = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        
        double cpu_usage = ((current.QuadPart - last.QuadPart) * 100.0) / 
                          (sys_time.QuadPart * getProcessorCount());
        
        return cpu_usage > 100.0 ? 100.0 : cpu_usage;
    }
};

std::wstring getPriorityString(int priority) {
    switch (priority) {
        case IDLE_PRIORITY_CLASS: return L"Dusuk";
        case BELOW_NORMAL_PRIORITY_CLASS: return L"Dusuk Ustu";
        case NORMAL_PRIORITY_CLASS: return L"Normal";
        case ABOVE_NORMAL_PRIORITY_CLASS: return L"Normal Ustu";
        case HIGH_PRIORITY_CLASS: return L"Yuksek";
        case REALTIME_PRIORITY_CLASS: return L"Gercek Zamanli";
        default: return L"Bilinmiyor";
    }
}

bool setProcessPriority(DWORD processId, DWORD priority) {
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, processId);
    if (hProcess == NULL) return false;
    
    bool result = SetPriorityClass(hProcess, priority);
    CloseHandle(hProcess);
    return result;
}

std::wstring getProcessUserName(DWORD processId) {
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!processHandle) return L"Bilinmiyor";

    HANDLE tokenHandle = NULL;
    if (!OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle)) {
        CloseHandle(processHandle);
        return L"Bilinmiyor";
    }

    DWORD size = 0;
    GetTokenInformation(tokenHandle, TokenUser, NULL, 0, &size);
    if (size == 0) {
        CloseHandle(tokenHandle);
        CloseHandle(processHandle);
        return L"Bilinmiyor";
    }

    std::vector<BYTE> userInfo(size);
    if (!GetTokenInformation(tokenHandle, TokenUser, userInfo.data(), size, &size)) {
        CloseHandle(tokenHandle);
        CloseHandle(processHandle);
        return L"Bilinmiyor";
    }

    WCHAR userName[256] = L"";
    WCHAR domainName[256] = L"";
    DWORD userNameSize = 256;
    DWORD domainNameSize = 256;
    SID_NAME_USE sidType;

    if (!LookupAccountSidW(NULL,
                          ((TOKEN_USER*)userInfo.data())->User.Sid,
                          userName,
                          &userNameSize,
                          domainName,
                          &domainNameSize,
                          &sidType)) {
        CloseHandle(tokenHandle);
        CloseHandle(processHandle);
        return L"Bilinmiyor";
    }

    CloseHandle(tokenHandle);
    CloseHandle(processHandle);

    std::wstringstream ss;
    ss << domainName << L"\\" << userName;
    return ss.str();
}

std::wstring getProcessStartTime(HANDLE hProcess) {
    FILETIME creation, exit, kernel, user;
    if (!GetProcessTimes(hProcess, &creation, &exit, &kernel, &user)) {
        return L"Bilinmiyor";
    }

    SYSTEMTIME st;
    FILETIME localTime;
    FileTimeToLocalFileTime(&creation, &localTime);
    FileTimeToSystemTime(&localTime, &st);

    std::wstringstream ss;
    ss << std::setfill(L'0') 
       << st.wDay << L"/" << std::setw(2) << st.wMonth << L"/" << st.wYear << L" "
       << std::setw(2) << st.wHour << L":" << std::setw(2) << st.wMinute;
    return ss.str();
}

std::wstring getProcessCommandLine(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) return L"";

    WCHAR buffer[MAX_PATH] = {0};
    if (GetModuleFileNameExW(hProcess, NULL, buffer, MAX_PATH)) {
        DWORD exitCode = 0;
        if (GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE) {
            CloseHandle(hProcess);
            return std::wstring(buffer);
        }
        
        CloseHandle(hProcess);
        return std::wstring(buffer);
    }
    
    CloseHandle(hProcess);
    return L"";
}

std::vector<ProcessInfo> getRunningProcesses() {
    static CPUTracker cpuTracker;
    std::vector<ProcessInfo> processes;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::wcout << L"Snapshot olusturulamadi!" << std::endl;
        return processes;
    }

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(processEntry);

    if (!Process32FirstW(snapshot, &processEntry)) {
        CloseHandle(snapshot);
        std::wcout << L"Ilk process bilgisi alinamadi!" << std::endl;
        return processes;
    }

    do {
        HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processEntry.th32ProcessID);
        PROCESS_MEMORY_COUNTERS pmc;
        SIZE_T memoryUsage = 0;
        SIZE_T peakMemoryUsage = 0;
        double cpuUsage = 0.0;
        int priority = 0;
        std::wstring priorityStr = L"Bilinmiyor";
        std::wstring startTime = L"Bilinmiyor";
        std::wstring userName = getProcessUserName(processEntry.th32ProcessID);
        std::wstring commandLine = getProcessCommandLine(processEntry.th32ProcessID);

        if (processHandle != NULL) {
            if (GetProcessMemoryInfo(processHandle, &pmc, sizeof(pmc))) {
                memoryUsage = pmc.WorkingSetSize;
                peakMemoryUsage = pmc.PeakWorkingSetSize;
            }
            cpuUsage = cpuTracker.getProcessCPUUsage(processEntry.th32ProcessID);
            priority = GetPriorityClass(processHandle);
            priorityStr = getPriorityString(priority);
            startTime = getProcessStartTime(processHandle);
            CloseHandle(processHandle);
        }

        ProcessInfo info = {
            processEntry.th32ProcessID,
            processEntry.szExeFile,
            memoryUsage,
            cpuUsage,
            priority,
            priorityStr,
            userName,
            startTime,
            commandLine,
            processEntry.cntThreads,
            peakMemoryUsage
        };
        processes.push_back(info);

    } while (Process32NextW(snapshot, &processEntry));

    CloseHandle(snapshot);
    return processes;
}

bool terminateProcess(DWORD processId) {
    HANDLE processHandle = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (processHandle == NULL) {
        DWORD error = GetLastError();
        if (error == ERROR_ACCESS_DENIED) {
            std::wcout << L"Erisim reddedildi. Yonetici izni gerekebilir.\n";
        }
        return false;
    }

    bool result = TerminateProcess(processHandle, 0) != 0;
    if (!result) {
        DWORD error = GetLastError();
        if (error == ERROR_ACCESS_DENIED) {
            std::wcout << L"Islem sonlandirma izni reddedildi.\n";
        }
    }
    
    CloseHandle(processHandle);
    return result;
}

void showProcessDetails(DWORD processId) {
    auto processes = getRunningProcesses();
    auto it = std::find_if(processes.begin(), processes.end(),
        [processId](const ProcessInfo& p) { return p.processId == processId; });
    
    if (it == processes.end()) {
        std::wcout << L"Islem bulunamadi! Islem sonlanmis veya erisim izni yok.\n";
        return;
    }

    const auto& process = *it;
    std::wcout << L"\nIslem Detaylari:\n";
    std::wcout << L"PID: " << process.processId << L"\n";
    std::wcout << L"Islem Adi: " << process.processName << L"\n";
    std::wcout << L"Kullanici: " << process.userName << L"\n";
    std::wcout << L"Baslangic Zamani: " << process.startTime << L"\n";
    std::wcout << L"Komut Satiri: " << process.commandLine << L"\n";
    std::wcout << L"Thread Sayisi: " << process.threadCount << L"\n";
    std::wcout << L"Oncelik: " << process.priorityStr << L"\n";
    std::wcout << L"Bellek Kullanimi: " << std::fixed << std::setprecision(2)
               << (process.memoryUsage / 1024.0 / 1024.0) << L" MB\n";
    std::wcout << L"En Yuksek Bellek Kullanimi: " << std::fixed << std::setprecision(2)
               << (process.peakMemoryUsage / 1024.0 / 1024.0) << L" MB\n";
    std::wcout << L"CPU Kullanimi: " << std::setprecision(1) << process.cpuUsage << L"%\n";
    
    try {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (hProcess != NULL) {
            FILETIME creationTime, exitTime, kernelTime, userTime;
            if (GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime)) {
                ULARGE_INTEGER kernelTimeValue, userTimeValue;
                kernelTimeValue.LowPart = kernelTime.dwLowDateTime;
                kernelTimeValue.HighPart = kernelTime.dwHighDateTime;
                userTimeValue.LowPart = userTime.dwLowDateTime;
                userTimeValue.HighPart = userTime.dwHighDateTime;
                
                double cpuTimeInSeconds = (kernelTimeValue.QuadPart + userTimeValue.QuadPart) / 10000000.0;
                std::wcout << L"Toplam CPU Zamani: " << std::fixed << std::setprecision(2) 
                        << cpuTimeInSeconds << L" saniye\n";
            }
            CloseHandle(hProcess);
        }
    } catch (...) {
        // Hata durumunda sessizce geç
    }
}

enum class SortBy {
    Memory,
    CPU,
    Name,
    PID,
    Priority
};

void filterAndSortProcesses(std::vector<ProcessInfo>& processes) {
    std::wcout << L"\nFiltreleme ve Siralama Secenekleri:\n";
    std::wcout << L"Filtreleme:\n";
    std::wcout << L"1. Isim ile filtrele\n";
    std::wcout << L"2. Kullanici ile filtrele\n";
    std::wcout << L"3. Minimum bellek kullanimi ile filtrele (MB)\n";
    std::wcout << L"4. Minimum CPU kullanimi ile filtrele (%)\n";
    std::wcout << L"5. Filtreleme yapma\n";
    std::wcout << L"Seciminiz: ";

    int filterChoice;
    std::cin >> filterChoice;
    if (std::cin.fail() || filterChoice < 1 || filterChoice > 5) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::wcout << L"Gecersiz secenek! Filtreleme yapilmadi.\n";
        filterChoice = 5; // Filtreleme yapma
    }
    std::cin.ignore();

    if (filterChoice == 1) {
        std::wcout << L"Isim icin arama kelimesi: ";
        std::wstring searchName;
        std::getline(std::wcin, searchName);
        if (!searchName.empty()) {
            std::transform(searchName.begin(), searchName.end(), searchName.begin(), ::towlower);

            processes.erase(
                std::remove_if(processes.begin(), processes.end(),
                    [&searchName](const ProcessInfo& p) {
                        std::wstring lowerName = p.processName;
                        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
                        return lowerName.find(searchName) == std::wstring::npos;
                    }), 
                processes.end()
            );
        }
    }
    else if (filterChoice == 2) {
        std::wcout << L"Kullanici adi: ";
        std::wstring searchUser;
        std::getline(std::wcin, searchUser);
        if (!searchUser.empty()) {
            std::transform(searchUser.begin(), searchUser.end(), searchUser.begin(), ::towlower);

            processes.erase(
                std::remove_if(processes.begin(), processes.end(),
                    [&searchUser](const ProcessInfo& p) {
                        std::wstring lowerUser = p.userName;
                        std::transform(lowerUser.begin(), lowerUser.end(), lowerUser.begin(), ::towlower);
                        return lowerUser.find(searchUser) == std::wstring::npos;
                    }), 
                processes.end()
            );
        }
    }
    else if (filterChoice == 3) {
        std::wcout << L"Minimum bellek kullanimi (MB): ";
        double minMemory;
        std::cin >> minMemory;
        if (std::cin.fail() || minMemory < 0) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::wcout << L"Gecersiz deger! Filtreleme yapilmadi.\n";
        } else {
            processes.erase(
                std::remove_if(processes.begin(), processes.end(),
                    [minMemory](const ProcessInfo& p) {
                        return (p.memoryUsage / 1024.0 / 1024.0) < minMemory;
                    }), 
                processes.end()
            );
        }
    }
    else if (filterChoice == 4) {
        std::wcout << L"Minimum CPU kullanimi (%): ";
        double minCPU;
        std::cin >> minCPU;
        if (std::cin.fail() || minCPU < 0 || minCPU > 100) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::wcout << L"Gecersiz deger! Filtreleme yapilmadi.\n";
        } else {
            processes.erase(
                std::remove_if(processes.begin(), processes.end(),
                    [minCPU](const ProcessInfo& p) {
                        return p.cpuUsage < minCPU;
                    }), 
                processes.end()
            );
        }
    }

    std::wcout << L"\nSiralama:\n";
    std::wcout << L"1. Bellek kullanimi (Azalan)\n";
    std::wcout << L"2. CPU kullanimi (Azalan)\n";
    std::wcout << L"3. Isim (A-Z)\n";
    std::wcout << L"4. PID (Artan)\n";
    std::wcout << L"5. Oncelik (Yuksekten Dusuge)\n";
    std::wcout << L"Seciminiz: ";

    int sortChoice;
    std::cin >> sortChoice;
    if (std::cin.fail() || sortChoice < 1 || sortChoice > 5) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::wcout << L"Gecersiz secenek! Varsayilan siralamayi kullaniyorum (Bellek kullanimi).\n";
        sortChoice = 1; // Varsayılan olarak bellek kullanımına göre sırala
    }

    switch (sortChoice) {
        case 1:
            std::sort(processes.begin(), processes.end(),
                [](const ProcessInfo& a, const ProcessInfo& b) {
                    return a.memoryUsage > b.memoryUsage;
                });
            break;
        case 2:
            std::sort(processes.begin(), processes.end(),
                [](const ProcessInfo& a, const ProcessInfo& b) {
                    return a.cpuUsage > b.cpuUsage;
                });
            break;
        case 3:
            std::sort(processes.begin(), processes.end(),
                [](const ProcessInfo& a, const ProcessInfo& b) {
                    return a.processName < b.processName;
                });
            break;
        case 4:
            std::sort(processes.begin(), processes.end(),
                [](const ProcessInfo& a, const ProcessInfo& b) {
                    return a.processId < b.processId;
                });
            break;
        case 5:
            std::sort(processes.begin(), processes.end(),
                [](const ProcessInfo& a, const ProcessInfo& b) {
                    return a.priority > b.priority;
                });
            break;
    }
}

int main() {
    setlocale(LC_ALL, "Turkish");
    std::wcout.imbue(std::locale("Turkish"));

    while (true) {
        std::wcout << L"\nIslem Yoneticisi\n";
        std::wcout << L"1. Calisan islemleri listele\n";
        std::wcout << L"2. Islem sonlandir\n";
        std::wcout << L"3. Islem onceligi degistir\n";
        std::wcout << L"4. Islem detaylarini goster\n";
        std::wcout << L"5. Islemleri filtrele ve sirala\n";
        std::wcout << L"6. Cikis\n";
        std::wcout << L"Seciminiz: ";

        int choice = 0;
        std::cin >> choice;
        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::wcout << L"Gecersiz giris. Lutfen sayi girin.\n";
            continue;
        }

        switch (choice) {
            case 1: {
                auto processes = getRunningProcesses();
                
                processes.erase(
                    std::remove_if(processes.begin(), processes.end(),
                        [](const ProcessInfo& process) {
                            return process.processName == L"TaskManager.exe";
                        }), 
                    processes.end()
                );
                
                std::sort(processes.begin(), processes.end(),
                    [](const ProcessInfo& a, const ProcessInfo& b) {
                        return a.memoryUsage > b.memoryUsage;
                    });
                
                std::wcout << std::left 
                        << std::setw(8) << L"PID" 
                        << std::setw(40) << L"Islem Adi"
                        << std::setw(20) << L"Bellek (MB)"
                        << std::setw(15) << L"CPU %"
                        << L"Oncelik" << std::endl;
                std::wcout << std::wstring(100, L'-') << std::endl;

                for (const auto& process : processes) {
                    std::wcout << std::left 
                            << std::setw(8) << process.processId
                            << std::setw(40) << process.processName
                            << std::setw(20) << std::fixed << std::setprecision(2)
                            << (process.memoryUsage / 1024.0 / 1024.0)
                            << std::setw(15) << std::setprecision(1) << process.cpuUsage
                            << process.priorityStr << std::endl;
                }
                break;
            }
            case 2: {
                std::wcout << L"Sonlandirilacak islemin PID'sini girin: ";
                DWORD pid;
                std::cin >> pid;
                if (std::cin.fail()) {
                    std::cin.clear();
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    std::wcout << L"Gecersiz PID.\n";
                    break;
                }

                if (terminateProcess(pid)) {
                    std::wcout << L"Islem basariyla sonlandirildi.\n";
                } else {
                    std::wcout << L"Islem sonlandirilamadi! Yetkisiz erisim veya gecersiz PID olabilir.\n";
                }
                break;
            }
            case 3: {
                std::wcout << L"Onceligi degistirilecek islemin PID'sini girin: ";
                DWORD pid;
                std::cin >> pid;
                if (std::cin.fail()) {
                    std::cin.clear();
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    std::wcout << L"Gecersiz PID.\n";
                    break;
                }

                std::wcout << L"\nOncelik seviyeleri:\n";
                std::wcout << L"1. Dusuk (Idle)\n";
                std::wcout << L"2. Dusuk Ustu (Below Normal)\n";
                std::wcout << L"3. Normal\n";
                std::wcout << L"4. Normal Ustu (Above Normal)\n";
                std::wcout << L"5. Yuksek (High)\n";
                std::wcout << L"6. Gercek Zamanli (Realtime)\n";
                std::wcout << L"Seciminiz: ";

                int priorityChoice;
                std::cin >> priorityChoice;
                if (std::cin.fail() || priorityChoice < 1 || priorityChoice > 6) {
                    std::cin.clear();
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    std::wcout << L"Gecersiz secenek!\n";
                    break;
                }

                DWORD newPriority = NORMAL_PRIORITY_CLASS; 
                switch (priorityChoice) {
                    case 1: newPriority = IDLE_PRIORITY_CLASS; break;
                    case 2: newPriority = BELOW_NORMAL_PRIORITY_CLASS; break;
                    case 3: newPriority = NORMAL_PRIORITY_CLASS; break;
                    case 4: newPriority = ABOVE_NORMAL_PRIORITY_CLASS; break;
                    case 5: newPriority = HIGH_PRIORITY_CLASS; break;
                    case 6: newPriority = REALTIME_PRIORITY_CLASS; break;
                    default: 
                        std::wcout << L"Gecersiz secenek!\n";
                        break;
                }

                if (setProcessPriority(pid, newPriority)) {
                    std::wcout << L"Islem onceligi basariyla degistirildi.\n";
                } else {
                    std::wcout << L"Islem onceligi degistirilemedi! Yetkisiz erisim veya gecersiz PID olabilir.\n";
                }
                break;
            }
            case 4: {
                std::wcout << L"Detaylari gosterilecek islemin PID'sini girin: ";
                DWORD pid;
                std::cin >> pid;
                if (std::cin.fail()) {
                    std::cin.clear();
                    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                    std::wcout << L"Gecersiz PID.\n";
                    break;
                }
                showProcessDetails(pid);
                break;
            }
            case 5: {
                auto processes = getRunningProcesses();
                
                processes.erase(
                    std::remove_if(processes.begin(), processes.end(),
                        [](const ProcessInfo& process) {
                            return process.processName == L"TaskManager.exe";
                        }), 
                    processes.end()
                );

                filterAndSortProcesses(processes);
                
                std::wcout << std::left 
                        << std::setw(8) << L"PID" 
                        << std::setw(40) << L"Islem Adi"
                        << std::setw(20) << L"Bellek (MB)"
                        << std::setw(15) << L"CPU %"
                        << L"Oncelik" << std::endl;
                std::wcout << std::wstring(100, L'-') << std::endl;

                for (const auto& process : processes) {
                    std::wcout << std::left 
                            << std::setw(8) << process.processId
                            << std::setw(40) << process.processName
                            << std::setw(20) << std::fixed << std::setprecision(2)
                            << (process.memoryUsage / 1024.0 / 1024.0)
                            << std::setw(15) << std::setprecision(1) << process.cpuUsage
                            << process.priorityStr << std::endl;
                }
                break;
            }
            case 6:
                return 0;
            default:
                std::wcout << L"Gecersiz secenek! Lutfen 1-6 arasinda bir sayi girin.\n";
                break;
        }
    }

    return 0;
} 