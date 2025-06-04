#include <cstdint>
#include <cstdio>
#include <windows.h>
#include <winternl.h>

#define DBG_PRINTEXCEPTION_C 0x40010006

typedef FARPROC( WINAPI* get_proc_address_t )( HMODULE, LPCSTR );

struct hook_context_t
{
    HMODULE module;
    LPCSTR name;
};

namespace
{
    get_proc_address_t o__get_proc_address = nullptr;

    hook_context_t captured_context = { nullptr };
    [[maybe_unused]] uint64_t o__return_address = 0;

    bool
    data_compare(
        const char* data,
        const char* b_mask,
        const char* sz_mask
    )
    {
        for ( ; *sz_mask; ++sz_mask, ++data, ++b_mask )
        {
            if ( *sz_mask == 'x' && *data != *b_mask )
            {
                return false;
            }
        }

        return !*sz_mask;
    }

    uint64_t
    find_pattern(
        const uint64_t base_address,
        const size_t size,
        const char* b_mask,
        const char* sz_mask
    )
    {
        for ( size_t i = 0; i < size; ++i )
        {
            if ( data_compare( reinterpret_cast< const char* >( base_address + i ), b_mask, sz_mask ) )
            {
                return base_address + i;
            }
        }

        return 0;
    }

    void
    enable_ldrp_debug_flags()
    {
        auto* ntdll = GetModuleHandleA( "ntdll.dll" );
        auto* ntdll_base = ( uint8_t* )ntdll;

        const auto pattern_addr = find_pattern(
            ( uint64_t )ntdll_base,
            0x200000,
            "\x8B\x0D\x00\x00\x00\x00\x80\x3D",
            "xx????xx"
        );

        if ( pattern_addr )
        {
            const auto offset = *( uint32_t* )( pattern_addr + 2 );
            auto* flag_addr = ( uint32_t* )( pattern_addr + 6 + offset );

            printf( "[*] Found LdrpDebugFlags at: %llX\n", flag_addr );

            unsigned long old_protect;
            VirtualProtect( flag_addr, sizeof( old_protect ), PAGE_READWRITE, &old_protect );
            *flag_addr = 5;
            VirtualProtect( flag_addr, sizeof( old_protect ), old_protect, &old_protect );

            printf( "[+] LdrpDebugFlags set to: %X\n", *flag_addr );
            return;
        }

        printf( "[-] Failed to find LdrpDebugFlags pattern\n" );
    }

    extern "C" FARPROC
    hkd__get_proc_address_for_caller()
    {
        auto* module = captured_context.module;
        auto* name = captured_context.name;
        auto* original_result = o__get_proc_address( module, name );

        printf( "[HOOK] GetProcAddress intercepted\n" );
        if ( HIWORD( name ) )
        {
            printf( "[HOOK] Module: %llX, Function: %s\n", module, name );
            printf( "[HOOK] Original result: %llX\n", original_result );

            if ( strcmp( name, "LoadLibraryA" ) == 0 )
            {
                printf( "[HOOK] Returning custom LoadLibraryA\n" );
                return ( FARPROC )0xDEADBEEFCAFEBABE;
            }
        }
        else
        {
            printf( "[HOOK] Module: %llX, Ordinal: %X\n", module, LOWORD( name ) );
        }

        return original_result;
    }

    extern "C" void
    hook_trampoline()
    {
        __asm {
            pop rax
            mov [o__return_address], rax

            push rax
            push rcx
            push rdx
            push r8
            push r9
            push r10
            push r11

            sub rsp, 0x20

            call hkd__get_proc_address_for_caller

            add rsp, 0x20

            pop r11
            pop r10
            pop r9
            pop r8
            pop rdx
            pop rcx
            add rsp, 8

            jmp [o__return_address]
        }
    }

    LONG WINAPI
    vectored_exception_handler( const PEXCEPTION_POINTERS exception_info )
    {
        if ( exception_info->ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_C )
        {
            printf( "[VEH] Caught debug print exception\n" );

            const auto* context = exception_info->ContextRecord;
            auto* stack_pointer = ( uint64_t* )context->Rsp;

            auto* original_module = ( HMODULE ) * ( stack_pointer + 0x648 / 8 );
            auto* original_proc_name = ( LPCSTR ) * ( stack_pointer + 0x650 / 8 );

            captured_context.module = original_module;
            captured_context.name = original_proc_name;

            const auto kernel_base = GetModuleHandleA( "kernelbase.dll" );
            if ( !kernel_base )
            {
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            auto* kernel_base_start = ( uint8_t* )kernel_base;
            const auto* dos_header = ( PIMAGE_DOS_HEADER )kernel_base;
            const auto* nt_headers = ( PIMAGE_NT_HEADERS )( kernel_base_start + dos_header->e_lfanew );
            const auto kernel_base_size = nt_headers->OptionalHeader.SizeOfImage;
            unsigned char* get_proc_address_for_caller = nullptr;

            const auto get_proc_address_for_caller_pattern = find_pattern(
                ( uint64_t )kernel_base_start,
                kernel_base_size,
                "\x48\x8B\xC4\x48\x89\x58\x00\x48\x89\x68\x00\x48\x89\x70\x00\x57\x48\x83\xEC\x00\x49\x8B\xE8\x48\x8B\xF2\x48\x8B\xF9",
                "xxxxxx?xxx?xxx?xxxx?xxxxxxxxx"
            );

            if ( get_proc_address_for_caller_pattern )
            {
                get_proc_address_for_caller = ( unsigned char* )get_proc_address_for_caller_pattern;
            }

            if ( !get_proc_address_for_caller )
            {
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            const auto target_return = ( uint64_t )get_proc_address_for_caller + 0x6C;
            for ( int i = 0; i < 0x200; i++ )
            {
                const auto possible_return = stack_pointer[ i ];

                if ( possible_return == target_return )
                {
                    printf( "[VEH] Found GetProcAddressForCaller+0x6C at RSP+%X: %llX\n", i * 8, ( void* )possible_return );
                    printf( "[VEH] Current RAX: %llX\n", ( void* )context->Rax );

                    stack_pointer[ i ] = ( uint64_t )hook_trampoline;
                    break;
                }
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }
} // namespace

int
main()
{
    printf( "[*] Automatic LDR Hook via Exception Handling\n" );

    o__get_proc_address = &GetProcAddress;
    printf( "[*] Original GetProcAddress: %p\n", o__get_proc_address );
    printf( "[*] Hook trampoline: %p\n", hook_trampoline );

    auto* veh = AddVectoredExceptionHandler( 1, vectored_exception_handler );
    printf( "[*] VEH installed\n" );

    auto* peb = ( PPEB )__readgsqword( 0x60 );
    peb->BeingDebugged = FALSE;
    printf( "[*] PEB->BeingDebugged set to FALSE\n" );

    enable_ldrp_debug_flags();

    printf( "\n[*] Testing GetProcAddress hook...\n" );
    const HMODULE kernel32 = GetModuleHandleA( "kernel32.dll" );

    printf( "\n[*] Calling GetProcAddress for LoadLibraryA\n" );
    const FARPROC proc = GetProcAddress( kernel32, "LoadLibraryA" );
    printf( "[*] GetProcAddress returned: %p\n", proc );

    printf( "\n[*] Done\n" );

    getchar();

    RemoveVectoredExceptionHandler( veh );
    return 0;
}
