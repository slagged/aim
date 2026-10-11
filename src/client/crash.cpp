#include "client.h"
#include <stdarg.h>

static LPTOP_LEVEL_EXCEPTION_FILTER previous_filter;
static int reporting_exception;
static char exception_text[0x104];
static char report_text[0x308];

// turn an address into a module name and section-relative offset.
int describe_address(const void *address, char *filename, int capacity, unsigned int *section, DWORD *offset)
{
    lstrcpynA(filename, "(UNKNOWN)", capacity);
    MEMORY_BASIC_INFORMATION memory;
    if (!VirtualQuery(address, &memory, sizeof(memory))) return -1;
    BYTE *base = static_cast<BYTE *>(memory.AllocationBase);
    if (!GetModuleFileNameA(reinterpret_cast<HMODULE>(base), filename, capacity)) return -2;
    if (IsBadReadPtr(base, sizeof(IMAGE_DOS_HEADER))) return 1;
    IMAGE_DOS_HEADER *dos = reinterpret_cast<IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 2;
    IMAGE_NT_HEADERS *nt = reinterpret_cast<IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
    if (IsBadReadPtr(nt, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))) return 3;
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 4;
    DWORD rva = static_cast<const BYTE *>(address) - base;
    IMAGE_SECTION_HEADER *header = IMAGE_FIRST_SECTION(nt);
    for (unsigned int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++header) {
        DWORD size = header->SizeOfRawData > header->Misc.VirtualSize ? header->SizeOfRawData : header->Misc.VirtualSize;
        // The original accepts the endpoint, despite PE ranges being half-open.
        if (rva >= header->VirtualAddress && rva <= header->VirtualAddress + size) {
            *section = i + 1;
            *offset = rva - header->VirtualAddress;
            return 0;
        }
    }
    return 0xff;
}

// use stable names for common exceptions, then ask NTDLL for others.
const char *exception_name(DWORD code)
{
    switch (code) {
#define EXCEPTION_NAME(value) case EXCEPTION_##value: return #value
        EXCEPTION_NAME(GUARD_PAGE);
        EXCEPTION_NAME(DATATYPE_MISALIGNMENT);
        EXCEPTION_NAME(BREAKPOINT);
        EXCEPTION_NAME(SINGLE_STEP);
        EXCEPTION_NAME(ACCESS_VIOLATION);
        EXCEPTION_NAME(IN_PAGE_ERROR);
        EXCEPTION_NAME(INVALID_HANDLE);
        EXCEPTION_NAME(ILLEGAL_INSTRUCTION);
        EXCEPTION_NAME(NONCONTINUABLE_EXCEPTION);
        EXCEPTION_NAME(INVALID_DISPOSITION);
        EXCEPTION_NAME(ARRAY_BOUNDS_EXCEEDED);
        EXCEPTION_NAME(FLT_DENORMAL_OPERAND);
        EXCEPTION_NAME(FLT_DIVIDE_BY_ZERO);
        EXCEPTION_NAME(FLT_INEXACT_RESULT);
        EXCEPTION_NAME(FLT_INVALID_OPERATION);
        EXCEPTION_NAME(FLT_OVERFLOW);
        EXCEPTION_NAME(FLT_STACK_CHECK);
        EXCEPTION_NAME(FLT_UNDERFLOW);
        EXCEPTION_NAME(INT_DIVIDE_BY_ZERO);
        EXCEPTION_NAME(INT_OVERFLOW);
        EXCEPTION_NAME(PRIV_INSTRUCTION);
        EXCEPTION_NAME(STACK_OVERFLOW);
#undef EXCEPTION_NAME
    }
    FormatMessageA(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS,
        GetModuleHandleA("NTDLL.DLL"), code, 0, exception_text, sizeof(exception_text), 0);
    return exception_text;
}

// collect crash properties through OSCORE's reporting interface.
int report_property(const char *name, const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    wvsprintfA(report_text, format, arguments);
    va_end(arguments);
    return PHSetString("EXCEPTION", name, report_text);
}

// follow ascending, aligned EBP links while their frames are readable.
DWORD report_calltrace(const CONTEXT *context)
{
    DWORD *frame = reinterpret_cast<DWORD *>(context->Ebp);
    DWORD address = context->Eip;
    char module[0x104];
    char property[0x20];
    unsigned int section;
    DWORD offset;
    describe_address(reinterpret_cast<void *>(address), module, sizeof(module), &section, &offset);
    wsprintfA(property, "CALLTRACE%d", 1);
    report_property(property, "%08X %08X %s", frame, address, module);
    for (int index = 2;; ++index) {
        if (IsBadReadPtr(frame, 8)) return 1;
        address = frame[1];
        DWORD *previous = frame;
        frame = reinterpret_cast<DWORD *>(frame[0]);
        if ((reinterpret_cast<DWORD>(frame) & 3) || frame <= previous) return address;
        describe_address(reinterpret_cast<void *>(address), module, sizeof(module), &section, &offset);
        wsprintfA(property, "CALLTRACE%d", index);
        report_property(property, "%08X %08X %s", frame, address, module);
    }
}

// report the fault site and the complete x86 register snapshot.
DWORD report_exception(EXCEPTION_POINTERS *exception)
{
    char module[0x104];
    unsigned int section = 0;
    DWORD offset = 0;
    EXCEPTION_RECORD *record = exception->ExceptionRecord;
    describe_address(record->ExceptionAddress, module, sizeof(module), &section, &offset);
    report_property("TYPE", "%s @%02X:%08X(%08X) did %08X-%s", module, section, offset,
        record->ExceptionAddress, record->ExceptionCode, exception_name(record->ExceptionCode));
    CONTEXT *context = exception->ContextRecord;
    report_property("REGS", "AX:%08X CS:%04X IP:%08X FLGS:%08X BX:%08X SS:%04X SP:%08X BP:%08X CX:%08X DS:%04X SI:%08X FS:%04X DX:%08X ES:%04X DI:%08X GS:%04X",
        context->Eax, context->SegCs, context->Eip, context->EFlags,
        context->Ebx, context->SegSs, context->Esp, context->Ebp,
        context->Ecx, context->SegDs, context->Esi, context->SegFs,
        context->Edx, context->SegEs, context->Edi, context->SegGs);
    return report_calltrace(context);
}

// avoid recursion if crash reporting itself faults, then chain the
// previous handler. EXCEPTION_EXECUTE_HANDLER is the observed reentry result.
LONG WINAPI client_exception_filter(EXCEPTION_POINTERS *exception)
{
    if (reporting_exception) return EXCEPTION_EXECUTE_HANDLER;
    reporting_exception = 1;
    report_exception(exception);
    PHSetGeneralInfo();
    reporting_exception = 0;
    return previous_filter ? previous_filter(exception) : EXCEPTION_CONTINUE_SEARCH;
}

// no caller was recovered in the application prefix.
void install_exception_filter()
{
    previous_filter = SetUnhandledExceptionFilter(client_exception_filter);
}
