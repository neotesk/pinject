/*
    This is PInject, a PTrace wrapper specifically made for injecting
    libraries to a target process. It's specifically made for 32-bit
    environment.

    Open-Source, Public Domain.
    2026 neotesk.
*/

// Throw an error on compile time if we are being compiled
// as a 64-bit library or executable.
#ifdef __x86_64__
#error "64-bit x86 is not supported."
#endif

// Forcefully undefine x86_64 flag so the LSP can shut it's mouth
#undef __x86_64__

#include <dlfcn.h>
#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/user.h>

// We need these, do not touch.
#define BUFFER_MAX     512
#define CDECL_SAFEZONE 1024

// Custom assertion
#define assertp( condition, message, ... ) \
    if ( condition ) { \
        printf( "Fatal Error! " message, ##__VA_ARGS__ ); \
        return 0; \
    }
#define asserti( condition, message, ... ) \
    if ( condition ) { \
        printf( "Fatal Error! " message, ##__VA_ARGS__ ); \
        return output; \
    }
#define assertv( condition, message, ... ) \
    if ( condition ) { \
        printf( "Fatal Error! " message, ##__VA_ARGS__ ); \
        return; \
    }

// Custom types since C doesn't support some
typedef struct user_regs_struct user_regs_t;
typedef unsigned char bool_t;
static const bool_t TRUE  = 1;
static const bool_t FALSE = 0;

// Use the given debug command
static bool_t pinject_debug_enabled = FALSE;
#define debugger( format, ... ) \
    if ( pinject_debug_enabled ) { \
        printf( "pinject: " format "\n", ##__VA_ARGS__ ); \
    }

// Custom structure so it holds our important stuff
typedef struct pinject_data_s {
    uint8_t valid;
    int32_t pid;
    ulong dlopen;
    ulong dlclose;
    ulong dlerror;
    user_regs_t regs;
    user_regs_t tempregs;
} pinject_data;

// Some helpers that we're gonna need
static inline bool_t __poke_text ( int32_t pid, ulong addr,
    const char *content ) {
    int32_t length = strlen( content ) + 1;
    uint32_t szWord = sizeof( long );
    ulong word;
    for ( int i = 0; i < length; i += szWord ) {
        word = 0;
        memcpy( &word, content + i, ( length - i > szWord )
            ? szWord : ( length - i ) );
        assertp( ptrace( PTRACE_POKETEXT, pid, addr + i, word ) == -1,
            "Failed to write word (%d bytes) at address %p.",
            szWord, ( void* )( addr + i ) );
    }
    return 1;
}
static inline void __peek_text ( int32_t pid, ulong addr, char *buffer,
    int32_t maxLen ) {
    ulong szWord = sizeof( long );
    long word;
    for ( int i = 0; i < maxLen; i += szWord ) {
        word = ptrace( PTRACE_PEEKTEXT, pid, addr + i, NULL );
        if ( word == -1 )
            break;
        memcpy(buffer + i, &word, szWord );
        if ( memchr( &word, 0, szWord ) )
            break;
    }
}
static ulong pinject_getmodbase ( int32_t pid, const char *name ) {
    char path[ 256 ];
    snprintf( path, sizeof( path ), "/proc/%d/maps", pid );
    FILE *maps = fopen( path, "r" );
    if ( !maps )
        return 0;

    char line[ 512 ];
    ulong addr = 0;

    while ( fgets( line, sizeof( line ), maps ) ) {
        if ( !strstr( line, name ) )
            continue;
        addr = strtoul( line, NULL, 16 );
        break;
    }

    fclose( maps );
    return addr;
}
static int32_t pinject_pidof ( const char *name ) {
    DIR *dir = opendir( "/proc" );
    assertp( !dir, "Cannot open /proc directory" );

    struct dirent* entry;
    char path[ 256 ];
    char comm[ 16 ];

    while ( ( entry = readdir( dir ) ) != NULL ) {
        if ( entry->d_type != DT_DIR || !isdigit( entry->d_name[ 0 ] ) )
            continue;
        snprintf( path, sizeof( path ), "/proc/%s/comm", entry->d_name );
        int fd = open( path, O_RDONLY );
        if ( fd == -1 )
            continue;
        long len = read( fd, comm, sizeof( comm ) - 1 );
        close( fd );
        if ( len == 0 )
            continue;
        comm[ len ] = '\0';
        if ( comm[ len - 1 ] == '\n' )
            comm[ len - 1 ] = '\0';
        if ( strcmp( comm, name ) != 0 )
            continue;
        int32_t pid = atoi( entry->d_name );
        closedir( dir );
        return pid;
    }

    closedir( dir );
    return -1;
}
static bool_t __get_regs ( int32_t pid, user_regs_t *regs ) {
    long regFetched = ptrace( PTRACE_GETREGS, pid, 0, regs ) != -1;
    assertp( !regFetched, "Cannot get registries of target process." );
    debugger( "Fetched process' registries! EIP: %p, ESI: %p, ESP: %p EAX: %p",
        regs->eip, regs->esi, regs->esp, regs->eax );
    return 1;
}
static bool_t __set_regs ( int32_t pid, user_regs_t *regs ) {
    long regFetched = ptrace( PTRACE_SETREGS, pid, 0, regs ) != -1;
    assertp( !regFetched, "Cannot set registries of target process." );
    debugger( "Changed process' registries! EIP: %p, ESI: %p, ESP: %p EAX: %p",
        regs->eip, regs->esi, regs->esp, regs->eax );
    return 1;
}

// Here comes the good stuff
static pinject_data pinject_begin ( int32_t pid ) {
    pinject_data output;
    output.valid = 0;
    output.pid = pid;

    // Attach to the process
    long attached = ptrace( PTRACE_ATTACH, pid, 0, 0 ) != -1;
    asserti( !attached, "Cannot attach to process." );
    debugger( "Attached to process with PID %d!", pid );

    // Wait for the process to stop
    waitpid( pid, NULL, 0 );

    // Get our own dlclose and dlopen functions, we need them to
    // calculate base offset.
    void *dlopenLcl = dlsym( RTLD_DEFAULT, "dlopen" );
    void *dlcloseLcl = dlsym( RTLD_DEFAULT, "dlclose" );
    void *dlerrorLcl = dlsym( RTLD_DEFAULT, "dlerror" );

    asserti( !dlopenLcl, "Cannot locate 'dlopen' symbol in target process." );
    debugger( "Located 'dlopen' symbol at address %p!", dlopenLcl );

    asserti( !dlcloseLcl, "Cannot locate 'dlclose' symbol in target process." );
    debugger( "Located 'dlclose' symbol at address %p!", dlcloseLcl );

    asserti( !dlerrorLcl, "Cannot locate 'dlerror' symbol in target process." );
    debugger( "Located 'dlerror' symbol at address %p!", dlerrorLcl );

    // Test if libdl or libc is available in our process
    const char *libPath = "libdl.so";
    ulong localBase = pinject_getmodbase( getpid(), libPath );
    if ( localBase == 0 ) {
        libPath = "libc.so";
        localBase = pinject_getmodbase( getpid(), libPath );
    }

    // Now check again if it has been loaded
    asserti( !localBase, "Cannot locate a baseplate library for "
        "dlopen/dlclose operations." );
    debugger( "Located baseplate library '%s' for dl operations!", libPath );

    // Get the base address of functions
    ulong dlopenOffs = ( ulong )dlopenLcl - localBase;
    ulong dlcloseOffs = ( ulong )dlcloseLcl - localBase;
    ulong dlerrorOffs = ( ulong )dlerrorLcl - localBase;

    // Load the target's dl library
    ulong remoteBase = pinject_getmodbase( pid, libPath );
    asserti( !remoteBase, "Target process with PID %d does not have '%s' in "
        "it's process map.", pid, libPath );

    // Now apply these offsets to get the target process' own dlopen
    // and dlclose calls.
    ulong dlopenTarget = remoteBase + dlopenOffs;
    ulong dlcloseTarget = remoteBase + dlcloseOffs;
    ulong dlerrorTarget = remoteBase + dlerrorOffs;

    debugger( "ASLR bypassed! dlopen: %p, dlclose: %p, dlerror: %p",
        dlopenTarget, dlcloseTarget, dlerrorTarget );

    output.dlopen = dlopenTarget;
    output.dlclose = dlcloseTarget;
    output.dlerror = dlerrorTarget;

    // Get the current registry so we can jump back after executing
    // operations.
    if ( !__get_regs( pid, &output.regs ) )
        return output;

    // Copy the registry to the temp section
    memcpy( &output.tempregs, &output.regs, sizeof( output.tempregs ) );

    output.valid = 1;

    return output;
}

static void *pinject_dlopen ( pinject_data data, const char *file, int mode ) {
    // Firstly, we need to align base ESP to a 16-byte boundary for stability
    ulong baseEsp = data.tempregs.esp & ~0xF;

    // Create a trap (int 3) for the function to return to.
    ulong trapAddr = baseEsp - CDECL_SAFEZONE;
    ptrace( PTRACE_POKETEXT, data.pid, trapAddr, 0xCC );
    debugger( "Created a trap instruction at address %p!", trapAddr );

    // Get the remote address for path. We're gonna write that into
    // it's stack. Since I'm paranoid i'm gonna give 16 bytes of padding.
    const ulong szFilePath = strlen( file ) + 1;
    long remotePathAddr = ( trapAddr - szFilePath - 16 ) & ~0x3;

    // Write it to the target process' stack
    __poke_text( data.pid, remotePathAddr, file );

    // Manually build the stack frame for dlopen( path, mode )
    // [esp + 8] = mode (convert it to ulong)
    // [esp + 4] = path pointer (remotePathAddr)
    // [esp + 0] = return address (trapAddr)
    data.tempregs.esp = ( remotePathAddr - 32 ) & ~0xF;
    ptrace( PTRACE_POKETEXT, data.pid, data.tempregs.esp + 0, trapAddr );
    ptrace( PTRACE_POKETEXT, data.pid, data.tempregs.esp + 4, remotePathAddr );
    ptrace( PTRACE_POKETEXT, data.pid, data.tempregs.esp + 8, ( ulong )mode );

    // Set the function registry
    data.tempregs.eip = data.dlopen;

    // Send it straight to the target process
    bool_t regSent = __set_regs( data.pid, &data.tempregs );
    if ( !regSent )
        return 0;

    // Let it execute our tiny stack
    bool_t procContinue = ptrace( PTRACE_CONT, data.pid, 0, 0 ) != -1;
    assertp( !procContinue, "Cannot continue target process." );

    // Wait for the process to stop
    waitpid( data.pid, NULL, 0 );

    // Fetch the result
    bool_t regFetched = ptrace( PTRACE_GETREGS, data.pid,
        0, &data.tempregs ) != -1;
    assertp( !regFetched, "Cannot get registries of target process." );
    debugger( "Fetched process' registries after execution!" );

    // Reset the registries
    __set_regs( data.pid, &data.regs );

    // Return the result
    debugger( "dlopen call returned %p", data.tempregs.eax );

    return ( void* )data.tempregs.eax;
}

static int pinject_dlclose ( pinject_data data, void *handle ) {
    ulong trapAddr = data.tempregs.esp - ( BUFFER_MAX + CDECL_SAFEZONE + 16 );
    ptrace( PTRACE_POKETEXT, data.pid, trapAddr, 0xCC );
    debugger( "Created a trap instruction at address %p!", trapAddr );

    // Manually build the stack frame for dlclose( handle )
    // [esp + 4] = handle (*handle)
    // [esp + 0] = return address (trapAddr)
    data.tempregs.esp -= 16;
    ptrace( PTRACE_POKETEXT, data.pid, data.tempregs.esp + 0, trapAddr );
    ptrace( PTRACE_POKETEXT, data.pid, data.tempregs.esp + 4, ( ulong )handle );

    // Set the function registry
    data.tempregs.eip = data.dlclose;

    // Send it straight to the target process
    bool_t regSent = __set_regs( data.pid, &data.tempregs );
    if ( !regSent )
        return 0;

    // Let it execute our tiny stack
    bool_t procContinue = ptrace( PTRACE_CONT, data.pid, 0, 0 ) != -1;
    assertp( !procContinue, "Cannot continue target process." );

    // Wait for the process to stop
    waitpid( data.pid, NULL, 0 );

    // Fetch the result
    bool_t regFetched = ptrace( PTRACE_GETREGS, data.pid,
        0, &data.tempregs ) != -1;
    assertp( !regFetched, "Cannot get registries of target process." );
    debugger( "Fetched process' registries after execution!" );

    // Return the result
    return data.tempregs.eax;
}

static void pinject_dlerror ( pinject_data data, char *output,
    ulong outputSz ) {
    // Setup dlerror call (dlerror takes no arguments)
    ulong trapAddr = data.tempregs.esp - ( BUFFER_MAX + CDECL_SAFEZONE + 16 );
    ptrace( PTRACE_POKETEXT, data.pid, trapAddr, 0xCC );

    data.tempregs.esp = data.tempregs.esp - 16;
    ptrace( PTRACE_POKETEXT, data.pid, data.tempregs.esp, trapAddr );
    data.tempregs.eip = data.dlerror;

    __set_regs( data.pid, &data.tempregs );

    bool_t procContinue = ptrace( PTRACE_CONT, data.pid, 0, 0 ) != -1;
    assertv( !procContinue, "Cannot continue target process." );

    waitpid( data.pid, NULL, 0 );

    // Get the pointer to the error string (returned in EAX)
    __get_regs( data.pid, &data.tempregs );
    ulong errorStrPtr = data.tempregs.eax;

    if ( errorStrPtr ) {
        __peek_text( data.pid, errorStrPtr, output, outputSz );
        debugger( "Target dlerror: %s", output );
    } else debugger( "dlerror() also returned 0. Check dlopen address." );
}

static int pinject_finish ( pinject_data data ) {
    // Restore registriuser_regs_t *regses
    bool_t regSent = ptrace( PTRACE_SETREGS, data.pid, 0, &data.regs ) != -1;
    assertp( !regSent, "Cannot set registries of target process." );
    debugger( "Restored process' registries!" );

    // Detach from the target process
    bool_t detached = ptrace( PTRACE_DETACH, data.pid, NULL, NULL ) != -1;
    assertp( !detached, "Cannot detach from process." );
    debugger( "Detached from the process!" );

    // Continue process.
    assertp( kill( data.pid, SIGCONT ) == -1,
        "Failed to resume target process." );

    return 1;
}
