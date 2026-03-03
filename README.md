# PInject
It's a single-header library for injecting shared/static libraries in 32-bit Linux environments.

### Example Usage:
```c
#include <pinject.h>

int main () {
    // Enable PInject debug messages
    pinject_debug_enabled = 1;

    // Begin the pinject session
    pinject_data session = pinject_begin( YOUR_PID );

    // Perform dlopen on target pid
    void *result = pinject_dlopen( &session, "/var/goober.so", RTLD_NOW );

    // Check if there's any error message
    if ( !result ) {
        char message[ 512 ];
        message[ 0 ] = '\0';
        pinject_dlerror( &session, message, 512 );
        printf( "dlerror(): %s", message );
    }

    // Do some stuff here, like continuing the process for a while
    // After that, if you want to close the library, do this:
    pinject_dlclose( &session, result );

    // Make sure to finish the session after usage or
    // you'll face unforeseen consequences
    pinject_finish( &session );

    return 0;
}
```

### Definitions:
```cpp
typedef struct pinject_data_s {
    uint8_t valid;
    int32_t pid;
    ulong dlopen;
    ulong dlclose;
    ulong dlerror;
    user_regs_t regs;
    user_regs_t tempregs;
} pinject_data;

// Returns the base address if name (needle) found in the haystack (process map)
// otherwise returns 0
ulong_t pinject_getmodbase ( int32_t pid, const char *name );

// Returns the pid of a process by name, same behavior as coreutils' pidof
int32_t pinject_pidof ( const char *name );

// Begin session
pinject_data pinject_begin ( int32_t pid );

// Same behavior as dlopen()
void *pinject_dlopen ( pinject_data *data, const char *file, int mode );

// Same behavior as dlclose()
int pinject_dlclose ( pinject_data *data, void *handle );

// Similar behavior as dlerror but writes the error string to output
void pinject_dlerror ( pinject_data *data, char *output, ulong_t outputSz );

// Finish the session
int pinject_finish ( pinject_data *data )
```
### License
It's public domain. #dwtfyw xD
