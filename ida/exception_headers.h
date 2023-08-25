typedef struct _EXCEPTION_RECORD {
  int                    ExceptionCode;
  int                    ExceptionFlags;
  struct _EXCEPTION_RECORD *ExceptionRecord;
  void*                    ExceptionAddress;
  int                    NumberParameters;
  void*                ExceptionInformation[15];
} EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

typedef struct _FLOATING_SAVE_AREA {
    int   ControlWord;
    int   StatusWord;
    int   TagWord;
    int   ErrorOffset;
    int   ErrorSelector;
    int   DataOffset;
    int   DataSelector;
    char    RegisterArea[80];
    int   Spare0;
} FLOATING_SAVE_AREA;

typedef struct  _CONTEXT {

    //
    // The flags values within this flag control the contents of
    // a CONTEXT record.
    //
    // If the context record is used as an input parameter, then
    // for each portion of the context record controlled by a flag
    // whose value is set, it is assumed that that portion of the
    // context record contains valid context. If the context record
    // is being used to modify a threads context, then only that
    // portion of the threads context will be modified.
    //
    // If the context record is used as an IN OUT parameter to capture
    // the context of a thread, then only those portions of the thread's
    // context corresponding to set flags will be returned.
    //
    // The context record is never used as an OUT only parameter.
    //

    int ContextFlags;

    //
    // This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
    // set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
    // included in CONTEXT_FULL.
    //

    int   Dr0;
    int   Dr1;
    int   Dr2;
    int   Dr3;
    int   Dr6;
    int   Dr7;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
    //

    FLOATING_SAVE_AREA FloatSave;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_SEGMENTS.
    //

    int   SegGs;
    int   SegFs;
    int   SegEs;
    int   SegDs;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_INTEGER.
    //

    int   Edi;
    int   Esi;
    int   Ebx;
    int   Edx;
    int   Ecx;
    int   Eax;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_CONTROL.
    //

    int   Ebp;
    int   Eip;
    int   SegCs;              // MUST BE SANITIZED
    int   EFlags;             // MUST BE SANITIZED
    int   Esp;
    int   SegSs;

    //
    // This section is specified/returned if the ContextFlags word
    // contains the flag CONTEXT_EXTENDED_REGISTERS.
    // The format and contexts are processor specific
    //

    char    ExtendedRegisters[512];

} CONTEXT;
typedef CONTEXT *PCONTEXT;
typedef struct _EXCEPTION_POINTERS {
  PEXCEPTION_RECORD ExceptionRecord;
  PCONTEXT          ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;
#define EXCEPTION_CONTINUE_SEARCH   0
#define EXCEPTION_EXECUTE_HANDLER   1
#define EXCEPTION_CONTINUE_EXECUTION -1