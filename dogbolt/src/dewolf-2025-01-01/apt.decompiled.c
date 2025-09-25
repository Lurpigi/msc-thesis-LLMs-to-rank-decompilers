extern unsigned char data_5019[0x7] = "\x00\x00\x00\x00\x00\x00\x00";
extern void * data_5008 = &data_5008;
extern char data_5018 = 0;



long sub_2020() {/* jump -> undetermined */}



long sub_2030() {
    return sub_2020();
}



long sub_2040() {
    return sub_2020();
}



long sub_2050() {
    return sub_2020();
}



long sub_2060() {
    return sub_2020();
}



long sub_2070() {
    return sub_2020();
}



long sub_2080() {
    return sub_2020();
}



long sub_2090() {
    return sub_2020();
}



long sub_20a0() {
    return sub_2020();
}



long sub_20b0() {
    return sub_2020();
}



long sub_20c0() {
    return sub_2020();
}



long sub_20d0() {
    return sub_2020();
}



long sub_20e0() {
    return sub_2020();
}



long sub_20f0() {
    return sub_2020();
}



long sub_2100() {
    return sub_2020();
}



long sub_2110() {
    return sub_2020();
}



long sub_2120() {
    return sub_2020();
}



long sub_2130() {
    return sub_2020();
}



long sub_2140() {
    return sub_2020();
}



long sub_2150() {
    return sub_2020();
}



long sub_2160() {
    return sub_2020();
}



long sub_2170() {
    return sub_2020();
}

struct _Unwind_Exception {
    unsigned long exception_class;
    void(_Unwind_Reason_Code, _Unwind_Exception *) * exception_cleanup;
    unsigned long private_1;
    unsigned long private_2;
};
enum _Unwind_Reason_Code {
    _URC_NO_REASON = 0,
    _URC_FOREIGN_EXCEPTION_CAUGHT = 1,
    _URC_FATAL_PHASE2_ERROR = 2,
    _URC_FATAL_PHASE1_ERROR = 3,
    _URC_NORMAL_STOP = 4,
    _URC_END_OF_STACK = 5,
    _URC_HANDLER_FOUND = 6,
    _URC_INSTALL_CONTEXT = 7,
    _URC_CONTINUE_UNWIND = 8
};

void sub_22e0(_Unwind_Exception * arg1, long * arg2) {
    if (*arg2 != 0L) {
        operator_delete(/* ptr */ *arg2);
    }
    _Unwind_Resume(/* exc */ arg1);
}

class std::streambuf {
    int() ** _vptr.basic_streambuf;
    char * _M_in_beg;
    char * _M_in_cur;
    char * _M_in_end;
    char * _M_out_beg;
    char * _M_out_cur;
    char * _M_out_end;
    std::locale _M_buf_locale;
};
class std::locale {
    std::locale::id * [0] _S_twinned_facets;
};
class std::locale::id {
    int _S_refcount;
};

int main(int argc, char ** argv, char ** envp) {
    void var_0;
    short var_6;
    int var_4;
    long var_3;
    void * var_5;
    var_5 = &var_0;
    CommandLine::CommandLine();
    ParseCommandLine(&var_3, &var_0, 0UL, _config, _system & 0xffffffff, (unsigned int)argc, argv, sub_25c0);
    var_4 = Configuration::FindI(*_config, "quiet");
    if (var_4 == 2) {
        Configuration::CndSet(*_config, "quiet::NoProgress");
        Configuration::Set(*_config, "quiet");
    }
    InitSignals();
    InitOutput(*0x50b0);
    CheckIfCalledByScript(argc, argv);
    CheckIfSimulateMode(var_5);
    var_6 = DispatchCommandLine(var_5, &var_3);
    if (var_3 != 0L) {
        operator_delete(/* ptr */ var_3);
    }
    CommandLine::~CommandLine();
    return (unsigned short)var_6;
}

struct _Unwind_Exception {
    unsigned long exception_class;
    void(_Unwind_Reason_Code, _Unwind_Exception *) * exception_cleanup;
    unsigned long private_1;
    unsigned long private_2;
};
enum _Unwind_Reason_Code {
    _URC_NO_REASON = 0,
    _URC_FOREIGN_EXCEPTION_CAUGHT = 1,
    _URC_FATAL_PHASE2_ERROR = 2,
    _URC_FATAL_PHASE1_ERROR = 3,
    _URC_NORMAL_STOP = 4,
    _URC_END_OF_STACK = 5,
    _URC_HANDLER_FOUND = 6,
    _URC_INSTALL_CONTEXT = 7,
    _URC_CONTINUE_UNWIND = 8
};

void sub_245c(_Unwind_Exception * arg1, void * arg2) {
    arg2 -= 112L;
    if (*arg2 != 0L) {
        operator_delete(/* ptr */ *arg2);
    }
    CommandLine::~CommandLine();
    _Unwind_Resume(/* exc */ arg1);
}

class std::ios_base::Init {
    bool _S_synced_with_stdio;
};

long _INIT_1() {
    std::ios_base::Init::Init(/* this */ data_5019);
    return __cxa_atexit(/* func */ _ZNSt8ios_base4InitD1Ev, data_5019, /* dso_handle */ &data_5008);
}



void sub_2530() {
    return;
}



void _FINI_0() {
    void * var_2;
    if (data_5018 != 0) {
        return;
    }
    var_2 = data_5008;
    __cxa_finalize(/* d */ var_2);
    deregister_tm_clones();
    data_5018 = 1;
    return;
}



void _INIT_0() {
    return sub_2530();
}

enum std::_Ios_Iostate {
    _S_goodbit = 0,
    _S_badbit = 1,
    _S_eofbit = 2,
    _S_failbit = 4,
    _S_ios_iostate_end = 65536,
    _S_ios_iostate_max = 2147483647,
    _S_ios_iostate_min = 2147483648
};
class std::ostream {
    int() ** _vptr.basic_ostream;
};

std::vector<CommandLine::Dispatch> sub_25c0() {
    char * var_2;
    var_2 = dgettext(/* domainname */ "apt", /* msgid */ "Usage: apt [options] command\\n\\napt is a commandline package manager and provides commands for\\nsearching and managing as wel...");
    if (var_2 == 0L) {
        std::ios::clear(/* this */ *(*_ZSt4cout - 24L) + _ZSt4cout, /* __state */ *(*(*_ZSt4cout - 24L) + 0x4fe0) | 1);
        return 1L;
    }
    std::__ostream_insert<char>(/* __out */ _ZSt4cout, /* __s */ var_2, /* __n */ strlen(var_2));
    return 1L;
}



void *** sub_2630(void *** arg1) {
    long var_68;
    long var_69;
    void * var_72;
    void * var_73;
    void ** var_70;
    void ** var_71;
    var_71 = "list";
    dgettext(/* domainname */ "apt", /* msgid */ "list packages based on package names");
    dgettext(/* domainname */ "apt", /* msgid */ "search in package descriptions");
    dgettext(/* domainname */ "apt", /* msgid */ "show package details");
    dgettext(/* domainname */ "apt", /* msgid */ "reinstall packages");
    dgettext(/* domainname */ "apt", /* msgid */ "reinstall packages");
    dgettext(/* domainname */ "apt", /* msgid */ "remove packages");
    dgettext(/* domainname */ "apt", /* msgid */ "Remove automatically all unused packages");
    dgettext(/* domainname */ "apt", /* msgid */ "update list of available packages");
    dgettext(/* domainname */ "apt", /* msgid */ "upgrade the system by installing/upgrading packages");
    dgettext(/* domainname */ "apt", /* msgid */ "upgrade the system by removing/installing/upgrading packages");
    dgettext(/* domainname */ "apt", /* msgid */ "edit the source information file");
    dgettext(/* domainname */ "apt", /* msgid */ "satisfy dependency strings");
    __builtin_memset(/* s */ arg1, /* c */ 0L, /* n */ 24L);
    __builtin_memset(/* s */ &var_68, /* c */ 0L, /* n */ 32L);
    var_70 = operator_new(/* sz */ 0x2d0);
    *arg1 = var_70;
    var_72 = var_70 + 0x2d0;
    *(arg1 + 16L) = var_72;
    *var_70 = var_71;
    *(var_70 + 0x2c8) = var_69;
    var_73 = var_70 + 8L & -8L;
    var_69 = var_70 - var_73;
    __builtin_memcpy(/* dest */ var_73, /* src */ &var_71 - var_69, /* n */ (unsigned long)((void *)var_69 + 0x2d0 >> 3) << 3L);
    *(arg1 + 8L) = var_72;
    return arg1;
}

struct _Unwind_Exception {
    unsigned long exception_class;
    void(_Unwind_Reason_Code, _Unwind_Exception *) * exception_cleanup;
    unsigned long private_1;
    unsigned long private_2;
};
enum _Unwind_Reason_Code {
    _URC_NO_REASON = 0,
    _URC_FOREIGN_EXCEPTION_CAUGHT = 1,
    _URC_FATAL_PHASE2_ERROR = 2,
    _URC_FATAL_PHASE1_ERROR = 3,
    _URC_NORMAL_STOP = 4,
    _URC_END_OF_STACK = 5,
    _URC_HANDLER_FOUND = 6,
    _URC_INSTALL_CONTEXT = 7,
    _URC_CONTINUE_UNWIND = 8
};

void sub_2be9(_Unwind_Exception * arg1) {
    long * var_0;
    return sub_22e0(arg1, var_0);
}
