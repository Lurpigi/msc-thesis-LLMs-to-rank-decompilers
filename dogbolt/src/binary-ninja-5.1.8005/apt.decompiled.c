int64_t (* const)() _init()
{
    if (!__gmon_start__)
        return __gmon_start__;
    
    return __gmon_start__();
}

int64_t sub_402020()
{
    int64_t var_8 = 0;
    /* jump -> nullptr */
}

int64_t sub_402030()
{
    int64_t var_8 = 0;
    /* tailcall */
    return sub_402020();
}

int64_t sub_402040()
{
    int64_t var_8 = 1;
    /* tailcall */
    return sub_402020();
}

int64_t sub_402050()
{
    int64_t var_8 = 2;
    /* tailcall */
    return sub_402020();
}

int64_t sub_402060()
{
    int64_t var_8 = 3;
    /* tailcall */
    return sub_402020();
}

int64_t sub_402070()
{
    int64_t var_8 = 4;
    /* tailcall */
    return sub_402020();
}

int64_t sub_402080()
{
    int64_t var_8 = 5;
    /* tailcall */
    return sub_402020();
}

int64_t sub_402090()
{
    int64_t var_8 = 6;
    /* tailcall */
    return sub_402020();
}

int64_t sub_4020a0()
{
    int64_t var_8 = 7;
    /* tailcall */
    return sub_402020();
}

int64_t sub_4020b0()
{
    int64_t var_8 = 8;
    /* tailcall */
    return sub_402020();
}

int64_t sub_4020c0()
{
    int64_t var_8 = 9;
    /* tailcall */
    return sub_402020();
}

int64_t sub_4020d0()
{
    int64_t var_8 = 0xa;
    /* tailcall */
    return sub_402020();
}

int64_t sub_4020e0()
{
    int64_t var_8 = 0xb;
    /* tailcall */
    return sub_402020();
}

int64_t sub_4020f0()
{
    int64_t var_8 = 0xc;
    /* tailcall */
    return sub_402020();
}

int64_t sub_402100()
{
    int64_t var_8 = 0xd;
    /* tailcall */
    return sub_402020();
}

int64_t sub_402110()
{
    int64_t var_8 = 0xe;
    /* tailcall */
    return sub_402020();
}

int64_t sub_402120()
{
    int64_t var_8 = 0xf;
    /* tailcall */
    return sub_402020();
}

int64_t sub_402130()
{
    int64_t var_8 = 0x10;
    /* tailcall */
    return sub_402020();
}

int64_t sub_402140()
{
    int64_t var_8 = 0x11;
    /* tailcall */
    return sub_402020();
}

int64_t sub_402150()
{
    int64_t var_8 = 0x12;
    /* tailcall */
    return sub_402020();
}

int64_t sub_402160()
{
    int64_t var_8 = 0x13;
    /* tailcall */
    return sub_402020();
}

int64_t sub_402170()
{
    int64_t var_8 = 0x14;
    /* tailcall */
    return sub_402020();
}

void __cxa_finalize(void* d)
{
    /* tailcall */
    return __cxa_finalize(d);
}

int64_t InitOutput(class std::streambuf* arg1)
{
    /* tailcall */
    return InitOutput(arg1);
}

uint64_t strlen(char const* arg1)
{
    /* tailcall */
    return strlen(arg1);
}

int64_t CheckIfSimulateMode(CommandLine& arg1)
{
    /* tailcall */
    return CheckIfSimulateMode(arg1);
}

void CommandLine::~CommandLine()
{
    /* tailcall */
    return CommandLine::~CommandLine();
}

char* dgettext(char const* domainname, char const* msgid)
{
    /* tailcall */
    return dgettext(domainname, msgid);
}

int64_t Configuration::FindI(char const* arg1, int32_t const& arg2)
{
    /* tailcall */
    return Configuration::FindI(arg1, arg2);
}

int64_t CheckIfCalledByScript(int32_t arg1, char const** arg2)
{
    /* tailcall */
    return CheckIfCalledByScript(arg1, arg2);
}

int32_t __cxa_atexit(void (* func)(void* retval), void* arg, void* dso_handle)
{
    /* tailcall */
    return __cxa_atexit(func, arg, dso_handle);
}

int64_t operator new(std::size_t sz)
{
    /* tailcall */
    return operator new(sz);
}

void operator delete(void* ptr)
{
    /* tailcall */
    return operator delete(ptr);
}

void CommandLine::CommandLine()
{
    /* tailcall */
    return CommandLine::CommandLine();
}

void __stack_chk_fail() __noreturn
{
    /* tailcall */
    return __stack_chk_fail();
}

class std::ostream& std::__ostream_insert<char>(class std::ostream& __out, char const* __s, std::streamsize __n)
{
    /* tailcall */
    return std::__ostream_insert<char>(__out, __s, __n);
}

int64_t DispatchCommandLine(CommandLine& arg1, std::vector<CommandLine::Dispatch> const& arg2)
{
    /* tailcall */
    return DispatchCommandLine(arg1, arg2);
}

int64_t ParseCommandLine(CommandLine& arg1, APT_CMD arg2, Configuration* const* arg3, pkgSystem** arg4, int32_t arg5, char const** arg6, bool (* arg7)(CommandLine&), std::vector<aptDispatchWithHelp, std::allocator<aptDispatchWithHelp> > (* arg8)())
{
    /* tailcall */
    return ParseCommandLine(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8);
}

void std::ios_base::Init::Init(class std::ios_base::Init* const this)
{
    /* tailcall */
    return std::ios_base::Init::Init(this);
}

void std::ios::clear(class std::ios* const this, std::ios_base::iostate __state)
{
    /* tailcall */
    return std::ios::clear(this, __state);
}

void _Unwind_Resume(struct _Unwind_Exception* exc) __noreturn
{
    /* tailcall */
    return _Unwind_Resume(exc);
}

int64_t Configuration::CndSet(char const* arg1, int32_t arg2)
{
    /* tailcall */
    return Configuration::CndSet(arg1, arg2);
}

int64_t Configuration::Set(char const* arg1, int32_t const& arg2)
{
    /* tailcall */
    return Configuration::Set(arg1, arg2);
}

int64_t InitSignals()
{
    /* tailcall */
    return InitSignals();
}

void sub_4022e0(struct _Unwind_Exception* arg1 @ rbp, int64_t* arg2 @ r12) __noreturn
{
    int64_t rdi_1 = *arg2;
    arg2[2];
    
    if (rdi_1)
        operator delete(rdi_1);
    
    _Unwind_Resume(arg1);
    /* no return */
}

int32_t main(int32_t argc, char** argv, char** envp)
{
    void* fsbase;
    int64_t rax = *(fsbase + 0x28);
    void var_58;
    void* var_90 = &var_58;
    CommandLine::CommandLine();
    void*** (* var_a8)(void*** arg1) = sub_402630;
    int64_t var_78;
    ParseCommandLine(&var_78, &var_58, nullptr, _config, _system, argc, argv, sub_4025c0);
    int32_t var_7c = 0;
    
    if (Configuration::FindI(*_config, "quiet") == 2)
    {
        Configuration::CndSet(*_config, "quiet::NoProgress");
        int32_t var_7c_1 = 1;
        Configuration::Set(*_config, "quiet");
    }
    
    InitSignals();
    InitOutput(*(std::cout + 0xf0));
    CheckIfCalledByScript(argc, argv);
    CheckIfSimulateMode(var_90);
    int16_t rax_3 = DispatchCommandLine(var_90, &var_78);
    int64_t rdi_6 = var_78;
    
    if (rdi_6)
        operator delete(rdi_6);
    
    CommandLine::~CommandLine();
    *(fsbase + 0x28);
    
    if (rax == *(fsbase + 0x28))
        return rax_3;
    
    __stack_chk_fail();
    /* no return */
}

void sub_40245c(struct _Unwind_Exception* arg1 @ rax, void* arg2 @ rbp) __noreturn
{
    int64_t rdi = *(arg2 - 0x70);
    *(arg2 - 0x60);
    
    if (rdi)
        operator delete(rdi);
    
    *(arg2 - 0x88);
    CommandLine::~CommandLine();
    _Unwind_Resume(arg1);
    /* no return */
}

int64_t _INIT_1()
{
    std::ios_base::Init::Init(&data_405019);
    /* tailcall */
    return __cxa_atexit(std::ios_base::Init::~Init, &data_405019, &data_405008);
}

void _start(int64_t arg1, int64_t arg2, void (* arg3)()) __noreturn
{
    int64_t stack_end_1;
    int64_t stack_end = stack_end_1;
    void ubp_av;
    __libc_start_main(main, __return_addr, &ubp_av, nullptr, nullptr, arg3, &stack_end);
    /* no return */
}

char* deregister_tm_clones()
{
    return &data_405018;
}

int64_t (* const)() sub_402530()
{
    return nullptr;
}

void _FINI_0()
{
    if (data_405018)
        return;
    
    if (__cxa_finalize)
        __cxa_finalize(data_405008);
    
    deregister_tm_clones();
    data_405018 = 1;
}

int64_t (* const)() _INIT_0()
{
    /* tailcall */
    return sub_402530();
}

std::vector<aptDispatchWithHelp, std::allocator<aptDispatchWithHelp> > sub_4025c0()
{
    char* __s = dgettext("apt", 
        "Usage: apt [options] command\n\napt is a commandline package manager and provides commands for"
    "searching and managing as well as querying information about packages.\nIt provides the same "
    "functionality as the specialized APT tools,\nlike apt-get and apt-cache, but enables options "
    "more suitable for\ninteractive use by default.\n");
    
    if (__s)
    {
        std::__ostream_insert<char>(std::cout, __s, strlen(__s));
        return true;
    }
    
    void* rdi_2 = std::cout + *(*std::cout - 0x18);
    std::ios::clear(rdi_2, *(rdi_2 + 0x20) | 1);
    return true;
}

void*** sub_402630(void*** arg1)
{
    void* fsbase;
    int64_t rax = *(fsbase + 0x28);
    void* const var_308 = "list";
    int64_t (* const var_300)(CommandLine&) = DoList;
    char* var_2f8 = dgettext("apt", "list packages based on package names");
    void* const var_2f0 = "search";
    int64_t (* const var_2e8)(CommandLine&) = DoSearch;
    char* var_2e0 = dgettext("apt", "search in package descriptions");
    void* const var_2d8 = "show";
    int64_t (* const var_2d0)(CommandLine&) = ShowPackage;
    char* var_2c8 = dgettext("apt", "show package details");
    int64_t (* const var_2b8)(CommandLine&) = DoInstall;
    void* const var_2c0 = "install";
    int64_t (* const var_2a0)(CommandLine&) = DoInstall;
    char* var_2b0 = dgettext("apt", "install packages");
    void* const var_2a8 = "reinstall";
    int64_t (* const var_288)(CommandLine&) = DoInstall;
    char* var_298 = dgettext("apt", "reinstall packages");
    void* const var_290 = "remove";
    int64_t (* const var_270)(CommandLine&) = DoInstall;
    char* var_280 = dgettext("apt", "remove packages");
    void* const var_278 = "autoremove";
    int64_t (* const var_258)(CommandLine&) = DoInstall;
    char* var_268 = dgettext("apt", "Remove automatically all unused packages");
    void* const var_260 = "auto-remove";
    void* const var_248 = "autopurge";
    void* const var_230 = "purge";
    void* const var_218 = "update";
    int64_t (* const var_240)(CommandLine&) = DoInstall;
    int64_t (* const var_228)(CommandLine&) = DoInstall;
    int64_t var_250 = 0;
    int64_t var_238 = 0;
    int64_t var_220 = 0;
    int64_t (* const var_210)(CommandLine&) = DoUpdate;
    char* var_208 = dgettext("apt", "update list of available packages");
    void* const var_200 = "upgrade";
    int64_t (* const var_1f8)(CommandLine&) = DoUpgrade;
    char* var_1f0 = dgettext("apt", "upgrade the system by installing/upgrading packages");
    void* const var_1e8 = "full-upgrade";
    int64_t (* const var_1e0)(CommandLine&) = DoDistUpgrade;
    char* var_1d8 = dgettext("apt", "upgrade the system by removing/installing/upgrading packages");
    void* const var_1d0 = "edit-sources";
    int64_t (* const var_1c8)(CommandLine&) = EditSources;
    char* var_1c0 = dgettext("apt", "edit the source information file");
    void* const var_1b8 = &data_403322;
    int64_t var_1a8 = 0;
    int64_t (* const var_1b0)(CommandLine&) = DoMoo;
    void* const var_1a0 = "satisfy";
    int64_t (* const var_198)(CommandLine&) = DoBuildDep;
    int64_t (* const var_180)(CommandLine&) = DoDistUpgrade;
    char* var_190 = dgettext("apt", "satisfy dependency strings");
    void* const var_188 = "dist-upgrade";
    void* const var_170 = "showsrc";
    int64_t var_178 = 0;
    int64_t (* const var_168)(CommandLine&) = ShowSrcPackage;
    void* const var_158 = "depends";
    int64_t var_160 = 0;
    int64_t (* const var_150)(CommandLine&) = Depends;
    void* const var_140 = "rdepends";
    int64_t var_148 = 0;
    int64_t (* const var_138)(CommandLine&) = RDepends;
    void* const var_128 = "policy";
    int64_t var_130 = 0;
    int64_t (* const var_120)(CommandLine&) = Policy;
    void* const var_110 = "build-dep";
    void* const var_f8 = "clean";
    int64_t var_118 = 0;
    int64_t (* const var_f0)(CommandLine&) = DoClean;
    void* const var_e0 = "autoclean";
    int64_t (* const var_108)(CommandLine&) = DoBuildDep;
    int64_t (* const var_d8)(CommandLine&) = DoAutoClean;
    int64_t var_100 = 0;
    int64_t var_e8 = 0;
    int64_t var_d0 = 0;
    void* const var_c8 = "auto-clean";
    int64_t (* const var_c0)(CommandLine&) = DoAutoClean;
    void* const var_b0 = "source";
    __builtin_memset(arg1, 0, 0x18);
    int64_t (* const var_a8)(CommandLine&) = DoSource;
    void* const var_98 = "download";
    int64_t (* const var_90)(CommandLine&) = DoDownload;
    void* const var_80 = "changelog";
    int64_t (* const var_78)(CommandLine&) = DoChangelog;
    int64_t var_b8 = 0;
    int64_t var_a0 = 0;
    int64_t var_88 = 0;
    int64_t var_70 = 0;
    void* const var_68 = "info";
    int64_t (* const var_60)(CommandLine&) = ShowPackage;
    int64_t var_58;
    __builtin_memset(&var_58, 0, 0x20);
    void** rax_13 = operator new(0x2d0);
    void* const rcx = var_308;
    *arg1 = rax_13;
    void* rdi_1 = &rax_13[1] & 0xfffffffffffffff8;
    arg1[2] = &rax_13[0x5a];
    *rax_13 = rcx;
    int64_t var_40;
    rax_13[0x59] = var_40;
    void* rax_14 = rax_13 - rdi_1;
    __builtin_memcpy(rdi_1, &var_308 - rax_14, (rax_14 + 0x2d0) >> 3 << 3);
    arg1[1] = &rax_13[0x5a];
    *(fsbase + 0x28);
    
    if (rax == *(fsbase + 0x28))
        return arg1;
    
    __stack_chk_fail();
    /* no return */
}

void sub_402be9(struct _Unwind_Exception* arg1 @ rax) __noreturn
{
    int64_t* r12;
    /* tailcall */
    return sub_4022e0(arg1, r12);
}

int64_t _fini() __pure
{
    return;
}

