extern char __bss_start = 0;
extern void * data_4008 = &data_4008;



long sub_1020() {/* jump -> undetermined */}



long sub_1030() {
    return sub_1020();
}



long sub_1040() {
    return sub_1020();
}



long sub_1050() {
    return sub_1020();
}



long sub_1060() {
    return sub_1020();
}



long sub_1070() {
    return sub_1020();
}



long sub_1080() {
    return sub_1020();
}



long sub_1090() {
    return sub_1020();
}



long sub_10a0() {
    return sub_1020();
}



long sub_10b0() {
    return sub_1020();
}



long sub_10c0() {
    return sub_1020();
}



long sub_10d0() {
    return sub_1020();
}



long sub_10e0() {
    return sub_1020();
}



long sub_10f0() {
    return sub_1020();
}



long sub_1100() {
    return sub_1020();
}



long sub_1110() {
    return sub_1020();
}



long sub_1120() {
    return sub_1020();
}



long sub_1130() {
    return sub_1020();
}



long sub_1140() {
    return sub_1020();
}



int main(int argc, char ** argv, char ** envp) {
    unsigned long var_12;
    long var_10;
    long var_11;
    long var_7;
    long var_9;
    void * var_8;
    var_10, var_9, var_12, var_11 = gedit_dirs_init();
    setlocale(/* category */ 6, /* locale */ "UTF-8", var_9, var_10, var_12, var_11, /* category */ (int)var_7, /* category */ (int)*(var_8 + 40L));
    bindtextdomain(/* domainname */ "org.gnome.gedit", /* dirname */ gedit_dirs_get_gedit_locale_dir());
    bind_textdomain_codeset(/* domainname */ "org.gnome.gedit", /* codeset */ "UTF-8");
    textdomain(/* domainname */ "org.gnome.gedit");
    var_9 = g_object_new(gedit_app_get_type(), "application-id", "org.gnome.gedit", "flags", 12L, 0L);
    var_7 = var_9;
    gedit_settings_unref_singleton();
    g_object_run_dispose(g_type_check_instance_cast(var_9, 80L));
    g_object_add_weak_pointer(g_type_check_instance_cast(var_9, 80L), &var_7);
    g_object_unref(var_7);
    if (var_7 != 0L) {
        var_8 = g_type_check_instance_cast(var_7, 80L);
        gedit_debug_message(256L, "../gedit/gedit.c", 161L, "main", "Leaking with %i refs", *(var_8 + 8L));
    }
    gedit_dirs_shutdown();
    return g_application_run(g_type_check_instance_cast(var_9, g_application_get_type()), (unsigned int)argc, argv);
}



void sub_1450() {
    return;
}



void _FINI_0() {
    void * var_2;
    if (__bss_start != 0) {
        return;
    }
    var_2 = data_4008;
    __cxa_finalize(/* d */ var_2);
    deregister_tm_clones();
    __bss_start = 1;
    return;
}



void _INIT_0() {
    return sub_1450();
}
