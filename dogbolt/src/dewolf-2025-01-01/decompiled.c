extern const unsigned char data_2078[0x38] = "\x1B\x5B\x31\x3B\x33\x32\x6D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D\x2D...";
extern const unsigned char data_201a[0x10] = "\x1B\x5B\x31\x3B\x33\x32\x6D\x25\x4C\x66\x1B\x5B\x30\x6D\x0A\x00";
extern int80_t askdo_input = 0;
extern int80_t result = 0;
extern int80_t memory = 0;
extern int80_t func_name = 0;
extern const unsigned int jump_table_2194[0xa] = {4294964447, 4294964108, 4294964140, 4294964172, 4294964204, 4294964236, 4294964292, 4294964348, 4294964404, 4294963964};



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



int main(int argc, char ** argv, char ** envp) {
    short var_0;
    askdo(var_0);
    return 0;
}



long askdo(short arg1) {
    double var_39;
    long double var_32;
    long double var_33;
    long double var_34;
    short var_31;
    int80_t var_35;
    system(/* line */ "clear");
    puts(/* str */ data_2078);
    __printf_chk(/* flag */ 2, /* format */ data_201a);
    __printf_chk(/* flag */ 2, /* format */ data_2078);
    puts(/* str */ "\\n0. Clear all\\n1. Addition\\n2. Subtraction\\n3. Multiplication\\n4. Division\\n5. sin (deg)\\n6. cos (deg)\\n7.tan (deg)\\n8...");
    __printf_chk(/* flag */ 2, /* format */ "Enter function option number/memory input num>9: ");
    __isoc99_scanf(/* format */ "%Lf", &askdo_input);
    var_33 = askdo_input;
    var_34 = (long double)0;
    if (var_33 == (long double)0) {
        var_33 = (long double)0;
    }
    else if (var_33 != (long double)0) {
        var_33 = var_34;
    }
    else {
        result = (long double)0;
        var_35 = result;
        memory = var_35;
        system(/* line */ "clear");
        askdo();
        var_33 = askdo_input;
    }
    if (var_33 >= 10.0) {
        result = 10.0;
        memory = 10.0;
        system(/* line */ "clear");
        askdo();
    }
    var_33 = memory;
    __printf_chk(/* flag */ 2, /* format */ "Enter performing number:");
    __isoc99_scanf(/* format */ "%Lf", &func_name);
    var_33 = askdo_input;
    arg1, var_31 = __fnstcw_memmem16(arg1);
    __fldcw_memmem16(arg1 & 0xff0000 | ((char)(arg1 >> 1) | 12) << 0x8);
    __fldcw_memmem16(arg1);
    switch((unsigned int) (int) var_33) {
    case 0x1:
        var_33 = memory;
        var_34 = func_name;
        var_33 += var_34;
        result = var_33;
        break;
    case 0x2:
        var_33 = memory;
        var_34 = func_name;
        var_33 -= var_34;
        result = var_33;
        break;
    case 0x3:
        var_33 = memory;
        var_34 = func_name;
        var_33 *= var_34;
        result = var_33;
        break;
    case 0x4:
        var_33 = memory;
        var_34 = func_name;
        var_33 /= var_34;
        result = var_33;
        break;
    case 0x5:
        var_33 = func_name;
        var_39 = sin(var_33 / 57.2957795);
        var_33 = (long double)var_39;
        result = (long double)var_39;
        break;
    case 0x6:
        var_33 = func_name;
        var_39 = cos(var_33 / 57.2957795);
        var_33 = (long double)var_39;
        result = (long double)var_39;
        break;
    case 0x7:
        var_33 = func_name;
        var_39 = tan(var_33 / 57.2957795);
        var_33 = (long double)var_39;
        result = (long double)var_39;
        break;
    case 0x8:
        __printf_chk(/* flag */ 2, /* format */ "Enter exponent value: ", jump_table_2194);
        __isoc99_scanf(/* format */ "%Lf", &var_32);
        var_33 = var_32;
    case 0x9:
        if ((unsigned int)(int)var_33 != 0x8) {
            __printf_chk(/* flag */ 2, /* format */ "Enter root cap value: ", jump_table_2194);
            __isoc99_scanf(/* format */ "%Lf", &var_32);
            var_33 = (long double)1 / var_32;
        }
        var_34 = func_name;
        var_39 = pow(/* x */ var_34, /* y */ var_33);
        var_33 = (long double)var_39;
        result = (long double)var_39;
        break;
    default:
        var_33 = result;
    }
    memory = var_33;
    system(/* line */ "clear");
    askdo();
    return 0L;
}



long repeat() {
    short var_2;
    int80_t var_4;
    var_4 = result;
    memory = var_4;
    system(/* line */ "clear");
    return askdo(var_2);
}
