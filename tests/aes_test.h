#include "core/aes.h"

class AES128Test {
public:
    static void shift_row(unsigned char *msg) {
        AES128::shift_row(msg);
    }

    static void inv_shift_row(unsigned char *msg) {
        AES128::inv_shift_row(msg);
    }

    static void mix_column(unsigned char *msg) {
        AES128::mix_column(msg);
    }

    static void inv_mix_column(unsigned char *msg) {
        AES128::inv_mix_column(msg);
    }

    static const unsigned char *get_schedule(const AES128 &aes) {
        return aes.schedule_[0];
    }
};
