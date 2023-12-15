#include "trace_analysis.h"


static void set_reg_tv(x86_reg csreg, TaintState &ts, const TaintValue &tv) {
    ts[csreg] = tv;
}
