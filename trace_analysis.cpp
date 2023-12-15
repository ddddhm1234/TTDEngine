#include "trace_analysis.h"

TraceAnalysis::TraceAnalysis(uint8_t *inst, uint64_t inst_len, uint8_t *mem, uint64_t mem_len, uint64_t cache_unit) : mem_view(mem, mem_len) {
    this->inst = inst;
    this->inst_len = inst_len;
    this->mem = mem;
    this->mem_len = mem_len;
    mem_view.cache(cache_unit);
}

TraceAnalysis::~TraceAnalysis() {
    
    cs_close(&csh);
}

