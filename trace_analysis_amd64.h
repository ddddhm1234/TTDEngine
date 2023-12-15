#pragma once

#include "trace_analysis.h"


class TraceAnalysisAMD64 : public TraceAnalysis {
public:
    struct InstRecord {
        uint64_t rax;
        uint64_t rbx;
        uint64_t rcx;
        uint64_t rdx;
        uint64_t rdi;
        uint64_t rsi;
        uint64_t rbp;
        uint64_t rsp;
        uint64_t rip;
        uint64_t r8;
        uint64_t r9;
        uint64_t r10;
        uint64_t r11;
        uint64_t r12;
        uint64_t r13;
        uint64_t r14;
        uint64_t r15;
        uint8_t opcodes[16];
    };

    TraceAnalysisAMD64(uint8_t *inst, uint64_t inst_len, uint8_t *mem, uint64_t mem_len, uint64_t cache_unit=1000000);

    virtual void list_string_xrefs(std::vector<StringRefResult> &results, uint64_t min_str_len = 5);
    virtual cs_insn *disasm(uint64_t inst_index);
    virtual void search_context(uint64_t value, std::vector<uint64_t> &inst_index);
    virtual void forward_taint(uint64_t inst_index, TaintState init_ts, std::vector<uint64_t> &result, uint64_t max_iter = 0);
    virtual void set_reg_tv(TaintState &ts, uint8_t regid, TaintValue tv);
    virtual void set_addr_tv(TaintState &ts, uint64_t addr, uint8_t size, TaintValue tv);
    static size_t csreg2off(x86_reg reg);
};