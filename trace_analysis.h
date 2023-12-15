#pragma once

#include <cstdint>
#include <unordered_map>
#include <bitset>
#include <string>

extern "C" {
    #include <capstone/capstone.h>
}
#include "memory_model.h"


typedef std::bitset<8> TaintValue;
typedef std::unordered_map<uint64_t, std::bitset<8>> TaintState;

class TraceAnalysis {
public:
    struct StringRefResult {
        StringRefResult(uint64_t inst_index, uint64_t string_addr, uint8_t type, void *buf, uint64_t len) : str(reinterpret_cast<char *>(buf), len) {
            this->inst_index = inst_index;
            this->string_addr = string_addr;
            this->type = type;
        }
        StringRefResult(uint64_t inst_index, uint64_t string_addr, uint8_t type, std::string &&s) : str(s) {
            this->inst_index = inst_index;
            this->string_addr = string_addr;
            this->type = type;
        }
        uint64_t inst_index;
        uint64_t string_addr;
        std::string str;
        uint8_t type; // 1 - gb2312, 2 - unicode
    };

    uint8_t *inst;
    uint64_t inst_len;
    uint8_t *mem;
    uint64_t mem_len;
    csh csh;
    MemoryView mem_view;

    TraceAnalysis(uint8_t *inst, uint64_t inst_len, uint8_t *mem, uint64_t mem_len, uint64_t cache_unit=1000000);

    virtual cs_insn *disasm(uint64_t inst_index) = 0;
    virtual void list_string_xrefs(std::vector<StringRefResult> &results, uint64_t min_str_len = 5) = 0;
    virtual void forward_taint(uint64_t inst_index, TaintState init_ts, std::vector<uint64_t> &result, uint64_t max_iter = 0) = 0;
    virtual TaintState get_new_ts() {
        return TaintState();
    }
    virtual void set_reg_tv(TaintState &ts, uint8_t regid, TaintValue tv) = 0;
    virtual void set_addr_tv(TaintState &ts, uint64_t addr, uint8_t size, TaintValue tv) = 0;
    virtual void search_context(uint64_t value, std::vector<uint64_t> &inst_index) = 0;
    ~TraceAnalysis();
};