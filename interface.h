#pragma once

#include "trace_analysis.h"
#include "trace_analysis_amd64.h"

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        uint64_t inst_index;
        uint64_t string_addr;
        char *buf;
        uint64_t buf_size;
        uint8_t type;
    } StringRef;

    typedef struct {
        uint64_t mem_addr;
        uint64_t mem_index;
    } MemResult;

    TraceAnalysis *get_amd64_ta(uint8_t *inst, uint64_t inst_len, uint8_t *mem, uint64_t mem_len, uint64_t cache_unit);

    void free_ta(TraceAnalysis *ta);

    TaintState *get_new_ts(TraceAnalysis *ta);

    void set_reg_tv(TraceAnalysis *ta, TaintState *ts, uint8_t regid, uint8_t tv);

    void set_addr_tv(TraceAnalysis *ta, TaintState *ts, uint64_t addr, uint8_t size, uint8_t tv);

    StringRef *list_strings(TraceAnalysis *ta, uint64_t &len, uint64_t min_len);

    void free_strings(StringRef *refs, uint64_t len);

    uint64_t *forward_taint(TraceAnalysis *ta, TaintState *ts, uint64_t begin_inst_index, uint64_t &len, uint64_t max_iter);

    void free_taint(uint64_t *buf);

    MemResult *search_mem(TraceAnalysis *ta, uint8_t *pattern, uint64_t pattern_len, uint64_t &len);

    void free_mem(MemResult *mr);

    uint64_t *search_context(TraceAnalysis *ta, uint64_t value, uint64_t &len);

    void free_context(uint64_t *cts);

    MemoryModel *get_memory_model_after(TraceAnalysis *ta, uint64_t mem_index);

    uint64_t get_memory_model_block_by_addr(MemoryModel *mdl, uint64_t addr);

    MemoryModel::MemBlock **get_memory_model_blocks(MemoryModel *mdl);

    uint64_t get_memory_model_blocks_len(MemoryModel *mdl);
#ifdef __cplusplus
}
#endif


