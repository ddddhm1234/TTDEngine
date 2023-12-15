#include "interface.h"
extern "C" {
    TraceAnalysis *get_amd64_ta(uint8_t *inst, uint64_t inst_len, uint8_t *mem, uint64_t mem_len, uint64_t cache_unit=1000000) {
        return new TraceAnalysisAMD64(inst, inst_len, mem, mem_len, cache_unit);
    }

    void free_ta(TraceAnalysis *ta) {
        delete ta;
    }

    TaintState *get_new_ts(TraceAnalysis *ta) {
        return new TaintState();
    }

    void set_reg_tv(TraceAnalysis *ta, TaintState *ts, uint8_t regid, uint8_t tv) {
        ta->set_reg_tv(*ts, regid, TaintValue(tv));
    }

    void set_addr_tv(TraceAnalysis *ta, TaintState *ts, uint64_t addr, uint8_t size, uint8_t tv) {
        ta->set_addr_tv(*ts, addr, size, TaintValue(tv));
    }

    StringRef *list_strings(TraceAnalysis *ta, uint64_t &len, uint64_t min_len=5) {
        std::vector<TraceAnalysis::StringRefResult> r;
        ta->list_string_xrefs(r, min_len);
        StringRef *refs = new StringRef[r.size()];
        for (uint64_t i = 0; i < r.size(); i++) {
            refs[i].string_addr = r[i].string_addr;
            refs[i].type = r[i].type;
            refs[i].inst_index = r[i].inst_index;
            refs[i].buf = new char[r[i].str.size()];
            refs[i].buf_size = r[i].str.size();
            memcpy(refs[i].buf, r[i].str.c_str(), refs[i].buf_size);
        }
        len = r.size();
        return refs;
    }

    void free_strings(StringRef *refs, uint64_t len) {
        for (uint64_t i = 0; i < len; i++) {
            delete refs[i].buf;
        }
        delete[] refs;
    }

    uint64_t *forward_taint(TraceAnalysis *ta, TaintState *ts, uint64_t begin_inst_index, uint64_t &len, uint64_t max_iter=0) {
        std::vector<uint64_t> r;
        ta->forward_taint(begin_inst_index, *ts, r, max_iter);
        uint64_t *result = new uint64_t[r.size()];
        memcpy(result, r.data(), r.size() * sizeof(uint64_t));
        len = r.size();
        return result;
    }

    void free_taint(uint64_t *buf) {
        delete[] buf;
    }

    MemResult *search_mem(TraceAnalysis *ta, uint8_t *pattern, uint64_t pattern_len, uint64_t &len) {
        std::vector<MemoryView::MemSearchResult> r;
        ta->mem_view.search_mem(pattern, pattern_len, r);
        MemResult *result = new MemResult[r.size()];
        for (uint64_t i = 0; i < r.size(); i++) {
            result[i].mem_addr = r[i].addr;
            result[i].mem_index = r[i].mem_index;
        }
        len = r.size();
        return result;
    }

    void free_mem(MemResult *mr) {
        delete[] mr;
    }

    uint64_t *search_context(TraceAnalysis *ta, uint64_t value, uint64_t &len) {
        std::vector<uint64_t> r;
        ta->search_context(value, r);
        len = r.size();
        uint64_t *result = new uint64_t[r.size()];
        memcpy(result, r.data(), sizeof(uint64_t) * len);
        return result;
    }

    void free_context(uint64_t *cts) {
        delete[] cts;
    }

    MemoryModel *get_memory_model_after(TraceAnalysis *ta, uint64_t mem_index) {
        MemoryModel *mem = new MemoryModel();
        ta->mem_view.get_memory_model_after(mem_index, *mem);
        return mem;
    }

    uint64_t get_memory_model_block_by_addr(MemoryModel *mdl, uint64_t addr) {
        return mdl->get_block_by_addr(addr);
    }

    MemoryModel::MemBlock **get_memory_model_blocks(MemoryModel *mdl) {
        auto it = mdl->blocks.data();
        return it;
    }

    uint64_t get_memory_model_blocks_len(MemoryModel *mdl) {
        return mdl->blocks.size();
    }

}