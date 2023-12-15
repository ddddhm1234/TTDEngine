#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include <tuple>
#include <list>

struct MemRecord {
    uint64_t pc;
    uint64_t target;
    uint64_t size;
    uint64_t type;
    uint8_t mem[8];
    uint64_t inst_index;
};

class MemoryModel {
public:
    using MemoryChangeCallback = void (*)(int block_index, uint64_t addr, uint64_t mem_index, void *user_data);

    struct MemBlock {
        uint64_t block_addr;
        uint8_t block_memory[4096];
        uint64_t len;
    };

    std::vector<MemBlock *> blocks;

    MemoryModel();
    MemoryModel(const MemoryModel &rhs);
    MemoryModel(MemoryModel &&rhs);
    MemoryModel &operator=(MemoryModel &&rhs);
    int get_block_by_addr(uint64_t addr);
    int get_insert_place(uint64_t addr);
    int put_byte(uint64_t addr, uint8_t byte);
    int put(uint64_t addr, uint8_t buf[8], uint64_t size);
    void apply(uint8_t *mem, uint64_t len);
    void apply_with_callback(uint8_t *mem, uint64_t len, MemoryChangeCallback callback, void *user_data);
    ~MemoryModel();
};

class MemoryView {
public:
    struct MemSearchResult {
        MemSearchResult(uint64_t mem_index, uint64_t addr) {
            this->mem_index = mem_index;
            this->addr = addr;
        }
        uint64_t mem_index;
        uint64_t addr;
    };

    std::vector<MemoryModel> mem_models;
    int unit;
    uint64_t len;
    uint8_t* mem;
    MemoryView(uint8_t *mem, uint64_t len);
    void cache(int unit=1000000);
    void search_mem(const void *pattern, uint64_t len, std::vector<MemSearchResult> &results);
    void get_memory_model_after(uint64_t mem_index, MemoryModel &mem_model);
    const MemRecord *get_mem_record(uint64_t index);
};

bool is_gb2312_string(const void *ptr, uint64_t buf_len, uint64_t &len); // the unit of len is uint8
bool is_unicode_string(const void *ptr, uint64_t buf_len, uint64_t &len); // the unit of len is uint16