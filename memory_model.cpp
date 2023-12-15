#include "memory_model.h"
#include <algorithm>
#include <cstdint>
#include <time.h>
#include <iostream>
#include <vector>
#include <intrin.h>

MemoryModel::MemoryModel() {
    
}

int MemoryModel::get_block_by_addr(uint64_t addr) {
    int low = 0;
    int high = blocks.size() - 1;
    int mid;
    while (low <= high) {
        mid = (low + high) / 2;
        if (blocks[mid]->block_addr <= addr && blocks[mid]->block_addr + blocks[mid]->len > addr) {
            return mid;
        }
        else if (blocks[mid]->block_addr < addr) {
            low = mid + 1;
        }
        else {
            high = mid - 1;
        }
    }
    return -1;
}

int MemoryModel::get_insert_place(uint64_t addr) {
    int low = 0;
    int high = blocks.size() - 1;
    int mid;
    while (low <= high) {
        mid = (low + high) / 2;
        if (blocks[mid]->block_addr > addr) {
            if (mid == 0) {
                return 0;
            }
            else if (blocks[mid - 1]->block_addr < addr) {
                return mid;
            }
            else {
                high = mid - 1;
            }
        }
        else {
            if (mid == blocks.size() - 1) {
                return blocks.size();
            }
            else if (blocks[mid + 1]->block_addr > addr) {
                return mid + 1;
            }
            else {
                low = mid + 1;
            }
        }
    }
    return 0;
}

int MemoryModel::put_byte(uint64_t addr, uint8_t byte) {
    int i_block = get_block_by_addr(addr);
    if (i_block == -1) {
        i_block = get_insert_place(addr);
        
        bool left_merge = i_block == 0 ? false : blocks[i_block - 1]->block_addr + blocks[i_block - 1]->len == addr && blocks[i_block - 1]->len < 4096;
        bool right_merge = i_block >= blocks.size() ? false : blocks[i_block]->block_addr == addr + 1 && blocks[i_block]->len < 4096;
        if (left_merge && right_merge && blocks[i_block - 1]->len + blocks[i_block]->len < 4096) {
            auto left_block = blocks[i_block - 1];
            auto right_block = blocks[i_block];
            left_block->block_memory[left_block->len] = byte;
            left_block->len++;
            memcpy(&left_block->block_memory[left_block->len], right_block->block_memory, right_block->len);
            left_block->len += right_block->len;
            delete right_block;
            blocks.erase(blocks.begin() + i_block);
            return i_block - 1;
        }
        else if (left_merge) {
            auto left_block = blocks[i_block - 1];
            left_block->block_memory[left_block->len] = byte;
            left_block->len++;
            return i_block - 1;
        }
        else if (right_merge) {
            auto right_block = blocks[i_block];
            right_block->block_addr--;
            uint8_t buf[4096];
            memcpy(buf, right_block->block_memory, right_block->len);
            right_block->block_memory[0] = byte;
            memcpy(&right_block->block_memory[1], buf, right_block->len);
            right_block->len++;
            return i_block;
        }
        else {
            MemBlock *new_block = new MemBlock;
            new_block->block_addr = addr;
            new_block->block_memory[0] = byte;
            new_block->len = 1;
            blocks.insert(blocks.begin() + i_block, new_block);
            return i_block;
        }
    }
    else {
        blocks[i_block]->block_memory[addr - blocks[i_block]->block_addr] = byte;
        return i_block;
    }
}

int MemoryModel::put(uint64_t addr, uint8_t buf[8], uint64_t size) {
    for (uint64_t i = 0; i < size - 1; i++) {
        put_byte(addr + i, buf[i]);
    }
    return put_byte(addr + size - 1, buf[size - 1]);
}

void MemoryModel::apply(uint8_t *mem, uint64_t len) {
    MemRecord* records = reinterpret_cast<MemRecord *>(mem);
    for (uint64_t i = 0; i < len / sizeof(MemRecord); i++) {
        put(records[i].target, records[i].mem, records[i].size);
    }
}

void MemoryModel::apply_with_callback(uint8_t *mem, uint64_t len, MemoryChangeCallback callback, void *user_data) {
    MemRecord* records = reinterpret_cast<MemRecord *>(mem);
    int b;
    for (uint64_t i = 0; i < len / sizeof(MemRecord); i++) {
        b = put(records[i].target, records[i].mem, records[i].size);
        callback(b, records[i].target, i, user_data);
    }
}

MemoryModel::~MemoryModel() {
    for (auto iter = blocks.begin(); iter != blocks.end(); iter++) {
        delete *iter;
    }
}

MemoryModel::MemoryModel(const MemoryModel &rhs) {
    blocks.reserve(rhs.blocks.size());
    for (auto it = rhs.blocks.begin(); it != rhs.blocks.end(); it++) {
        MemBlock *m = new MemBlock;
        m->block_addr = (*it)->block_addr;
        m->len = (*it)->len;
        memcpy(m->block_memory, (*it)->block_memory, (*it)->len);
        blocks.push_back(m);
    }
}

MemoryModel::MemoryModel(MemoryModel &&rhs) {
    blocks = rhs.blocks;
    rhs.blocks.clear();
}

MemoryModel &MemoryModel::operator=(MemoryModel &&rhs) {
    blocks = rhs.blocks;
    rhs.blocks.clear();
    return *this;
}

// ###################################################################################################

MemoryView::MemoryView(uint8_t *mem, uint64_t len) {
    this->mem = mem;
    this->len = len;
}

void MemoryView::cache(int unit) {
    this->unit = unit;
    MemoryModel mm;
    uint64_t unit_len = unit * sizeof(MemRecord);
    mem_models.emplace_back();
    for (uint64_t i = 0; i < len; i += unit_len) {
        mm.apply(mem + i, std::min({unit_len, len - i}));
        mem_models.emplace_back(mm);
    }
}

void MemoryView::get_memory_model_after(uint64_t mem_index, MemoryModel &mem_model) {
    auto view_index = mem_index / this->unit;
    auto view_begin = view_index * this->unit * sizeof(MemRecord);
    MemoryModel m_model(mem_models[view_index]);
    m_model.apply(mem + view_begin, mem_index * sizeof(MemRecord) - view_begin);
    mem_model = std::move(m_model);
}

struct MemorySearchArgsPass {
    MemoryModel *mm;
    const MemRecord *mem_record;
    const uint8_t* pattern;
    uint64_t pattern_len;
    std::vector<MemoryView::MemSearchResult> &results;
};

static void search_mem_func(int block_index, uint64_t addr, uint64_t mem_index, void *user_data) {
    static uint8_t temp_buf[4096 * 10];
    auto *args = reinterpret_cast<MemorySearchArgsPass *>(user_data);
    int block_begin;
    uint64_t addr_begin;

    if (block_index >= 1 && args->mm->blocks[block_index - 1]->block_addr + args->mm->blocks[block_index - 1]->len == args->mm->blocks[block_index]->block_addr
    && addr - args->pattern_len < args->mm->blocks[block_index]->block_addr) {
        block_begin = block_index - 1;
    }
    else {
        block_begin = block_index;
    }
    
    addr_begin = std::max({args->mm->blocks[block_begin]->block_addr, addr - args->pattern_len + 1});

    uint64_t addr_end;
    int block_end;
    if (block_index + 1 >= args->mm->blocks.size() || args->mm->blocks[block_index]->block_addr + args->mm->blocks[block_index]->len != args->mm->blocks[block_index + 1]->block_addr) {
        // this block is not full or this block is the last block
        block_end = block_index;
        addr_end = std::min({addr + args->mem_record[mem_index].size + args->pattern_len, args->mm->blocks[block_index]->block_addr + args->mm->blocks[block_index]->len});
    }
    else {
        if (addr + args->mem_record[mem_index].size + args->pattern_len > args->mm->blocks[block_index]->block_addr + args->mm->blocks[block_index]->len) {
            block_end = block_index + 1;
            addr_end = std::min({addr + args->mem_record[mem_index].size + args->pattern_len, args->mm->blocks[block_end]->block_addr + args->mm->blocks[block_end]->len});
        }
        else {
            block_end = block_index;
            addr_end = std::min({addr + args->mem_record[mem_index].size + args->pattern_len, args->mm->blocks[block_end]->block_addr + args->mm->blocks[block_end]->len});
        }
    }
    
    if (addr_end - addr_begin < args->pattern_len) {
        return;
    }

    if (block_begin == block_index) {
        for (uint64_t i = addr_begin - args->mm->blocks[block_index]->block_addr; i < addr_end - args->mm->blocks[block_index]->block_addr - args->pattern_len; i++) {
            if (!memcmp(args->mm->blocks[block_begin]->block_memory + i, args->pattern, args->pattern_len)) {
                args->results.emplace_back(mem_index, args->mm->blocks[block_index]->block_addr + i);
            }
        }
    }
    else {
        uint64_t off = args->mm->blocks[block_begin]->len - (addr_begin - args->mm->blocks[block_begin]->block_addr);
        memcpy(temp_buf, args->mm->blocks[block_begin]->block_memory + (addr_begin - args->mm->blocks[block_begin]->block_addr), off);
        for (int i = block_begin + 1; i < block_end; i++) {
            memcpy(temp_buf + off, args->mm->blocks[i]->block_memory, args->mm->blocks[i]->len);
            off += args->mm->blocks[i]->len;
        }
        memcpy(temp_buf + off, args->mm->blocks[block_end]->block_memory, addr_end - args->mm->blocks[block_end]->block_addr);
        off += addr_end - args->mm->blocks[block_end]->block_addr;
        // _ASSERT(off == addr_end - addr_begin);
        if (off < args->pattern_len) {
            return;
        }
        for (uint64_t i = 0; i <= off - args->pattern_len; i++) {
            if (!memcmp(temp_buf + i, args->pattern, args->pattern_len)) {
                args->results.emplace_back(mem_index, addr_begin + i);
            }
        }
    }
}

void MemoryView::search_mem(const void *pattern, uint64_t len, std::vector<MemSearchResult> &results) {
    MemoryModel mm;
    MemorySearchArgsPass sap = {&mm, reinterpret_cast<MemRecord *>(mem), reinterpret_cast<const uint8_t *>(pattern), len, results};
    mm.apply_with_callback(mem, this->len, search_mem_func, &sap);
}

const MemRecord *MemoryView::get_mem_record(uint64_t index) {
    return reinterpret_cast<const MemRecord *>(mem + index * sizeof(MemRecord));
}

bool is_gb2312_string(const void *ptr, uint64_t buf_len, uint64_t &len) {
    const uint8_t *buf = reinterpret_cast<const uint8_t *>(ptr);
    len = 0;
    for (uint64_t i = 0; i < buf_len; i++) {
        if (buf[i] == 0) {
            return true;
        }
        else if (buf[i] >= 32 && buf[i] <= 127) {
            // ascii printable char
            len++;
            continue;
        }
        else {
            if (i + 1 >= buf_len) {
                return false;
            }
            // gb2312 chinese char range
            else if (buf[i] >= 0xa1 && buf[i] <= 0xfe && buf[i + 1] >= 0xb0 && buf[i + 1] <= 0xfe) {
                i++;
                len += 2;
                continue;
            }
            else {
                return false;
            }
        }
    }
    return true;
}

bool is_unicode_string(const void *ptr, uint64_t buf_len, uint64_t &len) {
    const uint16_t *buf = reinterpret_cast<const uint16_t *>(ptr);
    len = 0;
    for (uint64_t i = 0; i < buf_len; i += 2) {
        uint16_t b = _rotl16(buf[i], 8);
        if (b == 0) {
            return true;
        }
        // english char and chinese char range
        else if ((b >= 32 && b <= 127) || (b >= 0x4E00 && b <= 0x62FF)) {
            len += 2;
            continue;
        }
        else {
            return false;
        }
    }
    return true;
}