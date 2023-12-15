#include "trace_analysis_amd64.h"
#include "capstone/x86.h"
#include <stdexcept>
#include <tuple>

TraceAnalysisAMD64::TraceAnalysisAMD64(uint8_t *inst, uint64_t inst_len, uint8_t *mem, uint64_t mem_len, uint64_t cache_unit)
: TraceAnalysis(inst, inst_len, mem, mem_len, cache_unit) {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &csh) != CS_ERR_OK) {
        throw std::exception("Can not initialize capstone engine");
    }
    cs_option(csh, CS_OPT_DETAIL, CS_OPT_ON);
}

cs_insn *TraceAnalysisAMD64::disasm(uint64_t inst_index) {
    cs_insn *insn;
    InstRecord *trace_ins = reinterpret_cast<InstRecord *>(inst) + inst_index;
    cs_disasm(csh, trace_ins->opcodes, 15, trace_ins->rip, 1, &insn);
    return insn;
} 

size_t TraceAnalysisAMD64::csreg2off(x86_reg reg) {
    switch (reg)
    {
    case X86_REG_RAX:
        return offsetof(TraceAnalysisAMD64::InstRecord, rax);
        break;
    case X86_REG_RBX:
        return offsetof(TraceAnalysisAMD64::InstRecord, rbx);
        break;
    case X86_REG_RCX:
        return offsetof(TraceAnalysisAMD64::InstRecord, rcx);
        break;
    case X86_REG_RDX:
        return offsetof(TraceAnalysisAMD64::InstRecord, rdx);
        break;
    case X86_REG_RDI:
        return offsetof(TraceAnalysisAMD64::InstRecord, rdi);
        break;
    case X86_REG_RSI:
        return offsetof(TraceAnalysisAMD64::InstRecord, rsi);
        break;
    case X86_REG_RBP:
        return offsetof(TraceAnalysisAMD64::InstRecord, rbp);
        break;
    case X86_REG_RSP:
        return offsetof(TraceAnalysisAMD64::InstRecord, rsp);
        break;
    case X86_REG_RIP:
        return offsetof(TraceAnalysisAMD64::InstRecord, rip);
        break;
    case X86_REG_R8:
        return offsetof(TraceAnalysisAMD64::InstRecord, r8);
        break;
    case X86_REG_R9:
        return offsetof(TraceAnalysisAMD64::InstRecord, r9);
        break;
    case X86_REG_R10:
        return offsetof(TraceAnalysisAMD64::InstRecord, r10);
        break;
    case X86_REG_R11:
        return offsetof(TraceAnalysisAMD64::InstRecord, r11);
        break;
    case X86_REG_R12:
        return offsetof(TraceAnalysisAMD64::InstRecord, r12);
        break;
    case X86_REG_R13:
        return offsetof(TraceAnalysisAMD64::InstRecord, r13);
        break;
    case X86_REG_R14:
        return offsetof(TraceAnalysisAMD64::InstRecord, r14);
        break;
    case X86_REG_R15:
        return offsetof(TraceAnalysisAMD64::InstRecord, r15);
        break;
    default:
        return sizeof(TraceAnalysisAMD64::InstRecord);
    }
}

struct ListStringArgsParse {
    TraceAnalysisAMD64 *ta;
    MemoryModel &mem;
    std::vector<TraceAnalysis::StringRefResult> &results;
    uint64_t min_len;
};

void read_strings(uint8_t *start, uint64_t len, uint64_t addr, uint64_t min_len, uint64_t inst_index, std::vector<TraceAnalysis::StringRefResult> &results,
uint8_t *next_block, uint64_t next_block_len) {
    uint64_t gb2312_len = 0;
    uint64_t unicode_len = 0;
    static char tmp_buf[10000];
    if (next_block == nullptr) {
        if (is_gb2312_string(start, len, gb2312_len) && gb2312_len >= min_len) {
            results.emplace_back(inst_index, addr, 1, start, gb2312_len);
            return;
        }
        if (is_unicode_string(start, len, unicode_len) && unicode_len >= min_len) {
            results.emplace_back(inst_index, addr, 2, start, unicode_len * 2);
        }
    }
    else {
        if (is_gb2312_string(start, len, gb2312_len)) {
            if (gb2312_len == len) {
                uint64_t second_len;
                if (is_gb2312_string(next_block, next_block_len, second_len) && gb2312_len + second_len >= min_len) {
                    memcpy(tmp_buf, start, gb2312_len);
                    memcpy(tmp_buf + gb2312_len, next_block, second_len);
                    results.emplace_back(inst_index, addr, 1, tmp_buf, gb2312_len + second_len);
                    return;
                }
            }
            else if (gb2312_len - len == 1) {
                if (start[gb2312_len] >= 0xa1 && start[gb2312_len] <= 0xfe && next_block[0] >= 0xb0 && next_block[0] <= 0xfe) {
                    uint64_t second_len;
                    if (is_gb2312_string(next_block + 1, next_block_len - 1, second_len) && second_len + gb2312_len + 1 >= min_len) {
                        memcpy(tmp_buf, start, len);
                        tmp_buf[len] = next_block[0];
                        memcpy(tmp_buf + len + 1, next_block + 1, second_len);
                        results.emplace_back(inst_index, addr, 1, tmp_buf, gb2312_len + second_len + 2);
                        return;
                    }
                }
            }
            else {
                results.emplace_back(inst_index, addr, 1, start, gb2312_len);
                return;
            }
        }
        if (is_unicode_string(start, len, unicode_len)) {
            if (unicode_len == len) {
                uint64_t second_len;
                if (is_unicode_string(next_block, next_block_len, second_len)) {
                    memcpy(tmp_buf, start, unicode_len);
                    memcpy(tmp_buf + unicode_len, next_block, second_len);
                    results.emplace_back(inst_index, addr, 2, tmp_buf, gb2312_len + second_len);
                    return;
                }
            }
            else if (len - unicode_len <= 2) {
                results.emplace_back(inst_index, addr, 2, start, unicode_len);
                return;
            }
            else {
                if (start[unicode_len] == 0 && next_block[0] == 0) {
                    results.emplace_back(inst_index, addr, 2, start, unicode_len);
                    return;
                }
                else if ((start[unicode_len] >= 32 && start[unicode_len] <= 127 && next_block[0] == 0) || 
                (start[unicode_len] >= 0x4E && start[unicode_len] <= 0x62)) {
                    uint64_t second_len;
                    if (is_unicode_string(next_block + 1, next_block_len - 1, second_len) && unicode_len + second_len + 1 >= min_len) {
                        memcpy(tmp_buf, start, len);
                        tmp_buf[len] = next_block[0];
                        memcpy(tmp_buf + len + 1, next_block + 1, second_len);
                        results.emplace_back(inst_index, addr, 2, tmp_buf, unicode_len + second_len + 2);
                        return;
                    }
                }
            }
        }
    }
}

static void is_string(int block_index, uint64_t addr, uint64_t mem_index, void *user_data) { 
    auto args = reinterpret_cast<ListStringArgsParse *>(user_data);
    const MemRecord *mmr = reinterpret_cast<const MemRecord *>(args->ta->mem + mem_index * sizeof(MemRecord));
    const uint64_t inst_end = mmr->inst_index;
    const uint64_t inst_begin = mem_index == 0 ? 0 : (mmr - 1)->inst_index;

    const TraceAnalysisAMD64::InstRecord *inst_record = reinterpret_cast<TraceAnalysisAMD64::InstRecord *>(args->ta->inst + sizeof(TraceAnalysisAMD64::InstRecord) * inst_begin);
    
    size_t reg_off;
    for (uint64_t inst = inst_begin; inst < inst_end; inst++) {
        auto dis = args->ta->disasm(inst);
        for (uint8_t op_index = 0; op_index < dis->detail->x86.op_count; op_index++) {
            const cs_x86_op *op = &dis->detail->x86.operands[op_index];
            switch (op->type) {
            case X86_OP_MEM:
                if (op->mem.segment == X86_REG_FS || op->mem.segment == X86_REG_GS) {
                    break;
                }

                reg_off = args->ta->csreg2off(op->mem.base);
                uint64_t base;
                base = 0;
                if (reg_off < sizeof(TraceAnalysisAMD64::InstRecord)) {
                    base = *reinterpret_cast<const uint64_t *>(reinterpret_cast<const uint8_t *>(inst_record) + reg_off);
                }

                reg_off = args->ta->csreg2off(op->mem.index);
                uint64_t index;
                index = 0;
                if (reg_off < sizeof(TraceAnalysisAMD64::InstRecord)) {
                    index = *reinterpret_cast<const uint64_t *>(reinterpret_cast<const uint8_t *>(inst_record) + reg_off);
                }

                uint64_t target_addr;
                target_addr = base + (index * op->mem.scale) + op->mem.disp;
                
                int block_index;
                block_index = args->mem.get_block_by_addr(target_addr);
                if (block_index == -1) {
                    break;
                }
                uint64_t off;
                off = target_addr - args->mem.blocks[block_index]->block_addr;
                if (block_index + 1 < args->mem.blocks.size() && 
                    args->mem.blocks[block_index]->block_addr + args->mem.blocks[block_index]->len == args->mem.blocks[block_index + 1]->block_addr) {
                    
                    read_strings(args->mem.blocks[block_index]->block_memory + off, args->mem.blocks[block_index]->len - off, 
                        target_addr, args->min_len, inst, args->results, args->mem.blocks[block_index + 1]->block_memory, args->mem.blocks[block_index + 1]->len);
                }
                else {
                    read_strings(args->mem.blocks[block_index]->block_memory + off, args->mem.blocks[block_index]->len - off, 
                        target_addr, args->min_len, inst, args->results, nullptr, 0);
                }
                
                break;
            case X86_OP_REG:
                if (op->access & CS_AC_READ) {
                    // read this reg
                    reg_off = args->ta->csreg2off(op->reg);
                    if (reg_off < sizeof(TraceAnalysisAMD64::InstRecord)) {
                        target_addr = *reinterpret_cast<const uint64_t *>(reinterpret_cast<const uint8_t *>(inst_record) + reg_off);;
                        block_index = args->mem.get_block_by_addr(target_addr);
                        if (block_index == -1) {
                            break;
                        }
                        uint64_t off = target_addr - args->mem.blocks[block_index]->block_addr;
                        if (block_index + 1 < args->mem.blocks.size() && 
                            args->mem.blocks[block_index]->block_addr + args->mem.blocks[block_index]->len == args->mem.blocks[block_index + 1]->block_addr) {
                            
                            read_strings(args->mem.blocks[block_index]->block_memory + off, args->mem.blocks[block_index]->len - off, 
                                target_addr, args->min_len, inst, args->results, args->mem.blocks[block_index + 1]->block_memory, args->mem.blocks[block_index + 1]->len);
                        }
                        else {
                            read_strings(args->mem.blocks[block_index]->block_memory + off, args->mem.blocks[block_index]->len - off, 
                                target_addr, args->min_len, inst, args->results, nullptr, 0);
                        }
                    }
                }
                if (op->access & CS_AC_WRITE) {
                    // write this reg
                    reg_off = args->ta->csreg2off(op->reg);
                    if (reg_off < sizeof(TraceAnalysisAMD64::InstRecord)) {
                        target_addr = *reinterpret_cast<const uint64_t *>(reinterpret_cast<const uint8_t *>(inst_record + 1) + reg_off);;
                        block_index = args->mem.get_block_by_addr(target_addr);
                        if (block_index == -1) {
                            break;
                        }
                        uint64_t off = target_addr - args->mem.blocks[block_index]->block_addr;
                        if (block_index + 1 < args->mem.blocks.size() && 
                            args->mem.blocks[block_index]->block_addr + args->mem.blocks[block_index]->len == args->mem.blocks[block_index + 1]->block_addr) {
                            
                            read_strings(args->mem.blocks[block_index]->block_memory + off, args->mem.blocks[block_index]->len - off, 
                                target_addr, args->min_len, inst, args->results, args->mem.blocks[block_index + 1]->block_memory, args->mem.blocks[block_index + 1]->len);
                        }
                        else {
                            read_strings(args->mem.blocks[block_index]->block_memory + off, args->mem.blocks[block_index]->len - off, 
                                target_addr, args->min_len, inst, args->results, nullptr, 0);
                        }
                    }
                }
                break;
            case X86_OP_IMM:
                continue;
                break;
            }
        }
        inst_record++;
        cs_free(dis, 1);
    }
}

void TraceAnalysisAMD64::list_string_xrefs(std::vector<StringRefResult> &results, uint64_t min_str_len) {
    MemoryModel mem_model;
    ListStringArgsParse args = {this, mem_model, results, min_str_len};
    mem_model.apply_with_callback(mem, mem_len, is_string, &args);
}

void TraceAnalysisAMD64::search_context(uint64_t value, std::vector<uint64_t> &inst_index) {
    const InstRecord *instr = reinterpret_cast<const InstRecord *>(inst);
    const uint64_t o1 = offsetof(InstRecord, rax);
    const uint64_t o2 = offsetof(InstRecord, r15);
    for (uint64_t i = 0; i < inst_len / sizeof(InstRecord); i++, instr++) {
        const uint64_t *regs = reinterpret_cast<const uint64_t *>(instr);
        for (uint64_t i = o1 / 8; i <= o2 / 8; i++) {
            if (regs[i] == value) {
                inst_index.push_back(i);
            }
        }
    }
}