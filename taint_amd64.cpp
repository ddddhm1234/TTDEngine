#include "taint_amd64.h"
#include "trace_analysis_amd64.h"
#include <cmath>
#include <cinttypes>
#include <cstdint>

static int csreg2regindex[256];
static int csreg2rangebegin[256];
static int csreg2rangeend[256];

static void setup();

constexpr uint8_t get_mask(uint8_t size) {
    return (1 << size) - 1;
}

static TaintValue mask_table[9] = {TaintValue(get_mask(0)), TaintValue(get_mask(1)), TaintValue(get_mask(2)), 
TaintValue(get_mask(3)), TaintValue(get_mask(4)), TaintValue(get_mask(5)), TaintValue(get_mask(6)),
TaintValue(get_mask(7)), TaintValue(get_mask(8))};


static uint64_t get_mem_op_addr(const cs_x86_op &op, const TraceAnalysisAMD64::InstRecord *inst) {
    const uint64_t *inst_p = reinterpret_cast<const uint64_t *>(inst);
    _ASSERT(op.type == X86_OP_MEM);
    uint64_t base = 0;
    uint64_t index = 0;
    uint64_t off;
    off = TraceAnalysisAMD64::csreg2off(op.mem.base);
    if (off < sizeof(TraceAnalysisAMD64::InstRecord)) {
        base = inst_p[off / 8];
    }
    off = TraceAnalysisAMD64::csreg2off(op.mem.index);
    if (off < sizeof(TraceAnalysisAMD64::InstRecord)) {
        index = inst_p[off / 8];
    }
    return base + (index * op.mem.scale) + op.mem.disp;
}

static TaintValue get_reg_tv(x86_reg csreg, const TaintState &ts) {
    if (csreg2regindex[csreg] == -1) {
        return 0;
    }
    auto it = ts.find(csreg2regindex[csreg]);
    if (it == ts.end()) {
        return 0;
    }
    auto mask = mask_table[csreg2rangeend[csreg] - csreg2rangebegin[csreg]] << csreg2rangebegin[csreg];
    return (it->second & mask) >> csreg2rangebegin[csreg];
}

static void set_reg_tv(x86_reg csreg, TaintState &ts, const TaintValue &tv) {
    if (csreg2regindex[csreg] == -1) {
        return;
    }
    auto it = ts.find(csreg2regindex[csreg]);
    if (it == ts.end()) {
        ts.insert(std::make_pair(csreg, TaintValue(0)));
        it = ts.find(csreg);
    }
    auto begin = csreg2rangebegin[csreg];
    auto end = csreg2rangeend[csreg];
    for (uint8_t i = 0; i < end - begin; i++) {
        it->second[i + begin] = tv[i];
    }
}

static TaintValue get_addr_tv(uint64_t addr, uint8_t size, const TaintState &ts) {
    if (size > 8) {
        return TaintValue(0);
    } 

    auto aligned_addr1 = addr & 0b1111111111111111111111111111111111111111111111111111111111111000;
    auto aligned_addr2 = (addr + size - 1) & 0b1111111111111111111111111111111111111111111111111111111111111000;
    TaintValue rs(0);

    if (aligned_addr2 == aligned_addr1) {
        auto it = ts.find(aligned_addr1);
        if (it == ts.end()) {
            return 0;
        }
        auto off = addr - aligned_addr1;
        for (uint8_t i = 0; i < size; i++) {
            rs[i] = it->second[i + off];
        }
    }
    else {
        auto it1 = ts.find(aligned_addr1);
        auto it2 = ts.find(aligned_addr2);
        auto size2 = addr + size - aligned_addr2;
        auto size1 = aligned_addr2 - addr;
        auto off1 = 8 - size1;
        if (it1 != ts.end()) {
            for (uint8_t i = 0; i < size1; i++) {
                rs[i] = it1->second[i + off1];
            }
        }
        if (it2 != ts.end()) {
            for (uint8_t i = 0; i < size2; i++) {
                rs[i + size1] = it2->second[i];
            }
        }
    }
    return rs;
}

static void set_addr_tv(uint64_t addr, uint8_t size, TaintState &ts, const TaintValue &tv) {
    if (size > 8) {
        return;
    }

    auto aligned_addr1 = addr & 0b1111111111111111111111111111111111111111111111111111111111111000;
    auto aligned_addr2 = (addr + size - 1) & 0b1111111111111111111111111111111111111111111111111111111111111000;

    if (aligned_addr1 == aligned_addr2) {
        auto off = addr - aligned_addr1;
        auto it = ts.find(aligned_addr1);
        if (it == ts.end()) {
            ts[aligned_addr1] = TaintValue(0);
            it = ts.find(aligned_addr1);
        }

        for (uint8_t i = 0; i < size; i++) {
            it->second[i + off] = tv[i];
        }
    }
    else {
        auto it1 = ts.find(aligned_addr1);
        auto it2 = ts.find(aligned_addr2);
        if (it1 == ts.end()) {
            ts[aligned_addr1] = TaintValue(0);
            it1 = ts.find(aligned_addr1);
        }
        if (it2 == ts.end()) {
            ts[aligned_addr2] = TaintValue(0);
            it2 = ts.find(aligned_addr2);
        }
        auto size2 = addr + size - aligned_addr2;
        auto size1 = aligned_addr2 - addr;
        auto off1 = 8 - size1;
        for (uint8_t i = 0; i < size1; i++) {
            it1->second[i + off1] = tv[i];
        }
        for (uint8_t i = 0; i < size2; i++) {
            it2->second[i] = tv[i + size1];
        }
    }
}

static TaintValue get_op_tv(const cs_x86_op &op, const TaintState &ts, const TraceAnalysisAMD64::InstRecord *inst) {
    switch (op.type) {
    case X86_OP_IMM:
        return TaintValue(0);
        break;
    
    case X86_OP_REG:
        return get_reg_tv(op.reg, ts);
        break;
    
    case X86_OP_MEM:
        return get_addr_tv(get_mem_op_addr(op, inst), op.size, ts);
    
    default:
        _ASSERT(false);
        return 0;
    }

}

static void set_op_tv(const cs_x86_op &op, TaintState &ts, const TraceAnalysisAMD64::InstRecord *inst, const TaintValue &tv) {
    switch (op.type) {
    case X86_OP_REG:
        set_reg_tv(op.reg, ts, tv);
        if (tv.none() && csreg2regindex[op.reg] != -1) {
            ts.erase(csreg2regindex[op.reg]);
        }
        break;
    case X86_OP_MEM:
        uint64_t addr;
        addr = get_mem_op_addr(op, inst);
        set_addr_tv(addr, op.size, ts, tv);
        if (tv.none()) {
            ts.erase(addr);
        }
        break;
    default:
        break;
    }
}

// return true, means this instruction is tained
static bool union_taint_op(const TraceAnalysisAMD64::InstRecord *inst, TaintState &ts, const cs_x86_op &op1, const cs_x86_op &op2, const cs_x86_op &out) {
    TaintValue tv1 = get_op_tv(op1, ts, inst), tv2 = get_op_tv(op2, ts, inst);
    TaintValue tv = tv1 | tv2;
    set_op_tv(out, ts, inst, tv);
    return tv.any();
}

// return true, means this instruction is tained
static bool copy_taint_op(const TraceAnalysisAMD64::InstRecord *inst, TaintState &ts, const cs_x86_op &op1, const cs_x86_op &out) {
    TaintValue tv1 = get_op_tv(op1, ts, inst);
    set_op_tv(out, ts, inst, tv1);
    return tv1.any();
}

static void clean_taint_op(const TraceAnalysisAMD64::InstRecord *inst, TaintState &ts, const cs_x86_op &out) {
    set_op_tv(out, ts, inst, TaintValue(0));
}

static bool is_op_same(const cs_x86_op &op1, const cs_x86_op &op2) {
    if (op1.type != op2.type) {
        return false;
    }

    if (op1.type == X86_OP_REG) {
        return op1.reg == op2.reg;
    }

    if (op1.type == X86_OP_IMM) {
        return memcmp(&op1.mem, &op2.mem, sizeof(op1.mem)) == 0;
    }

    if (op1.type == X86_OP_IMM) {
        return op1.imm == op2.imm;
    }

    return false;
}

static bool taint_step(cs_insn *insn, TaintState &ts, const TraceAnalysisAMD64::InstRecord *inst) {
    cs_x86_op *ops = insn->detail->x86.operands;
    uint8_t op_count = insn->detail->x86.op_count;
    bool tainted = false;

    TaintValue tv, tv2, tv3, tv4;
    uint64_t immop;
    switch (insn->id) {
    case X86_INS_AND:
        if (ops[1].type == X86_OP_IMM) {
            tv = get_op_tv(ops[0], ts, inst);
            if (tv.none()) {
                break;
                tainted = false;
            }
            immop = ops[1].imm;
            uint64_t mask = get_mask(8);
            for (uint64_t i = 0; i < ops[0].size; i++) {
                if ((immop & mask) == 0) {
                    tv[i] = 0;
                }
                mask <<= 8;
            }
            set_op_tv(ops[0], ts, inst, tv);
        }
        else {
            tainted = union_taint_op(inst, ts, ops[0], ops[1], ops[0]);
        }
        break;
    case X86_INS_OR:
        if (ops[1].type == X86_OP_IMM) {
            tv = get_op_tv(ops[0], ts, inst);
            if (tv.none()) {
                break;
                tainted = false;
            }
            immop = ops[1].imm;
            uint64_t mask = get_mask(8);
            for (uint64_t i = 0; i < ops[0].size; i++) {
                if (((immop & mask) >> (8 * i)) == 0xFF) {
                    tv[i] = 0;
                }
                mask <<= 8;
            }
            set_op_tv(ops[0], ts, inst, tv);
        }
        else {
            tainted = union_taint_op(inst, ts, ops[0], ops[1], ops[0]);
        }
        break;
    case X86_INS_ADC:
    case X86_INS_ADD:
        tainted = union_taint_op(inst, ts, ops[0], ops[1], ops[0]);
        break;
    case X86_INS_XOR:
    case X86_INS_SUB:
        if (is_op_same(ops[0], ops[1])) {
            tainted = get_op_tv(ops[0], ts, inst).any();
            clean_taint_op(inst, ts, ops[0]);
        }
        else {
            tainted = union_taint_op(inst, ts, ops[0], ops[1], ops[0]);
        }
        break;
    case X86_INS_CMOVA:
    case X86_INS_CMOVAE:
    case X86_INS_CMOVB:
    case X86_INS_CMOVBE:
    case X86_INS_CMOVE:
    case X86_INS_CMOVG:
    case X86_INS_CMOVGE:
    case X86_INS_CMOVL:
    case X86_INS_CMOVLE:
    case X86_INS_CMOVNE:
    case X86_INS_CMOVNO:
    case X86_INS_CMOVNP:
    case X86_INS_CMOVNS:
    case X86_INS_CMOVO:
    case X86_INS_CMOVP:
    case X86_INS_CMOVS:
    case X86_INS_MOVABS:
    case X86_INS_MOVSX:
    case X86_INS_MOVZX:
    case X86_INS_MOVSXD:
    case X86_INS_MOV:
        tainted = copy_taint_op(inst, ts, ops[1], ops[0]);
        break;
    case X86_INS_PUSH:
        tv = get_op_tv(ops[0], ts, inst);
        tainted = tv.any();
        if (tainted) {
            set_addr_tv(inst->rsp - 8, 8, ts, tv);
            tainted = true;
        }
        break;
    case X86_INS_POP:
        tv = get_addr_tv(inst->rsp, 8, ts);
        tainted = tv.any();
        if (tainted) {
            set_op_tv(ops[0], ts, inst, tv);
        }
        break;
    case X86_INS_MOVSB:
        tv = get_addr_tv(inst->rsi, 1, ts);
        tainted = tv.any();
        set_addr_tv(inst->rdi, 1, ts, tv);
        break;
    case X86_INS_MOVSW:
        tv = get_addr_tv(inst->rsi, 2, ts);
        tainted = tv.any();
        set_addr_tv(inst->rdi, 2, ts, tv);
        break;
    case X86_INS_MOVSD:
        tv = get_addr_tv(inst->rsi, 4, ts);
        tainted = tv.any();
        set_addr_tv(inst->rdi, 4, ts, tv);
        break;
    case X86_INS_MOVSQ:
        tv = get_addr_tv(inst->rsi, 8, ts);
        tainted = tv.any();
        set_addr_tv(inst->rdi, 8, ts, tv);
        break;
    case X86_INS_LEA:
        if (ops[1].type == X86_OP_MEM) {
            if (get_reg_tv(ops[1].mem.base, ts).any() || get_reg_tv(ops[1].mem.index, ts).any()) {
                tainted = true;
                set_reg_tv(ops[0].reg, ts, TaintValue(get_mask(8)));
            }
        }
        break;
    case X86_INS_XCHG:
        tv = get_op_tv(ops[0], ts, inst);
        tv2 = get_op_tv(ops[1], ts, inst);
        set_op_tv(ops[0], ts, inst, tv2);
        set_op_tv(ops[0], ts, inst, tv);
        tainted = tv.any() || tv2.any();
    case X86_INS_STOSQ:
        tv = get_reg_tv(ops[1].reg, ts);
        tainted = tv.any();
        set_addr_tv(inst->rdi, 8, ts, tv);
        break;
    case X86_INS_STOSD:
        tv = get_reg_tv(ops[1].reg, ts);
        tainted = tv.any();
        set_addr_tv(inst->rdi, 4, ts, tv);
        break;
    case X86_INS_STOSW:
        tv = get_reg_tv(ops[1].reg, ts);
        tainted = tv.any();
        set_addr_tv(inst->rdi, 2, ts, tv);
        break;
    case X86_INS_STOSB:
        tv = get_reg_tv(ops[1].reg, ts);
        tainted = tv.any();
        set_addr_tv(inst->rdi, 1, ts, tv);
        break;
    case X86_INS_MUL:
        tv = get_op_tv(ops[0], ts, inst);
        switch (ops[0].size) {
        case 1:
            tv2 = get_reg_tv(X86_REG_AX, ts);
            tainted = tv.any() || tv2.any();
            tv4 = tv | tv2;
            set_reg_tv(X86_REG_AX, ts, tv4);
            break;
        case 2:
            tv2 = get_reg_tv(X86_REG_DX, ts);
            tv3 = get_reg_tv(X86_REG_AX, ts);
            tainted = tv.any() || tv2.any() || tv3.any();
            tv4 = tv | tv2 | tv3;
            set_reg_tv(X86_REG_AX, ts, tv4);
            set_reg_tv(X86_REG_DX, ts, tv4);
            break;
        case 4:
            tv2 = get_reg_tv(X86_REG_EAX, ts);
            tv3 = get_reg_tv(X86_REG_EDX, ts);
            tainted = tv.any() || tv2.any() || tv3.any();
            tv4 = tv | tv2 | tv3;
            set_reg_tv(X86_REG_EAX, ts, tv4);
            set_reg_tv(X86_REG_EDX, ts, tv4);
            break;
        case 8:
            tv2 = get_reg_tv(X86_REG_RAX, ts);
            tv3 = get_reg_tv(X86_REG_RDX, ts);
            tainted = tv.any() || tv2.any() || tv3.any();
            tv4 = tv | tv2 | tv3;
            set_reg_tv(X86_REG_RAX, ts, tv4);
            set_reg_tv(X86_REG_RDX, ts, tv4);
            break;
        }
        break;
    case X86_INS_IMUL:
        switch (insn->detail->x86.op_count) {
        case 1:
            tv = get_op_tv(ops[0], ts, inst);
            switch (ops[0].size) {
            case 1:
                tv2 = get_reg_tv(X86_REG_AL, ts);
                tv3 = tv | tv2;
                set_reg_tv(X86_REG_AX, ts, tv3);
                break;
            case 2:
                tv2 = get_reg_tv(X86_REG_AX, ts);
                tv3 = tv | tv2;
                set_reg_tv(X86_REG_AX, ts, tv3);
                set_reg_tv(X86_REG_DX, ts, tv3);
                break;
            case 4:
                tv2 = get_reg_tv(X86_REG_EAX, ts);
                tv3 = tv | tv2;
                set_reg_tv(X86_REG_EAX, ts, tv3);
                set_reg_tv(X86_REG_EDX, ts, tv3);
                break;
            case 8:
                tv2 = get_reg_tv(X86_REG_RAX, ts);
                tv3 = tv | tv2;
                set_reg_tv(X86_REG_RAX, ts, tv3);
                set_reg_tv(X86_REG_RDX, ts, tv3);
                break;
            }
            tainted = tv3.any();
            break;
        case 2:
        case 3:
            union_taint_op(inst, ts, ops[0], ops[1], ops[0]);
            break;
        }
        break;
    case X86_INS_DIV:
    case X86_INS_IDIV:
        tv = get_op_tv(ops[0], ts, inst);
        switch (ops[0].size) {
        case 1:
            tv2 = get_reg_tv(X86_REG_AX, ts);
            tv3 = tv | tv2;
            tainted = tv3.any();
            if (tv3.any()) {
                set_reg_tv(X86_REG_AL, ts, TaintValue(1));
                set_reg_tv(X86_REG_AH, ts, TaintValue(1));
            }
            else {
               set_reg_tv(X86_REG_AL, ts, TaintValue(0));
                set_reg_tv(X86_REG_AH, ts, TaintValue(0));
            }
            break;
        case 2:
            tv2 = get_reg_tv(X86_REG_AX, ts);
            tv3 = get_reg_tv(X86_REG_DX, ts);
            tv4 = tv2 | tv3 | tv;
            tainted = tv4.any();
            set_reg_tv(X86_REG_AX, ts, tv4);
            set_reg_tv(X86_REG_DX, ts, tv4);
            break;
        case 4:
            tv2 = get_reg_tv(X86_REG_EAX, ts);
            tv3 = get_reg_tv(X86_REG_EDX, ts);
            tv4 = tv2 | tv3 | tv;
            tainted = tv4.any();
            set_reg_tv(X86_REG_EAX, ts, tv4);
            set_reg_tv(X86_REG_EDX, ts, tv4);
            break;
        case 8:
            tv2 = get_reg_tv(X86_REG_RAX, ts);
            tv3 = get_reg_tv(X86_REG_RDX, ts);
            tv4 = tv2 | tv3 | tv;
            tainted = tv4.any();
            set_reg_tv(X86_REG_RAX, ts, tv4);
            set_reg_tv(X86_REG_RDX, ts, tv4);
            break;
        }
        break;
    default:
        for (uint8_t i = 0; i < insn->detail->x86.op_count; i++) {
            if (get_op_tv(ops[i], ts, inst).any()) {
                tainted = true;
                break;
            }
        }
        break;
    }

    return tainted;
}

void TraceAnalysisAMD64::forward_taint(uint64_t inst_index, TaintState init_ts, std::vector<uint64_t> &result, uint64_t max_iter) {
    std::fill_n(csreg2regindex, 256, -1);
    std::fill_n(csreg2rangebegin, 256, -1);
    std::fill_n(csreg2rangeend, 256, -1);
    setup();

    uint64_t end;
    if (max_iter == 0) {
        end = inst_len / sizeof(InstRecord);
    }
    else {
        end = std::min({inst_index + max_iter, inst_len / sizeof(InstRecord)});
    }

    for (uint64_t i = inst_index; i < end; i++) {
        cs_insn *insn = disasm(i);
        if (taint_step(insn, init_ts, reinterpret_cast<const InstRecord *>(inst) + i)) {
            result.push_back(i);
        }
        cs_free(insn, 1);
        if (init_ts.empty()) {
            break;
        }
    }
}

void TraceAnalysisAMD64::set_reg_tv(TaintState &ts, uint8_t regid, TaintValue tv) {
    ::set_reg_tv(x86_reg(regid), ts, tv);

}

void TraceAnalysisAMD64::set_addr_tv(TaintState &ts, uint64_t addr, uint8_t size, TaintValue tv) {
    ::set_addr_tv(addr, size, ts, tv);
}

static void setup() {
    csreg2regindex[X86_REG_RAX] = 0;
    csreg2regindex[X86_REG_EAX] = 0;
    csreg2regindex[X86_REG_AX] = 0;
    csreg2regindex[X86_REG_AL] = 0;
    csreg2regindex[X86_REG_AH] = 0;
    csreg2rangebegin[X86_REG_RAX] = 0;
    csreg2rangeend[X86_REG_RAX] = 8;
    csreg2rangebegin[X86_REG_EAX] = 0;
    csreg2rangeend[X86_REG_EAX] = 4;
    csreg2rangebegin[X86_REG_AX] = 0;
    csreg2rangeend[X86_REG_AX] = 2;
    csreg2rangebegin[X86_REG_AL] = 0;
    csreg2rangeend[X86_REG_AL] = 1;
    csreg2rangebegin[X86_REG_AH] = 1;
    csreg2rangeend[X86_REG_AH] = 2;
    

    csreg2regindex[X86_REG_RBX] = 1;
    csreg2regindex[X86_REG_EBX] = 1;
    csreg2regindex[X86_REG_BX] = 1;
    csreg2regindex[X86_REG_BL] = 1;
    csreg2regindex[X86_REG_BH] = 1;
    csreg2rangebegin[X86_REG_RBX] = 0;
    csreg2rangeend[X86_REG_RBX] = 8;
    csreg2rangebegin[X86_REG_EBX] = 0;
    csreg2rangeend[X86_REG_EBX] = 4;
    csreg2rangebegin[X86_REG_BX] = 0;
    csreg2rangeend[X86_REG_BX] = 2;
    csreg2rangebegin[X86_REG_BL] = 0;
    csreg2rangeend[X86_REG_BL] = 1;
    csreg2rangebegin[X86_REG_BH] = 1;
    csreg2rangeend[X86_REG_BH] = 2;
    
    csreg2regindex[X86_REG_RCX] = 2;
    csreg2regindex[X86_REG_ECX] = 2;
    csreg2regindex[X86_REG_CX] = 2;
    csreg2regindex[X86_REG_CL] = 2;
    csreg2regindex[X86_REG_CH] = 2;
    csreg2rangebegin[X86_REG_RCX] = 0;
    csreg2rangeend[X86_REG_RCX] = 8;
    csreg2rangebegin[X86_REG_ECX] = 0;
    csreg2rangeend[X86_REG_ECX] = 4;
    csreg2rangebegin[X86_REG_CX] = 0;
    csreg2rangeend[X86_REG_CX] = 2;
    csreg2rangebegin[X86_REG_CL] = 0;
    csreg2rangeend[X86_REG_CL] = 1;
    csreg2rangebegin[X86_REG_CH] = 1;
    csreg2rangeend[X86_REG_CH] = 2;

    csreg2regindex[X86_REG_RDX] = 3;
    csreg2regindex[X86_REG_EDX] = 3;
    csreg2regindex[X86_REG_DX] = 3;
    csreg2regindex[X86_REG_DL] = 3;
    csreg2regindex[X86_REG_DH] = 3;
    csreg2rangebegin[X86_REG_RDX] = 0;
    csreg2rangeend[X86_REG_RDX] = 8;
    csreg2rangebegin[X86_REG_EDX] = 0;
    csreg2rangeend[X86_REG_EDX] = 4;
    csreg2rangebegin[X86_REG_DX] = 0;
    csreg2rangeend[X86_REG_DX] = 2;
    csreg2rangebegin[X86_REG_DL] = 0;
    csreg2rangeend[X86_REG_DL] = 1;
    csreg2rangebegin[X86_REG_DH] = 1;
    csreg2rangeend[X86_REG_DH] = 2;

    csreg2regindex[X86_REG_RDI] = 4;
    csreg2regindex[X86_REG_EDI] = 4;
    csreg2regindex[X86_REG_DI] = 4;
    csreg2regindex[X86_REG_DIL] = 4;
    csreg2rangebegin[X86_REG_RDI] = 0;
    csreg2rangeend[X86_REG_RDI] = 8;
    csreg2rangebegin[X86_REG_EDI] = 0;
    csreg2rangeend[X86_REG_EDI] = 4;
    csreg2rangebegin[X86_REG_DI] = 0;
    csreg2rangeend[X86_REG_DI] = 2;
    csreg2rangebegin[X86_REG_DIL] = 0;
    csreg2rangeend[X86_REG_DIL] = 1;

    csreg2regindex[X86_REG_RSI] = 5;
    csreg2regindex[X86_REG_ESI] = 5;
    csreg2regindex[X86_REG_SI] = 5;
    csreg2regindex[X86_REG_SIL] = 5;
    csreg2rangebegin[X86_REG_RSI] = 0;
    csreg2rangeend[X86_REG_RSI] = 8;
    csreg2rangebegin[X86_REG_ESI] = 0;
    csreg2rangeend[X86_REG_ESI] = 4;
    csreg2rangebegin[X86_REG_SI] = 0;
    csreg2rangeend[X86_REG_SI] = 2;
    csreg2rangebegin[X86_REG_SIL] = 0;
    csreg2rangeend[X86_REG_SIL] = 1;
    
    csreg2regindex[X86_REG_RBP] = 6;
    csreg2regindex[X86_REG_EBP] = 6;
    csreg2regindex[X86_REG_BP] = 6;
    csreg2regindex[X86_REG_BPL] = 6;
    csreg2rangebegin[X86_REG_RBP] = 0;
    csreg2rangeend[X86_REG_RBP] = 8;
    csreg2rangebegin[X86_REG_EBP] = 0;
    csreg2rangeend[X86_REG_EBP] = 4;
    csreg2rangebegin[X86_REG_BP] = 0;
    csreg2rangeend[X86_REG_BP] = 2;
    csreg2rangebegin[X86_REG_BPL] = 0;
    csreg2rangeend[X86_REG_BPL] = 1;
    
    csreg2regindex[X86_REG_RSP] = 7;
    csreg2regindex[X86_REG_ESP] = 7;
    csreg2regindex[X86_REG_SP] = 7;
    csreg2regindex[X86_REG_SPL] = 7;
    csreg2rangebegin[X86_REG_RSP] = 0;
    csreg2rangeend[X86_REG_RSP] = 8;
    csreg2rangebegin[X86_REG_ESP] = 0;
    csreg2rangeend[X86_REG_ESP] = 4;
    csreg2rangebegin[X86_REG_SP] = 0;
    csreg2rangeend[X86_REG_SP] = 2;
    csreg2rangebegin[X86_REG_SPL] = 0;
    csreg2rangeend[X86_REG_SPL] = 1;

    csreg2regindex[X86_REG_RIP] = 8;
    csreg2regindex[X86_REG_EIP] = 8;
    csreg2regindex[X86_REG_IP] = 8;
    csreg2rangebegin[X86_REG_RIP] = 0;
    csreg2rangeend[X86_REG_RIP] = 8;
    csreg2rangebegin[X86_REG_EIP] = 0;
    csreg2rangeend[X86_REG_EIP] = 4;
    csreg2rangebegin[X86_REG_IP] = 0;
    csreg2rangeend[X86_REG_IP] = 2;

    csreg2regindex[X86_REG_R8] = 9;
    csreg2regindex[X86_REG_R8D] = 9;
    csreg2regindex[X86_REG_R8W] = 9;
    csreg2regindex[X86_REG_R8B] = 9;
    csreg2rangebegin[X86_REG_R8] = 0;
    csreg2rangeend[X86_REG_R8] = 8;
    csreg2rangebegin[X86_REG_R8D] = 0;
    csreg2rangeend[X86_REG_R8D] = 4;
    csreg2rangebegin[X86_REG_R8W] = 0;
    csreg2rangeend[X86_REG_R8W] = 2;
    csreg2rangebegin[X86_REG_R8B] = 0;
    csreg2rangeend[X86_REG_R8B] = 1;

    csreg2regindex[X86_REG_R9] = 10;
    csreg2regindex[X86_REG_R9D] = 10;
    csreg2regindex[X86_REG_R9W] = 10;
    csreg2regindex[X86_REG_R9B] = 10;
    csreg2rangebegin[X86_REG_R9] = 0;
    csreg2rangeend[X86_REG_R9] = 8;
    csreg2rangebegin[X86_REG_R9D] = 0;
    csreg2rangeend[X86_REG_R9D] = 4;
    csreg2rangebegin[X86_REG_R9W] = 0;
    csreg2rangeend[X86_REG_R9W] = 2;
    csreg2rangebegin[X86_REG_R9B] = 0;
    csreg2rangeend[X86_REG_R9B] = 1;
    
    csreg2regindex[X86_REG_R10] = 11;
    csreg2regindex[X86_REG_R10D] = 11;
    csreg2regindex[X86_REG_R10W] = 11;
    csreg2regindex[X86_REG_R10B] = 11;
    csreg2rangebegin[X86_REG_R10] = 0;
    csreg2rangeend[X86_REG_R10] = 8;
    csreg2rangebegin[X86_REG_R10D] = 0;
    csreg2rangeend[X86_REG_R10D] = 4;
    csreg2rangebegin[X86_REG_R10W] = 0;
    csreg2rangeend[X86_REG_R10W] = 2;
    csreg2rangebegin[X86_REG_R10B] = 0;
    csreg2rangeend[X86_REG_R10B] = 1;
    
    csreg2regindex[X86_REG_R11] = 12;
    csreg2regindex[X86_REG_R11D] = 12;
    csreg2regindex[X86_REG_R11W] = 12;
    csreg2regindex[X86_REG_R11B] = 12;
    csreg2rangebegin[X86_REG_R11] = 0;
    csreg2rangeend[X86_REG_R11] = 8;
    csreg2rangebegin[X86_REG_R11D] = 0;
    csreg2rangeend[X86_REG_R11D] = 4;
    csreg2rangebegin[X86_REG_R11W] = 0;
    csreg2rangeend[X86_REG_R11W] = 2;
    csreg2rangebegin[X86_REG_R11B] = 0;
    csreg2rangeend[X86_REG_R11B] = 1;

    csreg2regindex[X86_REG_R12] = 13;
    csreg2regindex[X86_REG_R12D] = 13;
    csreg2regindex[X86_REG_R12W] = 13;
    csreg2regindex[X86_REG_R12B] = 13;
    csreg2rangebegin[X86_REG_R12] = 0;
    csreg2rangeend[X86_REG_R12] = 8;
    csreg2rangebegin[X86_REG_R12D] = 0;
    csreg2rangeend[X86_REG_R12D] = 4;
    csreg2rangebegin[X86_REG_R12W] = 0;
    csreg2rangeend[X86_REG_R12W] = 2;
    csreg2rangebegin[X86_REG_R12B] = 0;
    csreg2rangeend[X86_REG_R12B] = 1;

    csreg2regindex[X86_REG_R13] = 14;
    csreg2regindex[X86_REG_R13D] = 14;
    csreg2regindex[X86_REG_R13W] = 14;
    csreg2regindex[X86_REG_R13B] = 14;
    csreg2rangebegin[X86_REG_R13] = 0;
    csreg2rangeend[X86_REG_R13] = 8;
    csreg2rangebegin[X86_REG_R13D] = 0;
    csreg2rangeend[X86_REG_R13D] = 4;
    csreg2rangebegin[X86_REG_R13W] = 0;
    csreg2rangeend[X86_REG_R13W] = 2;
    csreg2rangebegin[X86_REG_R13B] = 0;
    csreg2rangeend[X86_REG_R13B] = 1;
    
    csreg2regindex[X86_REG_R14] = 15;
    csreg2regindex[X86_REG_R14D] = 15;
    csreg2regindex[X86_REG_R14W] = 15;
    csreg2regindex[X86_REG_R14B] = 15;
    csreg2rangebegin[X86_REG_R14] = 0;
    csreg2rangeend[X86_REG_R14] = 8;
    csreg2rangebegin[X86_REG_R14D] = 0;
    csreg2rangeend[X86_REG_R14D] = 4;
    csreg2rangebegin[X86_REG_R14W] = 0;
    csreg2rangeend[X86_REG_R14W] = 2;
    csreg2rangebegin[X86_REG_R14B] = 0;
    csreg2rangeend[X86_REG_R14B] = 1;
    
    csreg2regindex[X86_REG_R15] = 16;
    csreg2regindex[X86_REG_R15D] = 16;
    csreg2regindex[X86_REG_R15W] = 16;
    csreg2regindex[X86_REG_R15B] = 16;
    csreg2rangebegin[X86_REG_R15] = 0;
    csreg2rangeend[X86_REG_R15] = 8;
    csreg2rangebegin[X86_REG_R15D] = 0;
    csreg2rangeend[X86_REG_R15D] = 4;
    csreg2rangebegin[X86_REG_R15W] = 0;
    csreg2rangeend[X86_REG_R15W] = 2;
    csreg2rangebegin[X86_REG_R15B] = 0;
    csreg2rangeend[X86_REG_R15B] = 1;
}