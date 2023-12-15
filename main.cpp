#include <algorithm>
#include <cstdint>
#include <ctime>
#include <codecvt>
#include <vector>
#include <iostream>
#include <fstream>
#include <bitset>
#include "trace_analysis_amd64.h"
#include "memory_model.h"

#include <Windows.h>
extern "C" {
    #include <capstone/capstone.h>
}

using namespace std;

static void UnicodeToGB2312(const char* unicode, int size, char*gb2312)
{
	WideCharToMultiByte(CP_ACP, 0, LPCWCH(unicode), size / 2, gb2312, 10000, NULL, NULL);
}

struct Unit {
    union 
    {
        uint64_t byte;
        struct {
            uint8_t b0: 1;
            uint8_t b1: 1;
            uint8_t b2: 1;
            uint8_t b3: 1;
            uint8_t b4: 1;
            uint8_t b5: 1;
            uint8_t b6: 1;
            uint8_t b7: 1;  
        };
    };
};

int main(int argc, char *argv[]) {
    FILE* fp = fopen(R"(C:\Tools\System\pin\source\tools\MyTrace\output\0.mem)", "rb");

    fseek(fp, 0, SEEK_END);
    long mem_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t* mem = (uint8_t *)malloc(mem_len);
    fread(mem, mem_len, 1, fp);
    fclose(fp);

    ifstream file(R"(C:\Tools\System\pin\source\tools\MyTrace\output\0.ins)", ios::binary | ios::ate);
    streamsize ins_len = file.tellg();
    uint8_t* ins = (uint8_t *)malloc(ins_len);
    file.seekg(0, ios::beg);
    file.read((char*)ins, ins_len);
    file.close();


    TraceAnalysisAMD64 ta_amd64(ins, ins_len, mem, mem_len);

    std::vector<uint64_t> results;
    ta_amd64.search_context(0x0, results);
    cout << results.size() << endl;

    // std::vector<MemoryView::MemSearchResult> mem_occurs;
    // // 搜索内存变化过程中出现过的所有 "a.exe"
    // ta_amd64.mem_view.search_mem("a.exe", 5, mem_occurs);
    
    // const MemRecord *memrs = reinterpret_cast<const MemRecord *>(ta_amd64.mem);

    // for (uint8_t i = 0; i < mem_occurs.size(); i++) {
    //     uint64_t inst_index = memrs[mem_occurs[i].mem_index].inst_index;
    //     auto dis = ta_amd64.disasm(inst_index);
    //     printf("%016X: %s %s => %016X\n", dis->address, dis->mnemonic, dis->op_str, mem_occurs[i].addr);
    // }

    // // 追踪出现过第一次的"a.exe"
    // std::vector<uint64_t> result;
    // ta_amd64.forward_taint(memrs[mem_occurs[0].mem_index].inst_index, TaintState {{mem_occurs[0].addr - 1, TaintValue(0b11111111)}}, result, 10000);
    // // 打印追踪结果
    // for (int i = 0; i < result.size(); i++) {
    //     auto dis = ta_amd64.disasm(result[i]);

    //     cout << result[i] << " : " << dis->mnemonic << " " << dis->op_str << endl;

    //     cs_free(dis, 1);
    // }


    // // 列出trace中所有字符串引用
    // std::vector<TraceAnalysis::StringRefResult> xrefs;
    // ta_amd64.list_string_xrefs(xrefs, 20);
    // for (int i = xrefs.size() - 1; i >= 0; i--) {
    //     // 如果是ascii字符串
    //     if (xrefs[i].type == 1) {
    //         auto dis = ta_amd64.disasm(xrefs[i].inst_index);
    //         printf("%016llx %s %s => %s\n", dis->address, dis->mnemonic, dis->op_str, xrefs[i].str.c_str());
    //     }
    // }

    // cs_insn *I;
    // cs_disasm(ta_amd64.csh,  (uint8_t *)"\x48\x0F\xAF\xC3", 4, 0x0, 1, &I);
    // cout << I->mnemonic << " " << I->op_str << endl;

    // std::vector<uint64_t> result;
    // ta_amd64.forward_taint(93, TaintState {{0, TaintValue(0b11111111)}}, result, 10000);

    // for (int i = 2; i < 100; i++) {
    //     auto dis = ta_amd64.disasm(i);

    //     // cout << i << " : " << dis->mnemonic << " " << dis->op_str << endl;

    //     cs_free(dis, 1);
    // }

    // for (int i = 0; i < result.size(); i++) {
    //     auto dis = ta_amd64.disasm(result[i]);

    //     cout << result[i] << " : " << dis->mnemonic << " " << dis->op_str << endl;

    //     cs_free(dis, 1);
    // }


    // auto t1 = clock();

    // char pattern[] = "GetProcAddress";
    // std::vector<MemoryView::MemSearchResult> results;
    // ta_amd64.mem_view.search_mem(pattern, strlen(pattern), results);

    // auto t2 = clock();

    // cout << double(t2 - t1) / CLOCKS_PER_SEC << endl;
    
    return 0;
}