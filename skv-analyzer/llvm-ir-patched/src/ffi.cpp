#include <llvm/IR/InlineAsm.h>
#include <llvm-c/Core.h>
#include <string.h>
#include <stdlib.h>
#include <string>

extern "C" const char* LLVMIRPatchedGetInlineAsmString(LLVMValueRef Val) {
    llvm::Value *V = llvm::unwrap(Val);
    if (llvm::InlineAsm *IA = llvm::dyn_cast<llvm::InlineAsm>(V)) {
        std::string Str = IA->getAsmString().str();
        char *cstr = (char*)malloc(Str.length() + 1);
        strcpy(cstr, Str.c_str());
        return cstr;
    }
    return nullptr;
}

extern "C" void LLVMIRPatchedFreeString(const char* Str) {
    free((void*)Str);
}
