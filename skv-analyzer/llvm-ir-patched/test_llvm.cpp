#include <llvm/IR/InlineAsm.h>
#include <llvm-c/Core.h>
#include <iostream>

extern "C" const char* LLVMGetInlineAsmAsmString(LLVMValueRef Val) {
    llvm::Value *V = llvm::unwrap(Val);
    if (llvm::InlineAsm *IA = llvm::dyn_cast<llvm::InlineAsm>(V)) {
        return IA->getAsmString().c_str();
    }
    return nullptr;
}
