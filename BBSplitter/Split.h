
#ifndef LLVM_TRANSFORMS_BBSplitter_Split
#define LLVM_TRANSFORMS_BBSplitter_Split

#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"

namespace llvm {

struct Split : PassInfoMixin<Split> {
  PreservedAnalyses run(Function &BB, FunctionAnalysisManager &);
};

/// Create a legacy pass manager instance of a pass to force function attrs.
//Pass *createSplit();

}

#endif // LLVM_TRANSFORMS_BBSplitter_Split_h
