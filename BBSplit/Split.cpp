#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Transforms/BBSplitter/Split.h"
using namespace llvm;

static void splitTooBigBasicBlock(BasicBlock &BB) {
        
            if(BB.size() > 100){
                errs() << "Split: Found a too-big basic block. Splitting";

                auto splitInstr = BB.begin();
                for(int i = 0; i < 99; ++i){
                    splitInstr++;
                }

                splitTooBigBasicBlock(*BB.splitBasicBlock(splitInstr));
                
                return; //true; | uncomment if we need to return whether we made modifications
            }

            return; //false | Return false if we get here because that means we didn't modify this basic block
}


PreservedAnalyses Split::run(Function &F, FunctionAnalysisManager &) {

    for (auto &BB : F) {
        splitTooBigBasicBlock(BB);
    }

    // Just conservatively invalidate analyses, this isn't likely to be important.
    return PreservedAnalyses::none();
}

/*
namespace{

    struct Split : public FunctionPass{

        static char ID;

        Split() : FunctionPass(ID){}
        
        bool runOnFunction(Function &F) override{
            for (auto &BB : F) {
                splitTooBigBasicBlock(BB);
            }
        }

    }; // end of struct Split
}  // end of anonymous namespace


//char Split::ID = 0;

static RegisterPass<Split> X("split", "Basic Block Splitter Pass",
                            false,
                            false);

*/

