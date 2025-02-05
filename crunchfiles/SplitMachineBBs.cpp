//==- llvm/CodeGen/BreakFalseDeps.cpp - Break False Dependency Fix -*- C++ -*==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
/// \file split basic blocks pass.
///
///OWEN
///
/// Some basic blocks are too big to fit on just one page. The same is true for
/// sequences of basic blocks that fall through to one another. This makes them
/// problematic for DART randomization since we randomize with pages. This pass
/// splits any basic block (or sequence of basic blocks) that violate page size
/// constraints. 
//
//===----------------------------------------------------------------------===//

#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/RegisterClassInfo.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/TargetPassConfig.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Target/TargetMachine.h"
#include "llvm/MC/MCInstrDesc.h"
#include "X86.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"

#include "llvm/Support/CommandLine.h"

#include <vector>
#include <iostream>
#include <string>





using namespace llvm;

signed DartBBSplitFlag;
cl::opt<signed, true> DartSplitBB("Max-BB-Size", cl::desc("maximum size, in instructions, of a BBL"),
    cl::value_desc("instructions"), cl::location(DartBBSplitFlag), cl::init(0));

namespace llvm {

class SplitBasicBlocksPass : public MachineFunctionPass {
private:

  void splitBasicBlock(MachineBasicBlock &MBB, const TargetInstrInfo *TII) {
    MachineFunction *MF = MBB.getParent();
    MachineBasicBlock::iterator SplitPoint = MBB.begin();
    
    std::advance(SplitPoint, MBB.size() / 2);

    MachineBasicBlock *NewMBB = MF->CreateMachineBasicBlock();
    MF->insert(++MachineFunction::iterator(&MBB), NewMBB);

    NewMBB->splice(NewMBB->end(), &MBB, SplitPoint, MBB.end());

    BuildMI(MBB, MBB.end(), DebugLoc(), TII->get(X86::JMP_4)).addMBB(NewMBB);

    SmallVector<MachineBasicBlock *, 4> Succs(MBB.successors());

    //update successors
    for (MachineBasicBlock *Succ : Succs) {
        NewMBB->addSuccessor(Succ);
        MBB.removeSuccessor(Succ);
    }
    MBB.addSuccessor(NewMBB);

    //recomputeLiveIns(NewMBB);
    //update liveins (copied and pasted from the new version of livephysregs)
    LivePhysRegs LPR;
    //std::vector<MachineBasicBlock::RegisterMaskPair> OldLiveIns;
    NewMBB->clearLiveIns();//OldLiveIns);
    computeAndAddLiveIns(LPR, *NewMBB);
    NewMBB->sortUniqueLiveIns();

    LivePhysRegs prevLPR;
    //std::vector<MachineBasicBlock::RegisterMaskPair> OldLiveIns;
    MBB.clearLiveIns();//OldLiveIns);
    computeAndAddLiveIns(prevLPR, MBB);
    MBB.sortUniqueLiveIns();


    //RECENT check if blocks we've split are still too big
    if(MBB.size() > DartBBSplitFlag)
      splitBasicBlock(MBB, TII);
    if((NewMBB->size() > DartBBSplitFlag))
      splitBasicBlock(*NewMBB, TII);
  }

  unsigned getMBBsizeBytes(const MachineBasicBlock &MBB, const TargetInstrInfo *TII){

    return MBB.size() * 8;
    //TEST just return the length in instructions * 8 for now
    unsigned size(0);
    auto iter = MBB.begin();

    while(iter != MBB.end()){

      unsigned allegedsize = TII->getInstSizeInBytes(*iter);
      outs() << "Alleged size of this instr: " << allegedsize << "\n";

      size += allegedsize;
      std::advance(iter, 1);
    }

    return size;
  }


public:
  static char ID;
  SplitBasicBlocksPass() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &MF) override {

    outs() << "the machine split pass is running\n";
    outs() << "with max BBL size " << DartBBSplitFlag << "\n";
    bool Changed = false;

    if(DartBBSplitFlag == 0){
        outs() << "Max BBL size not set or set to 0. Not splitting";
        return Changed;
    }


    std::vector<MachineBasicBlock *> MBBsToSplit;

    unsigned sizecount(0);
    const TargetInstrInfo *TII = MF.getSubtarget().getInstrInfo();

    for (auto &MBB : MF) {

        //Don't split the padding section, it's of a very particular size
        if(MBB.getFullName().find("DART_Inflate_Binary") != std::string::npos){
          sizecount = 0;
          outs() << "we're in the " << MBB.getFullName() << " do not split here\n";
        }

        else
          sizecount += getMBBsizeBytes(MBB, TII);
        
        if(sizecount > DartBBSplitFlag){
            MBBsToSplit.push_back(&MBB);
            outs() << "Estimating block size: " << sizecount << "idk tho lol \n";
            outs() << "This block segment" << MBB.getFullName() << " is too big. Splitting\n";
            sizecount -= DartBBSplitFlag;
        }
        else if(!MBB.canFallThrough(false)){
            sizecount = 0;
        }
    }


    for (auto &MBB : MBBsToSplit){
        splitBasicBlock(*MBB, TII);
        Changed = true;
    }

    outs() << "finished splitting. Hopefully we're good from here\n";

    return Changed;
  }
};

char SplitBasicBlocksPass::ID;

//TODO: fix this so llvm knows what this pass is called. It shouldn't be too bad, literally
//copy it from another pass. Not that important right now so it's left out
//llvm::StringRef *SplitBasicBlocksPass::getPassName() const{
//  return "Basic Block Splitter Pass";
//}

} // end llvm namespace


#define DEBUG_TYPE "split-machine-BBs"

//INITIALIZE_PASS_BEGIN(SplitBasicBlocksPass, "split-bb", "Split Basic Blocks", false, false)
//NITIALIZE_PASS_DEPENDENCY(MachineDominatorTree)
//INITIALIZE_PASS_DEPENDENCY(MachineLoopInfo)
//INITIALIZE_PASS_END(SplitBasicBlocksPass, "split-bb", "Split Basic Blocks", false, false)


FunctionPass *llvm::createSplitBasicBlocksPass(){return new SplitBasicBlocksPass();}
