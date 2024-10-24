add_llvm_library( LLVMBBSplit MODULE
Split.cpp

ADDITIONAL_HEADER_DIRS
${LLVM_MAIN_INCLUDE_DIR}/llvm/Transforms
${LLVM_MAIN_INCLUDE_DIR}/llvm/Transforms/BBSplit

DEPENDS
intrinsics_gen

PLUGIN_TOOL
opt
)