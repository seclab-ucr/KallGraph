llvm_map_components_to_libnames(llvm_libs bitwriter core ipo irreader instcombine instrumentation target linker analysis scalaropts support )

file(GLOB KALL_SRC
    include/*.hpp
    lib/*.cpp
)

macro(setupEnv target)
target_include_directories(${target} PUBLIC include/)
target_link_libraries(${target} ${SVF_LIB} ${LLVMCudd} ${llvm_libs} )
set_target_properties(${target} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set_target_properties(${target} PROPERTIES
	COMPILE_FLAGS "-fno-rtti -fPIC"
)
endmacro(setupEnv)

add_executable(KallGraph
    KallGraph.cpp
    ${KALL_SRC}
)
setupEnv(KallGraph)