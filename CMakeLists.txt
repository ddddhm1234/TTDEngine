cmake_minimum_required(VERSION 3.22)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


add_library(TTDEngine SHARED interface.cpp memory_model.cpp taint_amd64.cpp trace_analysis.cpp trace_analysis_amd64.cpp)
target_link_directories(TTDEngine PUBLIC ${PROJECT_SOURCE_DIR}\\libs\\capstone\\libs)
target_link_libraries(TTDEngine capstone_dll)
target_include_directories(TTDEngine PUBLIC  ${PROJECT_SOURCE_DIR}\\libs\\capstone\\include)
add_executable(main main.cpp)
target_link_libraries(main TTDEngine)