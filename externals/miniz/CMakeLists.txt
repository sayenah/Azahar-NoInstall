# miniz - single-file zlib/zip library (MIT), https://github.com/richgel999/miniz
add_library(miniz STATIC miniz.c miniz.h)
target_include_directories(miniz INTERFACE .)
target_compile_definitions(miniz PRIVATE MINIZ_NO_TIME)
