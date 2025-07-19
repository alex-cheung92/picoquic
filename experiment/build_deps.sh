#!/bin/bash
cur_dir=$(cd `dirname $0` && pwd)
picosource_source_dir=$(dirname $cur_dir)
compile_out_dir=${picosource_source_dir}/experiment/build
deps_src_dir=${picosource_source_dir}/thirdlib


function compile_libevent() {
   cd ${deps_src_dir}/libevent
   mkdir -p build
   cd build && cmake  -G "Unix Makefiles" -D CMAKE_INSTALL_PREFIX=${picosource_source_dir}/experiment/build ..
   make
   make install
}


compile_libevent

#cmake -D CMAKE_INSTALL_PREFIX=/your/desired/install/directory ..