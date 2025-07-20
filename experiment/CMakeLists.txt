cmake_minimum_required(VERSION 3.13)
set(LIBEVENT_DIR ${PROJECT_SOURCE_DIR}/experiment/build)
find_package(LibEvent REQUIRED)
set(CMAKE_VERBOSE_MAKEFILE ON)

SET(EXPERIMENT_SOURCES
        server.c
        client.c
        common.c
)
add_library(experiment INTERFACE)
target_link_libraries(experiment INTERFACE picoquic-log)
target_link_libraries(experiment INTERFACE picoquic-core)
target_link_libraries(experiment INTERFACE ${LIBEVENT_LIBRARY})
target_include_directories(experiment INTERFACE ${LIBEVENT_INCLUDE_DIRS})
target_include_directories(experiment INTERFACE include)


add_executable(server_main
        server_main.c
        ${EXPERIMENT_SOURCES}
)
target_link_libraries(server_main PRIVATE experiment)

add_executable(client_main
        client_main.c
        ${EXPERIMENT_SOURCES}
        include/rpc.h
)
target_link_libraries(client_main PRIVATE experiment)

add_executable(my_test
        test/test_buffer.c
)
target_link_libraries(my_test PRIVATE experiment)



