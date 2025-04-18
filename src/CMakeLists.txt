add_executable(ollama_honeypot
        main.cpp
        # api/blob_handlers.cpp
        # api/generate_handlers.cpp
        api/version.cpp
        api/tags.cpp
        api/delete.cpp
        api/show.cpp
        utils/config.cpp
        utils/fake_data.cpp
        utils/logging.cpp

        state/honeypot_state.cpp
)

target_compile_features(ollama_honeypot PRIVATE cxx_std_23)

target_include_directories(ollama_honeypot PRIVATE
        ../include/honeypot
)

target_link_libraries(ollama_honeypot PRIVATE
        Crow::Crow
        nlohmann_json::nlohmann_json
        spdlog::spdlog
        fmt::fmt
        tsl::robin_map

        Threads::Threads
)

if(WIN32)
    message(STATUS "Adding Windows specific libraries: ws2_32, mswsock")
    target_link_libraries(ollama_honeypot PRIVATE ws2_32 mswsock)
endif()

set(CONFIG_COPY_STAMP_FILE "${CMAKE_CURRENT_BINARY_DIR}/config_copy.stamp")

add_custom_command(
        OUTPUT ${CONFIG_COPY_STAMP_FILE}
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_SOURCE_DIR}/config"
        "${CMAKE_CURRENT_BINARY_DIR}/config"
        COMMAND ${CMAKE_COMMAND} -E touch ${CONFIG_COPY_STAMP_FILE}
        MAIN_DEPENDENCY "${CMAKE_SOURCE_DIR}/config"
        COMMENT "Copying config directory to build output sub-directory (if changed/missing)"
        VERBATIM
)

add_custom_target(ensure_runtime_config
        DEPENDS ${CONFIG_COPY_STAMP_FILE}
)

add_dependencies(ollama_honeypot ensure_runtime_config)