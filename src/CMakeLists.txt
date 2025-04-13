add_executable(ollama_honeypot
        main.cpp
        # api/blob_handlers.cpp
        # api/generate_handlers.cpp
        api/misc_handlers.cpp
        api/model_handlers.cpp
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