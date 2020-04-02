

if(${TARGET} STREQUAL "agent")

    # Generate enrollment library
    file(GLOB enrollfiles ${SRC_FOLDER}/enrollment/*.o ${SRC_FOLDER}/os_auth/ssl.o ${SRC_FOLDER}/os_auth/check_cert.o)

    add_library(ENROLLMENT_O STATIC ${enrollfiles})

    set_source_files_properties(
        ${enrollfiles}
        PROPERTIES
        EXTERNAL_OBJECT true
        GENERATED true
    )

    set_target_properties(
        ENROLLMENT_O
        PROPERTIES
        LINKER_LANGUAGE C
    )

    # Tests
    list(APPEND enrollment_test_names "test_enrollment_client")
    list(APPEND enrollment_test_flags "-Wl,--wrap=OS_IsValidIP,--wrap=_merror,--wrap=_mwarn,--wrap=check_x509_cert \
                                       -Wl,--wrap=_minfo,--wrap=OS_GetHost,--wrap=os_ssl_keys,--wrap=OS_ConnectTCP \
                                       -Wl,--wrap=SSL_new,--wrap=SSL_connect,--wrap=SSL_get_error,--wrap=SSL_set_bio")

    # Compilig tests
    list(LENGTH enrollment_test_names count)
    math(EXPR count "${count} - 1")
    foreach(counter RANGE ${count})
        list(GET enrollment_test_names ${counter} test_name)
        list(GET enrollment_test_flags ${counter} test_flags)

        add_executable(${test_name} ${test_name}.c)

        target_link_libraries(
            ${test_name}
            ENROLLMENT_O
            ${TEST_DEPS}
        )

        if(NOT test_flags STREQUAL " ")
            target_link_libraries(
                ${test_name}
                ENROLLMENT_O
                ${test_flags}
            )
        endif()
        add_test(NAME ${test_name} COMMAND ${test_name})
    endforeach()
endif()