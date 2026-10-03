# Copyright © 2026 Racpast. All Rights Reserved.
#
# This file is part of SNIBypassGUI, a proprietary software project.
#
# NOTICE: All information contained herein is, and remains the property of
# Racpast. The intellectual and technical concepts contained herein are
# proprietary to Racpast and are protected by copyright law and international
# treaties. Dissemination of this information or reproduction of this material
# is strictly forbidden unless prior written permission is obtained from Racpast.
#
# Unauthorized copying, modification, distribution, or use of this file,
# via any medium, is strictly prohibited.
#
# For licensing inquiries: snibypassgui@gmail.com or racpast@gmail.com
#
# See the LICENSE file in the project root for full terms and conditions.

# snib_core references the updater's work-order format (services.cpp writes a plan,
# client.cpp starts the module, module.cpp resolves the plan directory), so the
# protocol objects have to be linked in here too. The application links them for the
# same reason; this target did not, which left every Updater:: symbol unresolved and
# meant the suite could not be built at all.
add_executable(snib_tests
    test_core.cpp
    $<TARGET_OBJECTS:snib_core>
    $<TARGET_OBJECTS:snib_updater_protocol>)

target_link_libraries(snib_tests PRIVATE snib_core)

target_compile_options(snib_tests PRIVATE
    ${SNIB_WARNING_FLAGS}
    ${SNIB_CHARSET_FLAGS})

target_compile_definitions(snib_tests PRIVATE
    "SNIB_SOURCE_DIR=L\"${CMAKE_SOURCE_DIR}\"")

target_link_options(snib_tests PRIVATE -static -static-libgcc -static-libstdc++)

target_link_libraries(snib_tests PRIVATE
    ws2_32 wininet bcrypt crypt32 iphlpapi shell32 ole32 oleaut32 taskschd advapi32 secur32
    snib_sodium)

add_test(NAME core_tests COMMAND snib_tests)
