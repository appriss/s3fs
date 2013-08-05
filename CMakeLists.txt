project(s3fs)

add_executable(s3fs main.cpp)

install(TARGETS s3fs RUNTIME DESTINATION bin)
