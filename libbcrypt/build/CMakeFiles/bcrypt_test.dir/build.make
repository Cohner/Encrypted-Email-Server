# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 2.8

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list

# Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ubuntu/workspace/libbcrypt

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ubuntu/workspace/libbcrypt/build

# Include any dependencies generated for this target.
include CMakeFiles/bcrypt_test.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/bcrypt_test.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/bcrypt_test.dir/flags.make

CMakeFiles/bcrypt_test.dir/src/main.cpp.o: CMakeFiles/bcrypt_test.dir/flags.make
CMakeFiles/bcrypt_test.dir/src/main.cpp.o: ../src/main.cpp
	$(CMAKE_COMMAND) -E cmake_progress_report /home/ubuntu/workspace/libbcrypt/build/CMakeFiles $(CMAKE_PROGRESS_1)
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Building CXX object CMakeFiles/bcrypt_test.dir/src/main.cpp.o"
	/usr/bin/c++   $(CXX_DEFINES) $(CXX_FLAGS) -o CMakeFiles/bcrypt_test.dir/src/main.cpp.o -c /home/ubuntu/workspace/libbcrypt/src/main.cpp

CMakeFiles/bcrypt_test.dir/src/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/bcrypt_test.dir/src/main.cpp.i"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -E /home/ubuntu/workspace/libbcrypt/src/main.cpp > CMakeFiles/bcrypt_test.dir/src/main.cpp.i

CMakeFiles/bcrypt_test.dir/src/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/bcrypt_test.dir/src/main.cpp.s"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_FLAGS) -S /home/ubuntu/workspace/libbcrypt/src/main.cpp -o CMakeFiles/bcrypt_test.dir/src/main.cpp.s

CMakeFiles/bcrypt_test.dir/src/main.cpp.o.requires:
.PHONY : CMakeFiles/bcrypt_test.dir/src/main.cpp.o.requires

CMakeFiles/bcrypt_test.dir/src/main.cpp.o.provides: CMakeFiles/bcrypt_test.dir/src/main.cpp.o.requires
	$(MAKE) -f CMakeFiles/bcrypt_test.dir/build.make CMakeFiles/bcrypt_test.dir/src/main.cpp.o.provides.build
.PHONY : CMakeFiles/bcrypt_test.dir/src/main.cpp.o.provides

CMakeFiles/bcrypt_test.dir/src/main.cpp.o.provides.build: CMakeFiles/bcrypt_test.dir/src/main.cpp.o

# Object files for target bcrypt_test
bcrypt_test_OBJECTS = \
"CMakeFiles/bcrypt_test.dir/src/main.cpp.o"

# External object files for target bcrypt_test
bcrypt_test_EXTERNAL_OBJECTS =

bcrypt_test: CMakeFiles/bcrypt_test.dir/src/main.cpp.o
bcrypt_test: CMakeFiles/bcrypt_test.dir/build.make
bcrypt_test: libbcrypt.so.1.0.0
bcrypt_test: CMakeFiles/bcrypt_test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --red --bold "Linking CXX executable bcrypt_test"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/bcrypt_test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/bcrypt_test.dir/build: bcrypt_test
.PHONY : CMakeFiles/bcrypt_test.dir/build

CMakeFiles/bcrypt_test.dir/requires: CMakeFiles/bcrypt_test.dir/src/main.cpp.o.requires
.PHONY : CMakeFiles/bcrypt_test.dir/requires

CMakeFiles/bcrypt_test.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/bcrypt_test.dir/cmake_clean.cmake
.PHONY : CMakeFiles/bcrypt_test.dir/clean

CMakeFiles/bcrypt_test.dir/depend:
	cd /home/ubuntu/workspace/libbcrypt/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ubuntu/workspace/libbcrypt /home/ubuntu/workspace/libbcrypt /home/ubuntu/workspace/libbcrypt/build /home/ubuntu/workspace/libbcrypt/build /home/ubuntu/workspace/libbcrypt/build/CMakeFiles/bcrypt_test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/bcrypt_test.dir/depend
