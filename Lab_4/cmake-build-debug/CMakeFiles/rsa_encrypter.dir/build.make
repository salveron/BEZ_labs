# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


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
CMAKE_COMMAND = /snap/clion/112/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /snap/clion/112/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/salveron/Documents/BEZ/lab4

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/salveron/Documents/BEZ/lab4/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/rsa_encrypter.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/rsa_encrypter.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/rsa_encrypter.dir/flags.make

CMakeFiles/rsa_encrypter.dir/rsa-encrypter.c.o: CMakeFiles/rsa_encrypter.dir/flags.make
CMakeFiles/rsa_encrypter.dir/rsa-encrypter.c.o: ../rsa-encrypter.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/salveron/Documents/BEZ/lab4/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/rsa_encrypter.dir/rsa-encrypter.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/rsa_encrypter.dir/rsa-encrypter.c.o   -c /home/salveron/Documents/BEZ/lab4/rsa-encrypter.c

CMakeFiles/rsa_encrypter.dir/rsa-encrypter.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/rsa_encrypter.dir/rsa-encrypter.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/salveron/Documents/BEZ/lab4/rsa-encrypter.c > CMakeFiles/rsa_encrypter.dir/rsa-encrypter.c.i

CMakeFiles/rsa_encrypter.dir/rsa-encrypter.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/rsa_encrypter.dir/rsa-encrypter.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/salveron/Documents/BEZ/lab4/rsa-encrypter.c -o CMakeFiles/rsa_encrypter.dir/rsa-encrypter.c.s

CMakeFiles/rsa_encrypter.dir/rsa-decrypter.c.o: CMakeFiles/rsa_encrypter.dir/flags.make
CMakeFiles/rsa_encrypter.dir/rsa-decrypter.c.o: ../rsa-decrypter.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/salveron/Documents/BEZ/lab4/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/rsa_encrypter.dir/rsa-decrypter.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/rsa_encrypter.dir/rsa-decrypter.c.o   -c /home/salveron/Documents/BEZ/lab4/rsa-decrypter.c

CMakeFiles/rsa_encrypter.dir/rsa-decrypter.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/rsa_encrypter.dir/rsa-decrypter.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/salveron/Documents/BEZ/lab4/rsa-decrypter.c > CMakeFiles/rsa_encrypter.dir/rsa-decrypter.c.i

CMakeFiles/rsa_encrypter.dir/rsa-decrypter.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/rsa_encrypter.dir/rsa-decrypter.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/salveron/Documents/BEZ/lab4/rsa-decrypter.c -o CMakeFiles/rsa_encrypter.dir/rsa-decrypter.c.s

# Object files for target rsa_encrypter
rsa_encrypter_OBJECTS = \
"CMakeFiles/rsa_encrypter.dir/rsa-encrypter.c.o" \
"CMakeFiles/rsa_encrypter.dir/rsa-decrypter.c.o"

# External object files for target rsa_encrypter
rsa_encrypter_EXTERNAL_OBJECTS =

rsa_encrypter: CMakeFiles/rsa_encrypter.dir/rsa-encrypter.c.o
rsa_encrypter: CMakeFiles/rsa_encrypter.dir/rsa-decrypter.c.o
rsa_encrypter: CMakeFiles/rsa_encrypter.dir/build.make
rsa_encrypter: CMakeFiles/rsa_encrypter.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/salveron/Documents/BEZ/lab4/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable rsa_encrypter"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/rsa_encrypter.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/rsa_encrypter.dir/build: rsa_encrypter

.PHONY : CMakeFiles/rsa_encrypter.dir/build

CMakeFiles/rsa_encrypter.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/rsa_encrypter.dir/cmake_clean.cmake
.PHONY : CMakeFiles/rsa_encrypter.dir/clean

CMakeFiles/rsa_encrypter.dir/depend:
	cd /home/salveron/Documents/BEZ/lab4/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/salveron/Documents/BEZ/lab4 /home/salveron/Documents/BEZ/lab4 /home/salveron/Documents/BEZ/lab4/cmake-build-debug /home/salveron/Documents/BEZ/lab4/cmake-build-debug /home/salveron/Documents/BEZ/lab4/cmake-build-debug/CMakeFiles/rsa_encrypter.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/rsa_encrypter.dir/depend

