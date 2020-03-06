# Unit Tests
## Index
1. [Requirements](#requirements)
2. [Compile Wazuh](#compile\ wazuh)
3. [Compile and run unit tests for Linux targets](#Compile\ and\ run\ unit\ tests\ for\ Linux\ targets)
4. [Compile and run unit tests for Windows agent](#Compile\ and\ run\ unit\ tests\ for\ Windows\ agent)
5. [Installing CMake](#Installing\ CMake)
6. [Installing cmocka](#Installing\ cmocka)
7. [Intalling wine](#Installing\ wine)

## Requirements:
1. Compiling tools (GCC and/or mingw)
2. CMake (version 3.10 or higher)
3. Wine (For executing winagent tests)
4. CMocka (C Unit Testing Framework)

Additional dependencies can be installed on Ubuntu by running the following commands.
```
sudo apt-get update -y
sudo apt-get install -y gcc-mingw-w64 nsis make python gcc g++ cmake libc6-dev curl policycoreutils automake autoconf libtool libssl-dev lcov
```

## Compile Wazuh
In order to run unit tests on a specific wazuh target, the project needs to be built with the `DEBUG` and `TEST` options as shown below:
```
make TARGET=server|agent|winagent DEBUG=1 TEST=1
```

## Compile and run unit tests for Linux targets
In order to run unit tests for either the Wazuh server or Linux agents, these need to be built using [CMake](#installing\ cmake) version 3.10 or higher and [cmocka](#installing\ cmocka).

Navigate into `wazuh/src/unit_tests` and run the following commands:
```
mkdir build
cd build
cmake -DTARGET=server|agent ..
make
```
Notice that when running the cmake command we need to specify the target on which we will run the unit tests, this target needs to match the wazuh target used for compilation and wazuh needs to be previously compiled.

There are several ways to run unit tests:

### Batch run
In order to run all unit tests and get a global result for all of them you can run the `ctest` command inside the `build` directory. CTest will run all available tests and display their results on the console. If more details on the tests are required, you can inspect the `LastTest.log` located inside `build/Testing/Temporary` after running this command.

### Coverage run
You can get a coverage report from the unit tests run by running `make coverage` inside the `build` directory. Tests will be run and if they all pass a `coverage-report` directory will be created with an html report.

### Running a specific test
In case you need to run a specific test, navigate into the subdirectory where the test resides and run it as you would any other Linux binary. As an example, if you want to run tests on `create_db.c`
```
cd syscheckd
./test_create_db
```
The output of the test will be written directly into the console.

## Compile and run unit tests for Windows agent
Similarly to compiling unit tests for server or Linux agent configurations, [CMake](#installing\ cmake) 3.10 or higher and [cmocka](#installing\ cmocka) are required, as well as a 32 bit [wine installation](#installing\ wine) in order to run the tests.

Navigate into `wazuh/src/unit_tests` and run the following commands:
```
mkdir build
cd build
cmake -DTARGET=winagent -DCMAKE_TOOLCHAIN_FILE=../Toolchain-win32.cmake ..
make
```
Just as when compiling server and Linux agent unit tests, the winagent target for Wazuh must be compiled previously.

The `CMAKE_TOOLCHAIN_FILE` option is added so crosscompiling of the unit tests can be properly configured by cmake.

There are several ways to run the tests:

### Batch run
In order to run all unit tests and get a global result for all of them you can run the `ctest` command inside the `build` directory. CTest will run all available tests by using wine and display their results on the console. If more details on the tests are required, you can inspect the `LastTest.log` located inside `build/Testing/Temporary` after running this command.

### Coverage run
This option has not been tested yet on Windows agents and there is no guarantee it will work.

### Running a specific test
In case you need to run a specific test, navigate into the subdirectory where the test resides and run it by using wine. As an example, if you want to run tests on `create_db.c`
```
cd syscheckd
wine test_create_db.exe
```
The output of the test will be written directly into the console.

## Installing CMake
If installing cmake using `apt-get` or `yum` yields a version lower the 3.10, remove it and run these commands to install from sources.

```
mkdir ~/temp
cd ~/temp
wget https://cmake.org/files/v3.17/cmake-3.17.0-rc1.tar.gz
tar -xzvf cmake-3.17.0-rc1.tar.gz
cd cmake-3.17.0-rc1/
./bootstrap
make
sudo make install
```

## Installing cmocka
The cmocka unit tests framework is required in order to compile and run the Wazuh unit tests suite. For server and Linux agent tests, a binary installation of cmocka using a package manager is enough. If you want to run the Windows agent tests, you will need to build cmocka using the MinGW compiler.

1. Clone cmocka repository:
```
git clone https://git.cryptomilk.org/projects/cmocka.git
```

2. Modify `DefineOptions.cmake` file and set `BUILD_SHARED_LIBS` to `OFF`

3. Build CMocka by running the following commands inside the repository directory:
```
mkdir build
cd build
cmake -DCMAKE_C_COMPILER=i686-w64-mingw32-gcc -DCMAKE_C_LINK_EXECUTABLE=i686-w64-mingw32-ld -DCMAKE_INSTALL_PREFIX=/usr/i686-w64-mingw32/ -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_BUILD_TYPE=Release ..
make
sudo make install
```

If you need to build cmocka for the Linux targets, keep `BUILD_SHARED_LIBS` as `ON` and run the following commands
```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
sudo make install
```
If you need to rebuild cmocka, remember to remove all files from the `build` directory first.

## Installing wine
On Ubuntu, run the following commands:
```
# Add 32 bit architecture
sudo dpkg –-add-architecture i386
wget https://dl.winehq.org/wine-builds/Release.key
sudo apt-key add Release.key
sudo apt-add-repository 'https://dl.winehq.org/wine-builds/ubuntu/'
sudo apt update
sudo apt install wine-stable
# Link wine binary
sudo ln -s /opt/wine-stable/bin/wine /usr/bin/
```
If you need to run the tests on a CentOS 7 machine, you can follow these instructions in order to build a 32 bit wine: https://www.systutorials.com/239913/install-32-bit-wine-1-8-centos-7/

After installing wine, the `WINEPATH` and `WINEARCH` variables need to be created in order for it to know it should run on 32 bit mode and find all required dlls for the tests. On an Ubuntu system, the following commands need to be executed and/or added into the user's `.bashrc` file.
```
export WINEPATH="/usr/i686-w64-mingw32/lib;/path/to/wazuh/src"
export WINEARCH=win32
```
If wine complains about being a 64 bit installation, remove/rename the directory `~/.wine` and run it again.