# MemJect [![C](https://img.shields.io/badge/language-C-%23f34b7d.svg)](https://en.wikipedia.org/wiki/C) [![Windows](https://img.shields.io/badge/platform-Windows-0078d7.svg)](https://en.wikipedia.org/wiki/Microsoft_Windows) [![x86](https://img.shields.io/badge/arch-x86-red.svg)](https://en.wikipedia.org/wiki/X86) [![License](https://img.shields.io/github/license/fredwangwang/MemJect.svg)](LICENSE)
Simple dll injector designed to load dll from disk. Supports PE header and entry point erasure. Written in C99.

## Features

* load dll from dll file on disk
* erase DLLEntryPoint
* erase PE header

## Getting started

### Prerequisites
C99 compiler for Windows is required in order to compile MemJect. Microsoft Visual Studio is required to load solution for easy compilation (MemJect.sln).

### Cloning
The very first step in order to compile MemJect is to clone this repo from GitHub to your local computer. Git is required to step futher, if not installed download it [here](https://git-scm.com). Open git bash / git cmd / cmd and enter following command:
```
git clone https://github.com/fredwangwang/MemJect.git
```
`MemJect` folder should have been succesfully created, containing all the source files.

### Compiling from source

When you have equiped a copy of source code, next step is opening **MemJect.sln** in Microsoft Visual Studio. If you don't have Visual Studio, compile **MemJect.cpp** using your compilator.

Find below line in **MemJect.cpp** and replace **csgo.exe** with your destination process name:
```c
#define PROCESS_NAME "csgo.exe"
```

Then change build configuration to `Release | x86` and simply press **Build solution**.

If everything went right you should receive `MemJect.exe` binary file.
