# COMPSEC300_PM
# Installation
## Precompiled
You can download one of the precompiled binaries from the 'Releases' section. There are currently two binaries provided:
- Binaries compiled on Windows 11
- Binaries compiled on Archlinux

To use binaries just extract the downloaded zip and run the executable from the commandline.\
Use
```./himitsu create <filename>```
and
```./himitsu open <filename>```
to get started.
## Building from source
### Building the program from source should be easy and painless.
1. Clone the repo\
```git clone https://github.com/k-um-i/COMPSEC300_PM.git```
2. Open the cloned folder\
```cd COMPSEC300_PM```
3. Install the go-webui dependency by following their instructions\
https://github.com/webui-dev/go-webui
4. Build the program
- Linux:
```go build -o himitsu main.go```
- Windows:
```go build -o himitsu.exe main.go```
### Possible issues with building
#### Requirements
First of all make sure you have golang installed.\
Note that compiling the program also requires a C-compiler since go-webui utilizes CGO.
#### invalid go version '1.24.1'
If you run into the ```invalid go version '1.24.1': must match format 1.23``` when compiling, you can circumvent this error by manually modifying the 'go.mod' file in the project directory.\
Manually change the go version inside go.mod from 1.24.1 to 1.24\
"go 1.24.1" -> "go 1.24"
