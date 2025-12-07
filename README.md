# PacketSnorter
## Final Project for CPE 400
PacketSnorter is a simple implementation of a packet sniffer using the C++ library [libtins](https://libtins.github.io/).

The packet sniffer can be simply ran normally to begin sniffing in a filtered or unfiltered mode.

The other use of the application is to find all local devices connected to network and provide a list of those devices with their hardware addresses. This functionality makes use of ARP requests.

### PacketSnorter Usage & Modes:
PacketSnorter's executable can simply be called by default or with modifiers to determine its functionality.

### Modes:
<img width="800" height="500" alt="Screenshot 2025-12-07 000753" src="https://github.com/user-attachments/assets/0b7e146c-c34a-4571-bd11-06f4f8a79b5d" /><br>
* Unfiltered: Starts the packet sniffer to capture any packet that is available to it. This is the default mode of the application and if there is any error with modifiers, it will default to unfiltered mode.
  
<img width="800" height="500" alt="Screenshot 2025-12-07 001122" src="https://github.com/user-attachments/assets/482771d2-1d6f-4096-b9ae-a90293df7cc4" /><br>
* Filtered: Same as the previous mode, but allows the usage of a filter to capture specific types of packets.
  
<img width="500" height="150" alt="Screenshot 2025-12-07 001157" src="https://github.com/user-attachments/assets/65d2c8bf-2bba-4f95-b99f-4973b16dac3d" /><br>
* ARP: The unique mode of this project, ARP mode will obtain the local networks subnet range and use that to send out ARP requests to any bound local devices. Any ARP replys will be processed and the hardware address of the device will be printed to the console. (!NOTE: The mode is not optimized and can run slowly on large subnets)

## Installation:
### Environment
This project was designed on a Linux environment.

If on Windows, it is recommended to install [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) and run the project through there. (Although results will be inaccurate due to [WSL network handling](https://learn.microsoft.com/en-us/windows/wsl/networking))

If unwilling to incorporate a Linux enviroment on your device, it is recommended to research into the [libtins](https://libtins.github.io/download/) library and find a way to install a valid instance of the library on your device and then find a way to compile the main.cpp file provided in this repo.

### Installing libtins on Linux
* First, update your Linux enviroment and make sure the build essentials are installed.
This is to make sure that the Linux environment has the GNU C++ compiler installed.
```
sudo apt update
sudo apt install build-essential   
```
* It is recommended to create a folder for your libtins installation in whatever location you desire.
```
mkdir libtins_SDK
cd libtins_SDK
```
* Compiling and installing libtins and its requirements,
```
sudo apt-get install libpcap-dev libssl-dev cmake
git clone https://github.com/mfontanini/libtins.git
cd libtins
mkdir build
cd build
cmake ../
make
sudo make install
```
* You can either run the below command to update your ld cache, or just restart your device as the process of restarting will also update it.
```
sudo ldconfig
```

### Installing PacketSnorter
Simple cloning the git repo and using makefile to setup executable,

```
git clone https://github.com/colbygram/PacketSnorter.git
cd PacketSnorter
make
```
 
## Usage:
Using the application simply requires a call to 
<br>```sudo ./SnortingPackets```
<br>**NOTE: you can not exit the application with user input through the application! To exit use ```CRTL + Z```**

### Mode Syntax:
Typical mode syntax would look like,
```sudo ./SnortingPackets <mode> <mode-modifier>```
* Examples: <br>
```sudo ./SnortingPackets f tcp``` captures only tcp packets using filtered mode<br>
```sudo ./SnortingPackets a``` selects ARP mode

## Project Notes:
* An important note is that this project was developed and tested in a WSL environment. In theory, the code base should work the same in any environment, but tests could not be completely accurate as WSL2 uses a NAT-based implementation for network handling, meaning the results are only accurate to the WSL environment due to the virtual ethernet adapter used and do not represent an actual Linux or Windows environment. Despite this, the project should work accurately in any environment as long as the setup steps are followed. I was unwilling to setup this project in an actual Windows environment due to the time contraint and the vastly different setup in Visual Studio. This project should still work properly in a normal Linux environment as WSL code compilation and error handling are the same, only the results will differ.

* My implementation of ARP request and even packet sniffing has much to be desired. In a better implementation, multithreading would be ideal for packet sniffing as a thread could manage packet capture and a packet queue, while another thread would process the packets, while another thread could handle user input. I acknowledge this limitation in my design, but believe it was out of scope for the project. I am stating this so it is clear that I do know that there are better methods for implementation, but it would only be an optimization and wouldn't change the actual functionality of the project. 

    Another optimization would be with the ARP requests. Ideally, it would be better to send out the ARP request to a broadcast address, opposed to individual addresses. Broadcasting the ARP request and then using a packet sniffer to listen for the ARP replies would be a more optimal solution, but without proper results due to WSL, I couldn't guarntee that my implementation of broadcasting was functioning properly. As stated before, this would only be an optimization however and would not change the current functionality of the project.
