# PacketSnorter
## Final Project for CPE 400
PacketSnorter is a simple implementation of a packet sniffer using the C++ library [libtins](https://libtins.github.io/).

The packet sniffer can be simply ran normally to begin sniffing in a filtered or unfiltered mode.

The other use of the application is to find all local devices connected to network and provide a list of those devices with their hardware addresses. This functionality makes use of ARP requests.

## Installation:
### Environment
This project was designed on a Linux environment.

If on Windows, it is recommended to install [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) and run the project through there.

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
