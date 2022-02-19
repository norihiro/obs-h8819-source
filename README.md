# OBS h8819 Source Plugin - Audio over Ethernet Source for REAC

## Introduction

This plugin provides audio source(s) from REAC, which is an audio-over-ethernet protocol developed by Roland.

Why h8819... This plugin captures packets whose EtherType is 0x8819.
An initial `h` is added to express that it was made by the company at Hamamatsu, Japan.

## Tested device

This plugin was developed and tested with Roland M-200i with it's sampling frequency 48 kHz.

44.1 kHz sampling frequency is not currently supported since the sampling frequency is hard-coded to 48 kHz.
To use this plugin, you have to set the sampling frequency of the REAC device to 48 kHz.
(Still you can set any sampling frequency on OBS Studio.)

## Disclaimer

This plugin is provided "as is" without warranty of any kind,
either expressed or implied, and the plugin is to be used at your own risk.
The author of this plugin has no relationship with Roland.
Do not ask Roland for support of this plugin.

## Properties

### Ethernet device
Specifies which ethernet device to be monitored.

To find the name of your ethernet device, run this command in terminal.
```
ifconfig -a
```
Then, choose your ethernet device. Usually it is named such as `enp2s0` or `en1`.

### Channel L / R
Specify left and right channel to be captured.

## Build and install
### Linux
Use cmake to build on Linux. After checkout, run these commands.
```
sed -i 's;${CMAKE_INSTALL_FULL_LIBDIR};/usr/lib;' CMakeLists.txt
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
make
sudo make install
```
During install, `setcap` will be called to enable packet capture.

### macOS
Build flow is similar to that for Linux.

After install, you need to set permission to capture raw packets. For example,
```
sudo chmod og+rw /dev/bpf1
```
Note that `bpf1` should be adjusted depending on your ethernet device to capture.
To get the BPF device name, replace `en` with `bpf` in your ethernet device name.

## Log file
This plugin will periodically output log lines like below.
If there are dropped packets, you should adjust your computer settings or connection, or just insufficient hardware performance.
```
h8819[enp2s0] current status: 262144 packets received, 0 packets dropped
```

OBS Studio might leave a log saying adding audio buffering like below.
If the amount is around 50 milliseconds or less, it should be all right.
If the amount keeps increasing, something is wrong.
```
adding 42 milliseconds of audio buffering, total audio buffering is now 42 milliseconds
```

## See also

- [reacdriver](https://github.com/per-gron/reacdriver) - The format of the packet was taken from this implementation.
- [reaccapture](https://github.com/norihiro/reaccapture) - Standalone implementation to convert the packet to wave file.
