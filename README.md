# OBS h8819 Source Plugin - Audio over Ethernet Source for REAC

## Introduction

This plugin provides audio source(s) from REAC, which is an audio-over-ethernet protocol developed by Roland.

Why h8819... This plugin captures packets whose EtherType is 0x8819.
An initial `h` is added to express that the hardware was made by the company at Hamamatsu, Japan.

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

## Prerequisite

This plugin is developed for hardware supporting REAC.
In addition to your PC running OBS, you need to have
- Dedicated Ethernet adapter on your PC for REAC connection.
  You should not share your LAN with REAC. That means two ethernet ports are required for streaming.
- REAC supported device.
  Currently only M-200i is tested with this plugin.

## Configuring as a global audio device

The source type of the global audio devices is hard-coded in OBS Studio.
You have to edit your scene collection file.

Instruction below is made for Linux.
For macOS user, replace `~/.config/obs-studio/` with `~/Library/Application Support/obs-studio/`.

Before start editing, add a default audio source on OBS Studio and exit OBS Studio.

At first, find your scene collection file and format it to be edited easily.
Below is an example. If you have changed your scene collection name, the file name will differ.
At the same time, take a backup file `scene-backup.json`.
```
python3 -mjson.tool ~/.config/obs-studio/basic/scenes/Untitled.json > scene.json
cp scene.json scene-backup.json
```

Then, open the file `scene.json` by your editor and find an entry named `AuxAudioDevice1`.
Edit `id`, `settings`, `versioned_id` as below (`+` indicates a new line, `-` indicates a removed line).
```patch
     "AuxAudioDevice1": {
         "balance": 0.5,
         "deinterlace_field_order": 0,
         "deinterlace_mode": 0,
         "enabled": true,
         "flags": 0,
         "hotkeys": {
             "libobs.mute": [],
             "libobs.push-to-mute": [],
             "libobs.push-to-talk": [],
             "libobs.unmute": []
         },
-        "id": "pulse_input_capture",
+        "id": "net.nagater.obs-h8819-source.source",
         "mixers": 255,
         "monitoring_type": 0,
         "muted": false,
         "name": "Mic/Aux",
         "prev_ver": 453115907,
         "private_settings": {},
         "push-to-mute": false,
         "push-to-mute-delay": 0,
         "push-to-talk": false,
         "push-to-talk-delay": 0,
         "settings": {
-            "device_id": "default"
+            "channel_l": 7,
+            "channel_r": 8,
+            "device_name": "enp12s0"
         },
         "sync": 0,
-        "versioned_id": "pulse_input_capture",
+        "versioned_id": "net.nagater.obs-h8819-source.source",
         "volume": 1.0
     },
```
You might need to adjust `device_name` depending on your hardware configuration.

Finally, apply your change.
```
cp scene.json ~/.config/obs-studio/basic/scenes/Untitled.json
```

Just in case something went wrong, revert to your backup.
```
cp scene-backup.json ~/.config/obs-studio/basic/scenes/Untitled.json
```

## Properties

### Ethernet device
Specifies which ethernet device to be monitored.

To find the name of your ethernet device, run this command in terminal.
```
ifconfig -a
```
Then, choose your ethernet device. Usually it is named such as `enp2s0` or `en1`.

For macOS user, replace `en` with `bpf`. For example, the device name should be `bpf1` to capture `en1`.

### Channel L / R
Specify left and right channel to be captured.
Available range is 1 to 40.

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
