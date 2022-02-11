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
either expressed or implied and the plugin is to be used at your own risk.
The author of this plugin has no relationship with Roland.
Do not ask Roland for support of this plugin.

## Properties

### Ethernet device
Specifies which ethernet device to be monitored.

### Channel L / R
Specify left and right channel to be captured.

## See also

- [reacdriver](https://github.com/per-gron/reacdriver)
