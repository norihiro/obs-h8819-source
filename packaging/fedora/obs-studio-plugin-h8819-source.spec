Name: obs-studio-plugin-h8819-source
Version: @VERSION@
Release: @RELEASE@%{?dist}
Summary: h8819 source plugin for OBS Studio
License: GPLv3+

Source0: %{name}-%{version}.tar.bz2
Patch0: obs-studio-plugin-h8819-source-libexec.patch
BuildRequires: cmake, gcc, gcc-c++
BuildRequires: obs-studio-devel
BuildRequires: libpcap-devel

%description
This plugin captures audio packets from REAC, which is an audio-over-ethernet protocol developed by Roland,
and provides the audio as sources on OBS Studio.

%prep
%autosetup -p1

%build
%{cmake} -DLINUX_PORTABLE=OFF -DCMAKE_SKIP_RPATH:BOOL=ON
%{cmake_build}

%install
%{cmake_install}

%files
%{_libdir}/obs-plugins/*.so
%{_datadir}/obs/obs-plugins/*/
%{_libexecdir}/obs-h8819-proc
%license LICENSE

%post
setcap cap_net_raw=eip %{_libexecdir}/obs-h8819-proc
