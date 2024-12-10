{pkgs}: {
  deps = [
    pkgs.libev
    pkgs.iana-etc
    pkgs.rustc
    pkgs.pkg-config
    pkgs.libxcrypt
    pkgs.libiconv
    pkgs.cargo
    pkgs.ffmpeg
    pkgs.portaudio
    pkgs.ffmpeg-full
    pkgs.postgresql
    pkgs.openssl
  ];
}
