{pkgs}: {
  deps = [
    pkgs.libev
    pkgs.iana-etc
    pkgs.ffmpeg
    pkgs.portaudio
    pkgs.ffmpeg-full
    pkgs.postgresql
    pkgs.openssl
  ];
}
