{pkgs}: {
  deps = [
    pkgs.portaudio
    pkgs.ffmpeg-full
    pkgs.postgresql
    pkgs.openssl
  ];
}
