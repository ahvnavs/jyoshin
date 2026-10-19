{ lib, buildGoModule, fetchFromGitHub }:

buildGoModule rec {
  pname = "kazeshini";
  version = "0.1.0";

  src = fetchFromGitHub {
    owner = "OWNER";
    repo = "kazeshini";
    rev = "v${version}";
    sha256 = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  };

  vendorHash = null;

  CGO_ENABLED = 0;

  ldflags = [
    "-s"
    "-w"
    "-X main.Version=v${version}"
  ];

  subPackages = [ "cmd/kazeshini" ];

  meta = with lib; {
    description = "Server Truth Engine for Linux: Read-only, local-first inspection engine";
    homepage = "https://github.com/OWNER/kazeshini";
    license = licenses.asl20;
    maintainers = [ ];
    platforms = platforms.linux;
  };
}

