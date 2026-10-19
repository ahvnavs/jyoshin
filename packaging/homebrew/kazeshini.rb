class Kazeshini < Formula
  desc "Server Truth Engine for Linux: Read-only, local-first inspection engine"
  homepage "https://github.com/OWNER/kazeshini"
  url "https://github.com/OWNER/kazeshini/archive/v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "Apache-2.0"
  head "https://github.com/OWNER/kazeshini.git", branch: "main"

  depends_on "go" => :build
  depends_on :linux

  def install
    ENV["CGO_ENABLED"] = "0"
    system "go", "build", *std_go_args(ldflags: "-s -w -X main.Version=v#{version}"), "./cmd/kazeshini"
  end

  test do
    output = shell_output("#{bin}/kazeshini --version")
    assert_match "kazeshini v#{version}", output
  end
end

