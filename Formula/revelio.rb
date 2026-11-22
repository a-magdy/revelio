class Revelio < Formula
  desc "Host-level dependency audit CLI for macOS and Linux"
  homepage "https://github.com/a-magdy/revelio"
  # Pinned by tag + commit over git rather than a release tarball + sha256:
  # GitHub's archive tarballs can only be hashed once the repo is public, and
  # the old sha256 here was the hash of a "Not Found" response. A git pin is
  # verifiable before and after the repo goes public.
  url "https://github.com/a-magdy/revelio.git",
      using:    :git,
      tag:      "v0.1.0",
      revision: "b6cd1b0b9a92708b9c1750389fee88ba1722591b"
  license "MIT"
  head "https://github.com/a-magdy/revelio.git", branch: "main"

  depends_on "bash"
  depends_on "jq"
  # `curl` ships with macOS; `git` (only required by `revelio publish`) ships
  # with the Xcode Command Line Tools.

  def install
    libexec.install "revelio.sh", "revelio.config.json", "lib"

    # Wrapper shim. Pins to brew bash 5 (revelio requires bash 4+, macOS ships
    # 3.2) and exports REVELIO_INVOCATION_PATH so the `schedule` subcommand
    # records this shim as the entrypoint in launchd/cron rather than the raw
    # libexec script.
    (bin/"revelio").write <<~SH
      #!/bin/bash
      export REVELIO_INVOCATION_PATH="${BASH_SOURCE[0]}"
      exec "#{Formula["bash"].opt_bin}/bash" "#{libexec}/revelio.sh" "$@"
    SH
    chmod 0755, bin/"revelio"
  end

  test do
    assert_match "revelio #{version}", shell_output("#{bin}/revelio --version")
    system bin/"revelio", "--help"
  end
end
