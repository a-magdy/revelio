class Revelio < Formula
  desc "Host-level dependency audit CLI for macOS and Linux"
  homepage "https://github.com/a-magdy/revelio"
  url "https://github.com/a-magdy/revelio/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "0019dfc4b32d63c1392aa264aed2253c1e0c2fb09216f8e2cc269bbfb8bb49b5"
  # NOTE: `license` stanza intentionally omitted until a LICENSE file lands
  # upstream (tracked in docs/LAUNCH.md). `brew audit --strict` will warn but
  # not fail.

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
    assert_match "revelio 0.1.0", shell_output("#{bin}/revelio --version")
    system bin/"revelio", "--help"
  end
end
