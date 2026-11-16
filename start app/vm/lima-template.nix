# Self-contained Lima 2.2.0 template for the launcher's own Linux VM (no `base`, so nothing from
# Lima's shipped `template:_default/mounts` or `_images/*` is inherited). macos_runtime.py adds the host
# architecture, the resources from vm.json and the locally verified image path before `limactl create`,
# then checks the effective configuration Lima reports before every boot.
{
  minimumLimaVersion = "2.2.0";
  vmType = "vz";
  os = "Linux";
  # Pinned Ubuntu 24.04 release images; macos_runtime.py verifies these digests before Lima sees a file.
  images = [
    {
      location = "https://cloud-images.ubuntu.com/releases/noble/release-20261017/ubuntu-24.04-server-cloudimg-arm64.img";
      arch = "aarch64";
      digest = "sha256:50e24e1fb79e89116e939d90aa7738f7af48c442fa1bc2510131e0b39c50348e";
    }
    {
      location = "https://cloud-images.ubuntu.com/releases/noble/release-20261017/ubuntu-24.04-server-cloudimg-amd64.img";
      arch = "x86_64";
      digest = "sha256:04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94";
    }
  ];
  # No host directory is ever shared with the guest; host files reach it only through the file broker.
  mounts = [ ];
  additionalDisks = [ ];
  networks = [ ];
  containerd = { system = false; user = false; };
  ssh = {
    localPort = 0;
    loadDotSSHPubKeys = false;
    forwardAgent = false;
    forwardX11 = false;
    forwardX11Trusted = false;
  };
  # First match wins. Lima fills guestIPMustBeZero=true for a 0.0.0.0 rule unless told otherwise; false makes it
  # match every bound guest address, and the second rule also covers loopback, so no guest TCP or UDP
  # listener is ever published on the host. Only Lima's own SSH port is reachable.
  portForwards = [
    { guestIP = "0.0.0.0"; guestIPMustBeZero = false; proto = "any"; ignore = true; }
    { guestIP = "127.0.0.1"; proto = "any"; ignore = true; }
  ];
  propagateProxyEnv = false;
  upgradePackages = false;
  plain = false;
  nestedVirtualization = false;
  vmOpts.vz.rosetta = { enabled = false; binfmt = false; };
  audio.device = "";
  video.display = "none";
  hostResolver = { enabled = true; ipv6 = false; };
}
