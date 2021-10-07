---
title: Quick Start Guide
---

## Description

<div class="intro-container">
<div style="width: 100%">
This guide is meant to enable you to quickly create a working setup for testing
the Midas kernel on either a real machine, or on QEMU.

<p>
Check out a <a href="{{ '/imgs/ae.img' | relative_url }}">sample disk image</a>
for artefact evaluation.
</p>
</div>
</div>

## Running the disk image

You can run either a virtual machine or a real machine with this disk image.
We shortly describe the necessary steps below.

### Contents of disk image

The disk image contains one ~50GB partition holding Ubuntu with various
kernels installed.
There is one user `midas` with password `midas`, who also has superuser
rights.
All useful files are stored in this user's home directory `/home/midas`.

Contained files:

- Cloned source code for Midas kernel `~/linux_midas`.
- Cloned exploit for CVE-2016-6516 in `~/CVE-2016-6516-exploit`.
- Installed Phoronix Test Suite and particular workloads.
- Scripts for running useful tasks in `~/scripts`.
    1. run exploit CVE-2016-6516 (`run_cve_exploit.sh`)
    2. run OSBench microbenchmarks (`run_ubench.sh`)
    3. run NPB benchmarks
    4. run PTS benchmarks  (`run_phoronix.sh`)
    5. setup machine frequency (`setup_machine`)

The `setup_machine` is appended to bashrc, and is run whenever a terminal
is opened. 
Its source can be found in `scripts/setup_machine.c`. 
Remember to set it up as a root setuid program if you recompile it.
This binary does the following:

- Set constant frequency for CPU (does not work for VMs)
- Disable kernel pointer obfuscation
- Enable perf recording for kernel
- Enable printk in logs

### Running a QEMU virtual machine

```
qemu-system-x86_64                   \
  -m 4G                              \
  -cpu host                          \
  -machine type=q35,accel=kvm        \
  -smp 4                             \
  -drive format=raw,file=ae.img      \
  -display default                   \
  -vga virtio                        \
  -show-cursor                       \
  -bios /usr/share/ovmf/OVMF.fd      \
  -net user,hostfwd=tcp::2222-:22    \
  -net nic
```

The above command sets up a machine with:

- 4GB memory
- same CPU as the host
- a modern platform, accelerated with kvm
- 4 CPU cores
- the provided image `ae.img`
- a default display
- firmware allowing booting a UEFI disk
- a network (host port 2222 forwards to guest port 22)

### Running on hardware

The disk image is provided as a raw, sparse image. You can run this
image on real hardware by writing the image to a HDD/SSD then booting
from that disk.

dd command: `dd if=ae.img of=/dev/<disk> bs=100M`

You will require a machine with:

- a reasonably recent Intel CPU (e.g. i7-8700)
- 1TB disk
- UEFI boot enabled
- Secure boot disabled

### Grub menu

When starting a machine with this disk image, the following options should
appear on the GRUB menu during booting:

- `Ubuntu default` is the default kernel shipped with Ubuntu
  (linux-5.11.0-37-generic) and can be used as the baseline
- `baseline` is mainline 5.11 kernel without Midas' modifications.
  Generated from commit 3cd88530ea3a55218099e60c7f0df7ee5ccdffe2
- `midas` is the Midas kernel based on 5.11.
  Generated from commit acfbfde5dd74b6c08efbf1aa16389fad41b61170
- `baseline-cve` is the baseline kernel with modifications detecting
  exploitation of CVE-2016-6516.
  Generated from commit a93186e3babbd4cbeb500559428062595b7c668b
- `midas-cve` is the midas kernel with modifications detecting
  exploitation of CVE-2016-6516.
  Generated from commit 9088ea808c171b013bd16707e1cc550268cb3c60

For each kernel version, we have generated it with the following
steps and commands:

1. Checkout code version `git checkout <hash>`
2. Compile kernel `make -j`
3. Install kernel modules (run as sudo)
   `make modules_install` and
4. Strip unnecessary symbols (run as sudo).
   `find /lib/modules/5.11.0<version> -iname "*.ko" -exec strip --strip-unneeded {} +`
5. Install kernel and update grub `make install`

## Testing and running artefact

In this tutorial, we will guide you through running the Midas kernel,
and provided related information.
The following experiments are described:

- How to run tests checking protection against CVE-2016-6516 as described in
  the paper.
- How to run the microbenchmarks reported in the paper
- How to run the Phoronix Test Suite benchmarks reported in the paper

### Testing protection against CVE-2016-6516

We demonstrate how the baseline kernel is vulnerable to this
double-fetch CVE, but the Midas kernel is not. The kernel setup
is described in more detail in the paper (section "Evaluation").

First, we list the steps necessary to trigger the bug on the
baseline kernel.

1. Restart the machine
2. In the GRUB menu, choose the 'baseline-cve' option.
3. Log in at the welcome screen
4. Open a terminal and run `~/scripts/run_cve_exploit.sh`.
5. Run `sudo dmesg` and check the output
6. Check that the output contains "Triggered bug: CVE-2016-6516!"

Next, test the Midas kernel. Follow steps 1-5, changing step 2
to choose the 'midas-cve' option.
In step 6, the bug trigger message should be absent from the output.

### Phoronix Test Suite benchmarks

Running these benchmarks is meaningful only on real hardware, not in a VM.

You will need to repeat the following steps for the baseline kernel, and
for the midas kernel.
After both runs, you should be able to compute relative performance.
Note that some benchmarks (pybench, git, linux build) report the time for
a run, and for others it reports operations per unit time
(openssl, redis, apache, nginx, ipc).

1. Restart the machine
2. In the GRUB menu, choose the `baseline` or `midas` option.
3. Log in at the welcome screen
4. Open a terminal and run `~/scripts/run_phoronix.sh`.
5. Optionally, choose to save the results to a file
6. Provide the below options when prompted for:
    - For Redis choose options 1,2
    - For IPC, choose option 4 then option 1

Phoronix will print the benchmark results to the terminal.

