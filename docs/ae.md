---
title: Artifact Evaluation Guide
---

### Description

<div class="intro-container">
<div style="width: 100%">
This guide is meant to enable you to quickly create a working setup for testing
the Midas kernel on either a real machine, or on QEMU.

<p>
Download the compressed disk image
<a href="https://zenodo.org/record/5753026">here.</a>
</p>
</div>
</div>

### Running the disk image

You can run either a virtual machine or a real machine with this disk image.
We shortly describe the necessary steps below.

#### Contents of disk image

The provided download is the compressed disk image.
This must be uncompressed before following the rest of this guide.
The following command will uncompress the file and provide a progress
indicator. 
This step can take an hour or two, so go take a stroll in the meantime.
Using more threads might help speed it up.

```
pv ae.img.xz | unxz -T <num threads> > ae.img
```

> Note: `pv` essentially provides the functionality of `cat`, but also 
  provides a handy progress bar. You can replace any instance of `pv`
  in this guide with `cat`.

The disk image contains one ~50GB partition holding Ubuntu with various
kernels installed.
There is one user `midas` with password `midas`, who also has superuser
rights.
All useful files are stored in this user's home directory `/home/midas`.

Contained files:

- Cloned source code for Midas kernel `~/linux_midas`.
- Cloned exploit for CVE-2016-6516 in `~/CVE-2016-6516-exploit`.
- Downloaded and build NPB in `~/NPB3.4.2`.
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

#### Running a QEMU virtual machine

The following command was tested with QEMU version 4.2.1
available on Ubuntu 20.04. 
Some of the options appear to be unavailable on an 
older version (v2.3).


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
- firmware allowing booting a UEFI disk (`OVMF.fd`)
- a network (host port 2222 forwards to guest port 22)

Note: If your computer complains about not having OVMF.fd, you 
need to install the OVMF package for your distribution. 
On Ubuntu, this is as easy as running 
`sudo apt install ovmf`.

#### Running on hardware

The disk image is provided as a raw, sparse image. You can run this
image on real hardware by writing the image to a HDD/SSD then booting
from that disk.

You will require a machine with:

- a reasonably recent Intel CPU (e.g. i7-8700)
- 1TB disk

First, enter the BIOS of the target machine, and make sure its using
UEFI boot mode.
Then disable the "Secure Boot" option.

Then boot from a Live USB. 
In this state, the default machine runs off the USB, and the hard disk
is not in use.
Now, you can copy the image to the actual disk.
First, download the disk image and extract it as explained above.
Then find the (1TB) disk you want to write the image to. 
If it is a hard disk, it might have a name such as `/dev/sda` or 
`/dev/sdb`. 
If it is a NVMe SSD, it might have a name such as `/dev/nvme0n1`.
Then copy the image to the correct disk using the following `dd` command.

```dd if=ae.img of=/dev/<disk> bs=100M```

> Note: You can combine the image uncompression operation and the 
write to disk by running the following command

``` pv ae.img.xz | unxz -T <num threads> | dd of=/dev/<disk>```

After the disk image has been written to the disk, reboot the machine.
During boot, make sure that you are booting from the disk you just
wrote to.
If you have more than one disk in the machine, you can choose to boot
from a particular disk by editing your BIOS options.

#### Grub menu

When starting a machine with this disk image, the following options should
appear on the GRUB menu during booting:

- `Ubuntu default` is the default kernel shipped with Ubuntu
  (linux-5.11.0-37-generic) and can be used as the baseline
- `baseline` is mainline 5.11 kernel without Midas' modifications.
  Generated from commit `3cd88530ea3a55218099e60c7f0df7ee5ccdffe2`
- `midas` is the Midas kernel based on 5.11.
  Generated from commit `acfbfde5dd74b6c08efbf1aa16389fad41b61170`
- `baseline-cve` is the baseline kernel with modifications detecting
  exploitation of CVE-2016-6516.
  Generated from commit `a93186e3babbd4cbeb500559428062595b7c668b`
- `midas-cve` is the midas kernel with modifications detecting
  exploitation of CVE-2016-6516.
  Generated from commit `9088ea808c171b013bd16707e1cc550268cb3c60`

> Note: Once booted, you can use the command `uname -r` to see the 
  currently running kernel version. 

The disk image also contains a clone of the git repository with
Midas' code (at `~/linux_midas`).
For verifying our installed kernels, you may re-compile and re-install
each of the kernels.
For each kernel version, we have generated it with the following
steps and commands.
Note, this is not a necessary step. 
We have already followed these instructions and installed the kernels.

1. Checkout code version `git checkout <hash>`
2. Compile kernel `make -j`
3. Install kernel modules (run as sudo)
   `make modules_install` and
4. Strip unnecessary symbols (run as sudo).
   `find /lib/modules/5.11.0<version> -iname "*.ko" -exec strip --strip-unneeded {} +`
5. Install kernel and update grub `make install`

### Testing and running artifact

In this tutorial, we will guide you through running the Midas kernel,
and provided related information.
The following experiments are described:

- How to run tests checking protection against CVE-2016-6516 as described in
  the paper.
- How to run the microbenchmarks reported in the paper
- How to run the NPB reported in the paper
- How to run the Phoronix Test Suite benchmarks reported in the paper

There is a faster, almost push-button way to run the performance benchmarks.
The steps to do so are:

1. Restart the machine
2. In the GRUB menu, choose the `baseline` option.
3. Run all benchmarks by running the script 
   `~/scripts/run_all_benchmarks.sh baselog`. 
   The first argument `baselog` specifies the file where the results of 
   the run is stored.
4. Restart the machine, this time choosing the `midas` option.
5. Run the benchmarks again, but specify a different log-file name.
   `~/scripts/run_all_benchmarks.sh midaslog`.
6. Now run the script to plot the relative performance of `midas` compared
   to the baseline: `~/scripts/generate_graphs.py baselog midaslog`.
   Note how we provide the log files from the two runs. This script outputs
   Figure 9 from the paper, storing it in `midas_performance.pdf`.
   
#### Testing protection against CVE-2016-6516

We demonstrate how the baseline kernel is vulnerable to this
double-fetch CVE, but the Midas kernel is not. The kernel setup
is described in more detail in the paper (section "Evaluation").

First, we list the steps necessary to trigger the bug on the
baseline kernel.

1. Restart the machine
2. In the GRUB menu, choose the 'baseline-cve' option.
3. Log in at the welcome screen
4. Open a terminal and run `~/scripts/run_cve_exploit.sh`.
   This can take a few minutes.
5. At the same time, run `watch -n1 'sudo dmesg | tail'` and check the output
6. Check that the output contains "Triggered bug: CVE-2016-6516!".
   Usually, you should see the first trigger message within a few seconds.
   A run usually also prints this message around 10 times.

Next, test the Midas kernel. Follow steps 1-5, changing step 2
to choose the 'midas-cve' option.
In step 6, the bug trigger message should be absent from the output.

#### Microbenchmarks

Running these benchmarks is meaningful only on real hardware, not in a VM.

> Note: We use the OSBench version available with Phoronix, since it 
  provides us an easy interface to see and compare test results.

You will need to repeat the following steps for the baseline kernel, and
for the midas kernel.
After both runs, you should be able to compute relative performance.
The benchmarks report performance as execution time per operation for
each workload.

1. Restart the machine
2. In the GRUB menu, choose the `baseline` or `midas` option.
3. Log in at the welcome screen
4. Open a terminal and run `~/scripts/run_ubench.sh`.
5. Choose option 6 to run all tests when prompted.
6. Optionally, follow the prompts to save the test results to file.
   Results are stored in `~/.phoronix-test-suite/test-results`.

The OSBench microbenchmarks are nicely packaged into a OpenBenchmarks
workload on Phoronix.
The microbenchmark will print their results to the terminal.
Make a note of the results, to be able to compare between runs.

#### Phoronix Test Suite benchmarks

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
5. Provide the below options when prompted for:
    - For Redis choose options 1,2
    - For IPC, choose option 4 then option 1
6. Optionally, follow the prompts to save the test results to file.

Phoronix will print the benchmark results to the terminal.

#### NASA Parallel Benchmarks

Running these benchmarks is meaningful only on real hardware, not in a VM.

You will need to repeat the following steps for the baseline kernel, and
for the midas kernel.
After both runs, you should be able to compute relative performance.
The benchmarks report performance as Mop/s for each workload.

1. Restart the machine
2. In the GRUB menu, choose the `baseline` or `midas` option.
3. Log in at the welcome screen
4. Open a terminal and run `~/scripts/run_npb.sh`.

NPB will print the benchmark results to the terminal.

#### Nginx case study

To recreate the case-study with Nginx, you will need a
second machine (hereafter called load-generator) connected to the
`midas` machine (hereafter called server-machine).
The Nginx webserver will run on the `midas` machine, and is already
installed on the image (v1.18).
Connect the load-generator to the server-machine with a ethernet
connection.
For consistency with the paper, a 1Gbps wired ethernet connection
is preferred.
Make sure that the machines each have an IP address allocated, and
that they can communicate.

We assume that the load-generator is running a linux-based OS, but
it is not necessary.
We can download the load-generating program `bombardier` from its
<a href="https://github.com/codesenberg/bombardier/releases">GitHub page .</a>
Download the version relevant for this machine's OS and architecture.
Make the file executable by running `chmod u+x bombardier-<version>`.

To prepare the server-machine, we need to correctly configure Nginx
and set up the test files.

- We can configure Nginx by updating the file `/etc/nginx/nginx.conf`.
  We change the contents of the config file to that shown below.
  Note that the config currently specifies that `nginx` uses one worker.
  As per the experiment, change this number to the number of cores on
  your server-machine.
  To run `nginx` with this configuration, restart the server by running
  `sudo nginx -s reload`.
- Note that the config specifies `/etc/nginx/html` as the directory
  holding the html files to serve.
  Create files of size 20B, 50B, 100B, 200B, 500B, 1000B, 2000B, 5000B
  and 10000B in this folder by running the following command.
  We will fetch these files during testing.

```
for len in {20,50,100,200,500,1000,2000,5000,10000} ; do dd if=/dev/zero of=/etc/nginx/html/$len.html bs=1 count=$len ; done
```
  

```
worker_processes  1;

events {
    worker_connections  1024;
}

http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;

    server {
        listen       8088;
        server_name  localhost;

        location / {
            root   /etc/nginx/html;
            index  index.html index.htm;
        }
    }
}
```

To run the test, first set the number of worker processes to 1 in 
the config file, then run the load generator with the following command.
In this command, make sure to put the correct name of the `bombardier`
executable, and the server-machine's IP address.
Note the port number `8088` is set in the server's configuration.
This command will print the request-per-second and throughput statistic
to the terminal.

```
for len in {20,50,100,200,500,1000,2000,5000,10000} ; do ./bombardier-<version> -c 100 -d 30s <server-machine IP>:8088/$len.html ; done
```

Repeat the above experiment after setting the number of worker
processes in the config file to the number of cores on the server-machine.
Remember to reload Nginx with the new configuration.

### Known bugs/pitfalls

- An occasional bug leads to lingering protections on a page.
  This triggers a check in `midas`'s code.
  The kernel logs will contain the following lines.
  Restart the machine when you encounter this bug.

```
[  sss.uuuuuu] ------------[ cut here ]------------
[  sss.uuuuuu] kernel BUG at arch/x86/kernel/uaccess.c:173!
...
[  sss.uuuuuu] RIP: 0010:page_unmark_one+0xe1/0xf0
```

- The kernel might occasionally hang on a spinlock.
  The kernel logs contain the following message.
  Restart the machine when you encounter this bug.

```
BUG: soft lockup - CPU#xx stuck for xxs! 
```
