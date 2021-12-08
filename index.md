---
title: Home
---

# Midas: Systematic Kernel TOCTTOU Protection

Midas systematically protects operating system kernels from data-race 
bugs (for example, *Time-Of-Check-To-Time-Of-Use* bugs) while accessing 
userspace data without intrusive, kernel-wide code changes. 

We have implemented Midas' protection on Linux. 
The source code is publicly available at the 
[GitHub repository](https://github.com/HexHive/midas).
Midas' prototype supports desktop distributions, and works with
existing kernel modules with no changes.

For more details, read the 
[paper](https://www.usenix.org/conference/usenixsecurity22/presentation/bhattacharyya).

## Citing Midas

Midas' pre-publication for the 31st Usenix Security Symposium 2022
may be cited as per the BibTex citation below.

```
@inproceedings {Bhattacharyya:2022:Midas,
author = {Atri Bhattacharyya and Uros Tesic and Mathias Payer},
title = {Midas: Systematic Kernel {TOCTTOU} Protection},
booktitle = {31st USENIX Security Symposium (USENIX Security 22)},
year = {2022},
address = {Boston, MA},
url = {https://www.usenix.org/conference/usenixsecurity22/presentation/bhattacharyya},
publisher = {USENIX Association},
month = aug,
}
```
