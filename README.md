# Nvidia Instruction Set Specification Generator
This is a project for automatically generating instruction set specifications for NVIDIA GPUs by fuzzing the nvdisasm program included in Cuda

Human readable ISA Spec for SM90a is [here](https://kuterdinel.com/nv_isa/).

## Credits
- Original parser based on [CuAssembler](https://github.com/cloudcores/CuAssembler) by cloudcores

- Cubin file generation for life range analysis is based on [TuringAs](https://github.com/daadaada/turingas) by Da Yan and `Yan, Da, et al. “Optimizing Batched Winograd Convolution on GPUs.” Proceedings of the 25th ACM SIGPLAN Symposium on Principles and Practice of Parallel Programming, Association for Computing Machinery, 2020, pp. 32–44. ACM Digital Library, https://doi.org/10.1145/3332466.3374520.`

- Original fuzzing algorithm based on `Zhang, Xiuxia, et al. “Understanding the GPU Microarchitecture to Achieve Bare-Metal Performance Tuning.” Proceedings of the 22nd ACM SIGPLAN Symposium on Principles and Practice of Parallel Programming, Association for Computing Machinery, 2017, pp. 31–43. ACM Digital Library, https://doi.org/10.1145/3018743.3018755.`

