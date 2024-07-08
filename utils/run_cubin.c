#include <cuda_runtime.h>
#include <stdio.h>
#include <cuda.h>

#define CUDA_CHECK(call) \
do { \
    cudaError_t err = call; \
    if (err != cudaSuccess) { \
        fprintf(stderr, "CUDA Error: %s at %s:%d\n", cudaGetErrorString(err), __FILE__, __LINE__); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

int main(int argc, char *args[]) {
    if (argc != 3) {
        printf("%s <cubin_path> <function_name>\n", args[0]);
        return 0;
    }

    CUDA_CHECK(cudaSetDevice(0));
    CUDA_CHECK(cuInit(0));

    CUmodule module;
    CUfunction kernel;

    CUDA_CHECK(cuModuleLoad(&module, args[1]));
    puts("module loaded");
    CUDA_CHECK(cuModuleGetFunction(&kernel, module, args[2]));

    int N = 32 * 4;
    // Allocate device memory for the array
    int *d_array;
    CUDA_CHECK(cudaMalloc((void**)&d_array, N * sizeof(int)));

    void *args[] = { &d_array };
    cuLaunchKernel(kernel, N, 1, 1, N, 1, 1, 0, 0, args, NULL);
    cuModuleUnload(module);

    int array[N];
    cudaMemcpy(array, d_array, N * sizeof(int), cudaMemcpyDeviceToHost);

    // Print the result
    for (int i = 0; i < N; ++i) {
        printf("%d ", array[i]);
    }
    printf("\n");

    return 0;
}
