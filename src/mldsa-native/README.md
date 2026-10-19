[//]: # (SPDX-License-Identifier: CC-BY-4.0)

# mldsa-native source tree

This is the main source tree of mldsa-native.

## Building

To build mldsa-native for a fixed parameter set (ML-DSA-44/65/87), build the compilation units in `src/*` separately, and link to an RNG and your application. See [examples/basic](../examples/basic) for a simple example.

Alternatively, you can use the auto-generated helper files [mldsa_native.c](mldsa_native.c) and [mldsa_native_asm.S](mldsa_native_asm.S), which bundle all *.c and *.S files together. See [examples/monolithic_build](../examples/monolithic_build) and [examples/monolithic_build_native](../examples/monolithic_build_native) for examples without and with native code.

## Configuration

The build is configured by [mldsa_native_config.h](mldsa_native_config.h), or by the file pointed to by `MLD_CONFIG_FILE`. Note in particular `MLD_CONFIG_PARAMETER_SET` and `MLD_CONFIG_NAMESPACE_PREFIX`, which set the parameter set and namespace prefix, respectively.

## API

The public API is defined in [mldsa_native.h](mldsa_native.h).

## Supporting multiple parameter sets

If you want to support multiple parameter sets, build the library once per parameter set you want to support. Set `MLD_CONFIG_MULTILEVEL_BUILD` for all builds, `MLD_CONFIG_MULTILEVEL_WITH_SHARED` for one of them, and `MLD_CONFIG_MULTILEVEL_NO_SHARED` for the others, to avoid duplicating shared functionality. Finally, link with RNG and your application as before. This is demonstrated in the examples [examples/multilevel_build](../examples/multilevel_build), [examples/multilevel_build_native](../examples/multilevel_build_native), [examples/monolithic_build_multilevel](../examples/monolithic_build_multilevel) and [examples/monolithic_build_multilevel_native](../examples/monolithic_build_multilevel_native).
