# Bridge docker setup

For all images, build from the strata-bridge directory with:

```sh
docker build -f docker/<dockerfile> .
```

Layout:
- `Dockerfile`: base image used to build the other images.


## Base image

- x86 ubuntu 24.04 image based on succinct's SP1 image
- SP1 toolchain installed
- Bridge toolchain installed
- External dependencies compiled
- Internal dependencies (`crates` dir) compiled

Build using:

```sh
docker build -f docker/base.Dockerfile . -t bridge-base:latest
```

## Runtime image

- x86 ubuntu 24.04 image updated, upgraded and cleaned

```sh
docker build -f docker/rt.Dockerfile . -t bridge-rt:latest
```
