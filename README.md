# SwapCT Proof of Concept

This repository serves as a Proof of Concept implementation of the Swap Confidential Transaction system: https://eprint.iacr.org/2021/631.pdf.

For performance comparison, there is a derived implementation of the Omniring transaction system in the `omniring` branch.

# ATTENTION
This code is not secure! Do not use it in any relevant setting.

# Usage

The main reason for this code are runtime measurements. Thereby we allow everyone to recreate the plots we present in the paper. 
    
## Performance Reproducibility

### With docker

Given a working docker environment (https://docs.docker.com/engine/install/), you build and run a container on linux with

    docker build --tag swapct .
    docker run -v "$(pwd)/plots:/usr/src/swapct/plots" --rm -it swapct -r 11 -o 20 -s 5

For other operating systems, please refer to the documentation on building and running docker containers.

The following command line options are available:
* r is the ring size used for the input ring signatures. This has to be of the form 2^x-5
* o is the maximum number of outputs. It will calculate the times from 1 input and output up to the specified value-
* s is the number of measurements performed for each setting.

Enjoy your plot in `plots/main.pdf` which will look like

![Example Plot](plots/example.png)

### Manually

As the authors promote the creation of reproducible results and it is hard to give absolute performance figures, 
we encourage you to recreate the generation and verification times in your environment.

You need a recent (>=1.48) rust installation with cargo.
An easy setup method for a rust environment on your operating system is https://rustup.rs/

To generate the timings run

    cargo run --bin plots --release -- -r 27 -o 22 -s 30 

Be aware that this takes around 40 seconds to build and 7 minutes to run on a modern CPU.

While running, it presents you a progress bar and the parameters used, e.g.
    
     Finished release [optimized] target(s) in 0.05s
      Running `target/release/plots -r 27 -o 5 -s 4`
    using Opt { statistics: 4, outputs: 5, ring: 27 }
    [00:00:00] [##########>-----------------------------] 5/20 (1s)

The program outputs two files `plots/generation.tex` and `plots/verification.tex`. 
To plot them nicely in comparison to the authors measurements, change to the plots directory and compile the `main.tex` with `pdflatex`

    cd plots
    pdflatex main.tex
   
and enjoy the results in `main.pdf`

## Test

The modules written include a few unit tests which helped during development and may serve as examples on how to interact with the library.
They capture the most basic operations, such as offer generation, sealing, and verification (`transaction::tests::create_offer`). For the lower level signatures, the tests check basic sign and verify queries (`aasig::tests::create_aasig`).
By no means are they exhaustive and cover all code.

To run the unit tests, use

    cargo test

