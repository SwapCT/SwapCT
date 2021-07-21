# Omniring Performance Evaluation

This repository serves as a Proof of Concept implementation of the Omniring system.
https://eprint.iacr.org/2019/580.pdf

# ATTENTION
This code is not secure! Do not use it in any relevant setting.

# Usage

## Performance

![Performance Plot](plots/example.png)

(a) Transaction generation and (b) transaction verification in SwapCT and Omniring with same number of inputs and outputs and a ring size r=123.
In SwapCT, each input has a separate anonymity set of size r while in Omniring, all inputs share one anonymity set of size r.
The points show the median and the error bars the minimum and maximum time of 30 runs.

## Observations
In Omniring, there is a noticable step from 10 inputs and outputs to 11 as the size of the Bulletproof witness changes from 2026 to 2216 elements and the power of 2 padding increases this to 2^12=4096.
In SwapCT, the jump from 12 to 13 is explained by a similar padding from an 938 element witness for 12 inputs and outputs to 1029 elements for 13, which is padded to 2^11=2048.
For a ring size of 11, Omniring sucessfully fails to have more than 11 inputs as all slots of the ring signature are used already.


## Run Manually

As the authors promote the creation of reproducible results and it is hard to give absolute performance figures, 
we encourage you to recreate the generation and verification times in your environment.

You need a recent (>=1.48) rust installation with cargo.
An easy setup method for a rust environment on your operating system is https://rustup.rs/

To generate the timings run

    cargo run --bin plots --release -- -r 123 -o 20 -s 30 

Be aware that this takes around 40 seconds to build and 10 minutes to run on a modern CPU.

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
They capture the most basic operations, such as transaction generation and verification (`transaction::tests::create_tx`). For the lower level modules, the tests check e.g. basic one-time account creation and receiving (`account::tests::create_account`).
By no means are they exhaustive and cover all code.


To run the unit tests, use

    cargo test
