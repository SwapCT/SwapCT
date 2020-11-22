#!/bin/bash

set -e

plots "$@"
cd plots
pdflatex main.tex