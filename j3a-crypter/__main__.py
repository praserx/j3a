#!/usr/bin/env python3

import os
import sys

from crypter import Crypter

if __name__ == "__main__":

    # Help message and author
    help = ("Usage: crypter.py [option] src dest\n"
        "Options:\n"
        "  -h    print help\n"
        "  -v    verbose\n"
        "Arguments:\n"
        "  src   source folder\n"
        "  dest  destination folder\n"
        "Author:\n"
        "  Tomas Pekar\n"
        "  xpekar10@stud.fit.vutbr.cz\n")

    verbose = False

    # Print help message
    for arg in sys.argv:
        if arg == "-h":
            print(help)
            exit(0)

    # Check and set verbose
    for arg in sys.argv:
        if arg == "-v":
            verbose = True
            sys.argv.remove(arg)

    # Too few args, print help
    if len(sys.argv) > 4:
       print(help)
       exit(1)
    elif len(sys.argv) < 2:
       print(help)
       exit(1)

    src = sys.argv[1]
    dest = sys.argv[2]

    # Source folder does not exitsts
    if not os.path.isdir(src):
        print("Error: Source folder doesn't exists.")
        exit(1)

    # Destination folder does not exists
    if not os.path.isdir(dest):
        print("Error: Destination folder doesn't exists.")
        exit(1)

    # Dest can not be the same as source
    if dest == src:
        print("Error: Destination directory can't be the same as source directory!")
        exit(1)

    # Init Crypter
    crypter = Crypter(verbose)
    
    # Print warning
    select = input("Content of destination folder will be removed. Do you want continue? [y/n]\n")
    if (select != "y") and (select != "yes"):
        exit(0)
    
    # Print init info
    print("Initializing...")
    crypter.initialize(src, dest)

    # Print analyze info
    print("Analyzing directory...")
    crypter.analyze(dest)

    # Print encryption info
    print("Processing files...")
    crypter.process()

    # Print done
    print("Postprocessing is done! Check output files.")
    
    exit(0)
    