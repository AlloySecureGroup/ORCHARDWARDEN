"""PyInstaller entry point."""
import sys

from orchardwarden.cli import main

if __name__ == "__main__":
    sys.exit(main())
