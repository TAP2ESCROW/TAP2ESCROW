# TAP2ESCROW

## Introduction

**TAP2ESCROW** is a Python-based project for demonstrating an escrow protocol on Bitcoin. It involves explorations into advanced cryptographic protocols like blind signatures and ring signatures for building secure escrow systems.
This tool is designed for providing a reference implementation of a research work titled: TAP2ESCROW: Taproot-Based Threshold Adaptor Signature Protocol for Multi-Party Bitcoin Escrow.
It utilizes a built-in test framework to interact with a local Bitcoin Core node on regtest for transaction creation and testing.

## Prerequisites

Before you begin, ensure you have the following installed on your system:
* Python 3.8+
* `virtualenv` for creating an isolated Python environment.
* `git` for cloning the repository.
* A compiled instance of Bitcoin Core. The path to your Bitcoin Core `src` directory needs to be configured.

## Installation and Setup

Follow these steps to get your development environment set up:

1.  **Create a project directory and set up a virtual environment:**
    ```bash
    mkdir code_testing
    cd code_testing
    python3 -m venv myenv
    source myenv/bin/activate
    ```

2.  **Clone the repository:**
    ```bash
    git clone https://github.com/TAP2ESCROW/TAP2ESCROW.git
    cd TAP2ESCROW
    ```

3.  **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Bitcoin Core Path:**
    Open the `config.ini` file and set the `SOURCE_DIRECTORY` to the absolute path of your local Bitcoin Core source directory. For example:
    ```ini
    [path]
    SOURCE_DIRECTORY=/home/user/bitcoin/
    ```

## Usage

To run the application, execute the main script from the project's root directory:

```bash
python tap2escrow.py
