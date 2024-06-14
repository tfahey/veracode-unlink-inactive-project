# Veracode Unlink Inactive SCA Agent Projects

## Overview

This script allows the user to unlink inactive SCA Agent projects in Veracode.

## Installation

Clone this repository:

    git clone https://github.com/tfahey/veracode-unlink-inactive-project.git

Install dependencies:

    cd veracode-unlink-inactive-project
    pip install -r requirements.txt

### Getting Started

It is highly recommended that you store veracode API credentials on disk, in a secure file that has 
appropriate file protections in place.

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>


### Preparing the CSV Files
    Two CSV templates present in the repository can be used to prepare the input data.
    
### Running the script
    python3 UnlinkInactiveProject.py

If a credentials file is not created, you can export the following environment variables:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    python3 UnlinkInactiveProject.py****

## Notes


## Run ##

```shell
python3 UnlinkInactiveProject.py 
```


