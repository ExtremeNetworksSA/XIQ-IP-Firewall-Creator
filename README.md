# XIQ IP Firewall Configuration
## Purpose
The ExtremeCloud IQ (XIQ) UI allows you to configure each ACL individually when compiling an IP Firewall. If you have many, this can be time-consuming. This script will read your XLSX template file and create an IP Firewall object that you can rename and assign to your User Profile.

### Overview
1. Download all files from GitHub
2. Populate your ACLs in the provided template
3. Store all files in the same folder
4. Prepare your Python environment and run the script
5. Review the new IP Firewall object
6. Delete and try again or
7. Rename it to the desired name
8. Assign it to the target User Profile

## Actions & Requirements
Install the required modules and generate an API Token to run script without user prompts.  If you need assistance setting up your computing environment, see this guide: https://github.com/ExtremeNetworksSA/API_Getting_Started

### Copy Required Files
You must copy from Github and place these files into the same folder:  `XIQ-IPFirewall-Config_v#.py` & `requirements.txt` & `ip-firewall-template.xlsx`

### Install Modules
There are additional modules that need to be installed in order for this script to function.  They're listed in the *requirements.txt* file and can be installed with the command `pip install -r requirements.txt` if using `PIP`.  Store the *requirements.txt* file in the same directory as the Python script file.

## User Settings
Review the user controllable variables within `XIQ-IPFirewall-Config_v#.py` which are outlined below.
Locate in the script "Begin user settings section" (around line 58)
  - **Authentication Options**:  [Token](#api-token) (Recommended), static entry for user/password, or prompt for credentials.
  - `ipFirewallName = "PythonGeneratedFirewall"` < This is the name used when creating the new IP Firewall object in XIQ. Note: This script will not overwrite an existing object.
  - `filename = "ip-firewall-template.xlsx"` < if you change this variable, remember to also change the file name to match.

### API Token
The default setup uses tokens for authentication to run without user prompts. Other options include hard-coded credentials (less secure) or prompting for credentials each time.

To run this script without user prompts, generate a token using `api.extremecloudiq.com`. Follow this [KB article](https://extreme-networks.my.site.com/ExtrArticleDetail?an=000102173) for details.

Brief instructions:

  1) Navigate to [API Swagger Site - api.extremecloudiq.com](https://api.extremecloudiq.com)
  2) Use the Authentication: /login API (Press: Try it out) to authenticate using a local administrator account in XIQ
  ```json
    {
    "username": "username@company.com",
    "password": "ChangeMe"
    }
  ```
  3) Press the Execute button
  4) Copy the `access_token` value (excluding the "" characters).  Note the expiration, it's 24 hours.
  ```json
    {
    "access_token": "---CopyAllTheseCharacters---",
    "token_type": "Bearer",
    "expires_in": 86400
    }
  ```
  5) Scroll to the top and press the Authorize button
  6) Paste contents in the Value field then press the **Authorize** button.  You can now execute any API's listed on the page.  **WARNING!** - You have the power to run all POST/GET/PUT/DELETE/UPDATE APIs and affect your live production VIQ environment.
  7) Scroll down to Authorization section > `/auth/apitoken` API (Press: Try it out)
  8) You need to convert a desired Token expiration date and time to EPOCH time:  Online time EPOCH converter:  https://www.epochconverter.com/
  
    EPOCH time 1717200000 corresponds to June 1, 2024, 00:00:00 UTC
  
  9) Update the `description` and `expire_time` as you see fit.  Update the permissions as shown for minimal privileges to run only specific APIs for this script.
  ```json
    "description": "Token for API Script",
    "expire_time": 1717200000,
    "permissions": [
      "auth:r","logout","l3-address-profile"
    ]
  ```
  10) Press the **Execute** button
  11) Scroll down and copy the contents of the `access_token`:
  ```json
    "access_token": "---ThisIsYourScriptToken---",
    ^^^ Use this Token in your script ^^^
  ```
  ```json
    Locate in your Python script and paste your token:
    XIQ_Token = "---ThisIsYourScriptToken---"
  ```

## Example XLSX Template:

| Source IP | Destination IP | Network Service | Action | Logging |
| -------: | ------:| --------:| -----:| --:|
| Any | Any | DHCP-Client | PERMIT | OFF |
| Any | Any | DNS | PERMIT | OFF |
| Any | 10.0.0.0/255.0.0.0 | Any | DENY | OFF |
| Any | 172.16.0.0/255.240.0.0 | Any | DENY | OFF |
| Any | 192.168.0.0/255.255.0.0 | Any | DENY | OFF |
| Any | Any | Any | PERMIT | OFF |

Chart Explanation:
- This is what is provided as default in the template.  It's a clone of the default XIQ Guest policy.

## Caveat

There's a limitation as of August 2024 when naming the IP Objects via API you can't use '/' characters.

If you enter 10.20.30.0/255.255.255.0 (forward slash) in the template, the script will create a Network object with the name 10.20.30.0-255.255.255.0 (hiphen)
