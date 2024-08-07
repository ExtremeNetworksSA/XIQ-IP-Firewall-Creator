#!/usr/bin/env python3
import getpass  ## import getpass is required if prompting for XIQ crednetials
import json
import requests
from colored import fg
import os
import pandas as pd
from pprint import pprint as pp
import re #regex
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module='openpyxl') # Suppress specific warnings


########################################################################################################################
## written by:       Mike Rieben
## e-mail:           mrieben@extremenetworks.com
## date:             August, 2024
## version:          1.0
## tested versions:  Python 3.11.4, XIQ 24r4 (June 2024)
########################################################################################################################
## This script ...  See README.md file for full description 
########################################################################################################################
## ACTION ITEMS / PREREQUISITES
## Please read the README.md file in the package to ensure you've completed the required and optional settings below
## Also as a reminder, do not forget to install required modules:  pip install -r requirements.txt
########################################################################################################################
## - ## two pound chars represents a note about that code block or a title
## - # one pound char represents a note regarding the line and may provide info about what it is or used for
########################################################################################################################
##API References in Swagger that are used herein:
## - Configuration - Policy GET /ip-firewall-policies
## - Configuration - Network GET /network-services
## - Configuration - Policy GET /l3-address-profiles
##   - ^^^ Source IP object allowed type:  IP Address, Hostname, Network: 10.10.20.0/255.255.255.0, (Not supported >>>) Wildcard: 10.10.10.0/255.0.0.255
########################################################################################################################


#region - Begin user settings section
## AUTHENTICATION Options:  Uncomment the section you wish to use whie other sections remain commented out
## 1) Static Username and password, must have empty token variable (Uncomment 3 total lines below). Enter values for username and password after uncommenting.
# XIQ_Token = ""
# XIQ_username = "name@contoso.com"  # Enter your ExtremeCloudIQ Username "xxxx"
# XIQ_password = "<password>"  # Enter your ExtremeCLoudIQ password "xxxx"

## 2) Prompt user to enter credentials, must have empty token variable (Uncomment 4 total lines below), simply uncomment - no entries required
# XIQ_Token = ""
# print ("Enter your XIQ login credentials ")
# XIQ_username = input("Email: ")
# XIQ_password = getpass.getpass("Password: ")

## 3) TOKEN generation from api.extremecloudiq.com (Swagger). Must have empty username and password variables (Uncomment 3 total lines below).  Enter XIQ Token within "" only.
# XIQ_Token = "XXXXXXXXXXXX"
XIQ_username = ""
XIQ_password = ""
##Authentication Options END

##User defined variables as outlined in README documentation
ipFirewallName = 'PythonGeneratedFirewall'
filename = 'ip-firewall-template.xlsx' #<-- If you change it here, remember to also change the template file name.
#endregion ##end user settings section

#region #************************* No user edits below this line required ************************************************************************************
##Global Variables-------------------------------------------------------------------------------------------------------------------------------------
URL = "https://api.extremecloudiq.com"  ##XIQ's API portal
headers = {"Accept": "application/json", "Content-Type": "application/json"}
PATH = os.path.dirname(os.path.abspath(__file__))  #Stores the current Python script directory to write the CSV file to
colorWhite = fg(255) ##DEFAULT Color: color pallete here: https://dslackw.gitlab.io/colored/tables/colors/
colorRed = fg(1) ##RED
colorGreen = fg(2) ##GREEN
colorPurple = fg(54) ##PURPLE
colorCyan = fg(6) ##CYAN
colorOrange = fg(94) ##ORANGE
colorGrey = fg(8)  ##GREY
#endregion #end Global Variables---------------------------------------------------------------------------------------------------------------------------------

##Use provided credentials to acquire the access token if none was provided-------------------------
def GetaccessToken(XIQ_username, XIQ_password):
    url = f'{URL}/login'
    payload = json.dumps({"username": XIQ_username, "password": XIQ_password})
    response = requests.post(url, headers=headers, data=payload)
    if response is None:
        log_msg = "ERROR: Not able to login into ExtremeCloudIQ - no response!"
        raise TypeError(log_msg)
    if response.status_code != 200:
        log_msg = f"Error getting access token - HTTP Status Code: {str(response.status_code)}"
        try:
            data = response.json()
            if "error_message" in data:
                log_msg += f"\n\t{data['error_message']}"
        except:
            log_msg += ""
        raise TypeError(log_msg)
    data = response.json()
    if "access_token" in data:
        headers["Authorization"] = "Bearer " + data["access_token"]
        return 0
    else:
        log_msg = "Unknown Error: Unable to gain access token"
        raise TypeError(log_msg)
##end Use provided credentials....--------------------------------------------------------------

##Get Network Service ID and verify the object exists in XIQ----------------------------------------------------------
def GetNetworkServiceID(networkServiceName_local):
    url = f'{URL}/network-services?page=1&limit=100&name={networkServiceName_local}'
    try:
        rawList = requests.get(url, headers=headers, verify = True)
    except ValueError as e:
        print('script is exiting...')
        raise SystemExit
    except Exception as e:
        print('script is exiting...')
        raise SystemExit
    if rawList.status_code != 200:
        print('Error exiting script...')
        print(rawList.text)
        raise SystemExit
    jsonDump = rawList.json()
    if jsonDump['total_count'] == 1:
        networkServiceID = jsonDump['data'][0]['id']
        return networkServiceID
    else:
        print(f'{colorRed}ABORT: The entered Network Service value "{networkServiceName_local}" was not found within the selectable list.  See template > Lookup tab for list.')
        raise SystemExit
##end function----------------------------------------------------------

##Get and Store All Network Service Names:IDs for lookup later (1 API Call)----------------------------------------------------------
def GetAllIpObjectIDs():
    newData = {}
    addressTypes = ['L3_ADDRESS_TYPE_IP_ADDRESS','L3_ADDRESS_TYPE_IP_SUBNET','L3_ADDRESS_TYPE_HOST_NAME','L3_ADDRESS_TYPE_WILDCARD']
    for itemTypes in addressTypes:
        url = f'{URL}/l3-address-profiles?addressType={itemTypes}'
        try:
            rawList = requests.get(url, headers=headers, verify = True)
        except ValueError as e:
            print('script is exiting...')
            raise SystemExit
        except Exception as e:
            print('script is exiting...')
            raise SystemExit
        if rawList.status_code != 200:
            print('Error exiting script...')
            print(rawList.text)
            raise SystemExit
        jsonDump = rawList.json()
        for item in jsonDump:
            newData[item['name']] = item['id']
    return newData
##end function----------------------------------------------------------

##Using a POST to create a temporary IP Firewall object and determine if the policy exists to eleminate looping through every found object name
def CreateIpFirewallPolicy():
    print(f'{colorPurple}\nAttempting to create IP Firewall Policy: {ipFirewallName}')
    url = f'{URL}/ip-firewall-policies'
    payload = json.dumps(
        {
            "name": ipFirewallName,
            "description": "The Python script created this placeholder object and has not finished updating. Maybe the script failed at some point. Delete this object and try again.",
            "rules": [
            {
            "action": "PERMIT",
            "service_id": 17003,
            "logging_type": "OFF"
            }
            ]
        }
    )
    response = requests.request("POST", url, headers=headers, data=payload)    
    if response is None:
        log_msg = "ERROR: POST call to create IP Firewall object - no response!"
        print(f'{colorRed}{log_msg}')
    if response.status_code != 201:
        log_msg = f"Error - HTTP Status Code: {str(response.status_code)}"
        data = response.json()
        try:
            if "error_message" in data:
                log_msg += f"\n\t{data['error_message']}"
        except:
            log_msg += ""
        if data['error_message'] == "INVALID_ARGUMENT: db.constraint.violate.can.not.persist.object.with.name":
            print(f'''{colorRed}{log_msg}
                ABORT: IP Firewall Object "{ipFirewallName}" already exists. In the spirit of this script's "do no harm", you must delete or change the name in XIQ first and try again.
                Navigate to Configure > Common Objects > Security > IP Firewall Policies > PythonGeneratedFirewall
                If it doesn't appear in the list, try refreshing your screen or check another page.''')
            raise(SystemExit)
    else:
        data = response.json()
        iPFirewallObjectID = data['id']
    return iPFirewallObjectID

##If this script created the IP Firewall Policy, this function will update the object with the final ACLs compiled from the template
def UpdateIpFirewallPolicy(existingIpFirewallObjectID_local,finalAclPayload_local):
    print(f'{colorPurple}\nAttempting to update IP Firewall Policy with user provided ACLs: {ipFirewallName}')
    url = f"{URL}/ip-firewall-policies/{existingIpFirewallObjectID_local}"
    payload = json.dumps(
        {
        "name": ipFirewallName,
        "description": "IP Firewall object created by a Python script",
        "rules": finalAclPayload_local
        }
    )
    response = requests.request("PUT", url, headers=headers, data=payload)    
    if response is None:
        log_msg = "ERROR: PUT call to update IP Firewall object - no response!"
        print(f'{colorRed}{log_msg}')
    if response.status_code != 200:
        log_msg = f"Error - HTTP Status Code: {str(response.status_code)}"
        try:
            data = response.json()
            if "error_message" in data:
                log_msg += f"\n\t{data['error_message']}"
        except:
            log_msg += ""
        print(f'{colorRed}{log_msg}')
    else:
        print(f'{colorGreen}IP Firewall Object udpated successfully!\nNavigate to Configure > Common Objects > Security > IP Firewall Policies > {ipFirewallName}\nRefresh page if necessary.')

##Delete IP Firewall object give you an easy way to delete the object after creation
def DeleteIpFirewallPolicy(existingIpFirewallObjectID_local):
    print(f'{colorPurple}\nDeleting IP Firewall object: ' + ipFirewallName)
    url = f"{URL}/ip-firewall-policies/{existingIpFirewallObjectID_local}"
    response = requests.request("DELETE", url, headers=headers)
    if response is None:
        log_msg = "ERROR: DELETE call to delete IP Firewall object - no response!"
        print(f'{colorRed}{log_msg}')
    if response.status_code != 200:
        log_msg = f"Error - HTTP Status Code: {str(response.status_code)}"
        try:
            data = response.json()
            if "error_message" in data:
                log_msg += f"\n\t{data['error_message']}"
        except:
            log_msg += ""
        print(f'{colorRed}{log_msg}')
    else:
        print(f'{colorGreen}IP Firewall object deleted successfully!')

##Evaluates what the user entered into a cell in Source/Destination IP and determines what type of object should be created.
def GoRegexCellValidation(cellEntry_local):
    #Pattern for valid IPv4 addresses
    ipv4_pattern = re.compile(
        r"^(?!0\.)(?!255\.)(1?[\d]?[\d]|2([0-4][\d]|5[0-5]))\."
        r"((1?[\d]?[\d]|2([0-4][\d]|5[0-5]))\.){2}"
        r"(?!0$)(?!255$)(1?[\d]?[\d]|2([0-4][\d]|5[0-5]))$"
    )

    #Pattern for valid hostnames (starting and ending with a digit)
    hostname_pattern = re.compile(r'^\d.*\d$')
  
    #Pattern for valid network addresses with subnet mask
    network_pattern = re.compile(
        r"^(?!0\.)(?!255\.)(1?[\d]?[\d]|2([0-4][\d]|5[0-5]))\."
        r"((1?[\d]?[\d]|2([0-4][\d]|5[0-5]))\.){2}"
        r"(?!0$)(?!255$)(1?[\d]?[\d]|2([0-4][\d]|5[0-5]))"
        r"/(255|254|252|248|240|224|192|128|0)\."
        r"(255|254|252|248|240|224|192|128|0)\."
        r"(255|254|252|248|240|224|192|128|0)\."
        r"(255|254|252|248|240|224|192|128|0)$"
    )

    #Pattern for Wildcard IP and mask. Requires a prefix of (W. or w.)
    wildcard_pattern = re.compile(r'^[Ww]\.\d.*\d$')
    
    if ipv4_pattern.match(cellEntry_local) and not (cellEntry_local.endswith('/') or cellEntry_local.endswith('\\')):
        return("IpObject")

    if wildcard_pattern.match(cellEntry_local):
        if cellEntry_local.split('/')[1].split('.')[0] == '255':
            return("WildcardObject")
        
    if not hostname_pattern.match(cellEntry_local) and not ('/' in cellEntry_local or '\\' in cellEntry_local):
        if not cellEntry_local.startswith(' ') and not cellEntry_local.endswith(' '):
            return("HostnameObject")

    if network_pattern.fullmatch(cellEntry_local):
        ipOctets = cellEntry_local.split('/')[0].split('.')
        if ipOctets[3] != '255':
            #Check if the mask is a valid contiguous subnet mask
            octets = cellEntry_local.split('/')[1].split('.')
            binary_mask = ''.join(format(int(octet), '08b') for octet in octets)
            if re.match(r'^(1+0*){1,4}$', binary_mask):
                return("NetworkObject")
                
    print(f"{colorRed}{cellEntry_local}: Invalid input.")
    return("InvalidObject")

##Create IP Object
def CreateIpObject(rowValue_local):
    url = f'{URL}/l3-address-profiles'
    newData = {}
    payload = json.dumps(
        {
        "name": rowValue_local,
        "description": "Created by a Python script.",
        "value": rowValue_local,
        "address_type": "IP_ADDRESS",
        "enable_classification": False,
        "classified_entries": []
        }
    )
    response = requests.request("POST", url, headers=headers, data=payload)
    if response is None:
        log_msg = "ERROR: POST call to create IP Address object - no response!"
        print(f'{colorRed}{log_msg}')
    if response.status_code != 201:
        log_msg = f"Error - HTTP Status Code: {str(response.status_code)}"
        data = response.json()
        try:
            if "error_message" in data:
                log_msg += f"\n\t{data['error_message']}"
        except:
            log_msg += ""
    else:
        data = response.json()
        name = (data['ip_address_profile']['name'])
        id = (data['ip_address_profile']['id'])
        newData[name] = id
        networkSubnetIpObjectIDs.update(newData)
        print(f'{colorGreen}IP Object: "{name}", created successfully')

##Create Hostname Object
def CreateHostnameObject(rowValue_local):
    url = f'{URL}/l3-address-profiles'
    newData = {}
    payload = json.dumps(
        {
        "name": rowValue_local,
        "description": "Created by a Python script.",
        "value": rowValue_local,
        "address_type": "HOST_NAME",
        "enable_classification": False,
        "classified_entries": []
        }
    )
    response = requests.request("POST", url, headers=headers, data=payload)
    if response is None:
        log_msg = "ERROR: POST call to create Hostname object - no response!"
        print(f'{colorRed}{log_msg}')
    if response.status_code != 201:
        log_msg = f"Error - HTTP Status Code: {str(response.status_code)}"
        data = response.json()
        try:
            if "error_message" in data:
                log_msg += f"\n\t{data['error_message']}"
        except:
            log_msg += ""
    else:
        data = response.json()
        name = (data['host_name_address_profile']['name'])
        id = (data['host_name_address_profile']['id'])
        newData[name] = id
        networkSubnetIpObjectIDs.update(newData)
        print(f'{colorGreen}Hostname Object: "{name}", created successfully')

#Create Network Object
def CreateNetworkObject(rowValue_local):
    url = f'{URL}/l3-address-profiles'
    newData = {}
    rowIP = rowValue_local.split('/')[0]
    rowMask = rowValue_local.split('/')[1]
    nameCreate = rowIP + "-" + rowMask #can't use / character in the name via API but you can via the GUI
    payload = json.dumps(
        {
        "name": nameCreate,
        "description": "Created by a Python script.",
        "value": rowIP,
        "netmask": rowMask,
        "address_type": "IP_SUBNET",
        "enable_classification": False,
        "classified_entries": []
        }
    )
    response = requests.request("POST", url, headers=headers, data=payload)
    if response is None:
        log_msg = "ERROR: POST call to create IP Subnet/Network object - no response!"
        print(f'{colorRed}{log_msg}')
    if response.status_code != 201:
        log_msg = f"Error - HTTP Status Code: {str(response.status_code)}"
        data = response.json()
        try:
            if "error_message" in data:
                log_msg += f"\n\t{data['error_message']}"
        except:
            log_msg += ""
    else:
        data = response.json()
        name = (data['subnet_address_profile']['name'])
        id = (data['subnet_address_profile']['id'])
        newData[name] = id
        networkSubnetIpObjectIDs.update(newData)
        print(f'{colorGreen}IP Subnet/Network Object: "{name}", created successfully')

##This is the start of the program
def main():
    ##Test if a token is provided.  If not, use credentials.
    if not XIQ_Token:
        try:
            login = GetaccessToken(XIQ_username, XIQ_password)
        except TypeError as e:
            print(e)
            raise SystemExit
        except:
            log_msg = "Unknown Error: Failed to generate token"
            print(log_msg)
            raise SystemExit
    else:
        headers["Authorization"] = "Bearer " + XIQ_Token
    ##Test if template file was found in the current directory which is required.
    if os.path.exists(filename): 
        print(f'{colorPurple}\nReading the template file found in the current directory: {filename}')
        dfFromFile = pd.read_excel(filename, sheet_name='Template')
        if len(dfFromFile) > 64: #first row are column headers and not counted.  Must not exceed 64 rules.
            print(f'{colorRed}You have exceeded the max number of allowed rules within a single IP Firewall object.  Max number is 64 rules.')
            raise(SystemExit)
        ##Go acquire every IP object type and store them for later lookup.  Reduces API calls.
        global networkSubnetIpObjectIDs
        networkSubnetIpObjectIDs = GetAllIpObjectIDs()        
        ##Convert the XLSX file contents to a list
        aclsRowsList = [row.tolist() for _, row in dfFromFile.iterrows()] # Convert each row to a list
        ##Compile the json payload to be used when updating the IP Firewall Policy object
        allAclPayload = []
        for row in aclsRowsList:
            rowAclPayload = {}
            if row[0] != 'Any': #API endpoint does not allow you to use 'source_ip_id' = 0 which is 'Any'
                try:
                    if row[0] in networkSubnetIpObjectIDs:
                        tempVar = row[0]
                    elif '/' in row[0]:
                        tempVar = row[0].replace('/','-') #due to an API limitation using '/' characters we have to swap and test if it exists
                    else:
                        tempVar = row[0]
                    rowAclPayload['source_ip_id'] = networkSubnetIpObjectIDs[tempVar]
                except:
                    isObjectValid = GoRegexCellValidation(row[0])
                    if isObjectValid == "InvalidObject":
                        raise SystemExit(f'{colorRed}ABORT: Source IP Object "{row[0]}" is not valid. Try creating the object in XIQ first and try again.')
                    else:
                        if isObjectValid == "IpObject":
                            print(f"{colorPurple}Attempting to create: {isObjectValid} - {row[0]}")
                            CreateIpObject(row[0])
                            rowAclPayload['source_ip_id'] = networkSubnetIpObjectIDs[tempVar]
                        elif isObjectValid == "HostnameObject":
                            print(f"{colorPurple}Attempting to create: {isObjectValid} - {row[0]}")
                            CreateHostnameObject(row[0])
                            rowAclPayload['source_ip_id'] = networkSubnetIpObjectIDs[tempVar]
                        elif isObjectValid == "NetworkObject":
                            print(f"{colorPurple}Attempting to create: {isObjectValid} - {row[0]}")
                            CreateNetworkObject(row[0])
                            rowAclPayload['source_ip_id'] = networkSubnetIpObjectIDs[tempVar]
                        elif isObjectValid == "WildcardObject":
                            print(f"{colorRed}Wildcard objects not supported: {isObjectValid} - {row[0]}")
            if row[1] != 'Any': #API endpoint does not allow you to use 'source_ip_id' = 0 which is 'Any'
                try:
                    if row[1] in networkSubnetIpObjectIDs:
                        tempVar = row[1]
                    elif '/' in row[1]:
                        tempVar = row[1].replace('/','-') #due to an API limitation using '/' characters we have to swap and test if it exists
                    else:
                        tempVar = row[1]
                    rowAclPayload['destination_ip_id'] = networkSubnetIpObjectIDs[tempVar]
                except:
                    isObjectValid = GoRegexCellValidation(row[1])
                    if isObjectValid == "InvalidObject":
                        raise SystemExit(f'{colorRed}ABORT: Destination IP Object "{row[1]}" is not valid. Try creating the object in XIQ first and try again.')
                    else:
                        if isObjectValid == "IpObject":
                            print(f"{colorPurple}Attempting to create: {isObjectValid} - {row[1]}")
                            CreateIpObject(row[1])
                            rowAclPayload['destination_ip_id'] = networkSubnetIpObjectIDs[tempVar]
                        elif isObjectValid == "HostnameObject":
                            print(f"{colorPurple}Attempting to create: {isObjectValid} - {row[1]}")
                            CreateHostnameObject(row[1])
                            rowAclPayload['destination_ip_id'] = networkSubnetIpObjectIDs[tempVar]
                        elif isObjectValid == "NetworkObject":
                            print(f"{colorPurple}Attempting to create: {isObjectValid} - {row[1]}")
                            CreateNetworkObject(row[1])
                            rowAclPayload['destination_ip_id'] = networkSubnetIpObjectIDs[tempVar]
                        elif isObjectValid == "WildcardObject":
                            print(f"{colorRed}Wildcard objects not supported: {isObjectValid} - {row[1]}")
            if row[2] != 'Any':
                try:
                    rowAclPayload['service_id'] = GetNetworkServiceID(row[2]) #Send the user entered Service Name and verify the object exists.
                except:
                    raise(SystemExit) #error message is provided in the function above: GetNetworkServiceID()
            if row[3]:
                if row[3] == 'DENY' or row[3] == 'PERMIT':
                    rowAclPayload['action'] = row[3]
                else:
                    print(f'{colorRed}ABORT: Invalid entry "{row[3]}" in the Action column.  Must be "DENY" or "PERMIT".')
                    raise(SystemExit)
            if row[4]:
                if row[4] == 'OFF' or row[4] == 'DROPPED_PACKETS' or row[4] == 'SESSION_INITIATION' or row[4] == 'SESSION_TERMINATION' or row[4] == 'BOTH':
                    rowAclPayload['logging_type'] = row[4]
                else:
                    print(f'{colorRed}ABORT: Invalid entry "{row[4]}" in the Logging column.  See template > Lookup tab for list.')
                    raise(SystemExit)
            allAclPayload.append(rowAclPayload)

        ##Go attempt to create a temporary policy to test if the new pocliy name exists. If not, return the temporary policy ID to be used later.
        existIpFirewallPolicyID = CreateIpFirewallPolicy()

        ##Send the temporary policy ID and the new payload to update the IP Firewall Policy object
        UpdateIpFirewallPolicy(existIpFirewallPolicyID,allAclPayload)

    else: #inform the user if the script can't find the XLSX file in the current directory
        print(f'{colorRed}\nABORT: File missing! You must copy the provided template (from Github) into your current Python script directory!: {filename} \n')
        
##Python will see this and run whatever function is provided: xxxxxx(), should be the last items in this file
if __name__ == '__main__':
    main() ##Go to main function

##***end script***


