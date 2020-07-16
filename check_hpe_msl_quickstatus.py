#!/usr/bin/env python3


description = "Fetches the QuickStatus data from the HPE MSL Tape Library to report on the real health status"

__version__ = "0.0.3"
__version_date__ = "2020-06-06"
__author__ = "Rune Darrud <theflyingcorpse@gmail.com>"
__description__ = "Check HPE MSL QuickStatus Plugin"
__license__ = "MIT"

# Options

import logging
from argparse import ArgumentParser, RawDescriptionHelpFormatter
import sys
import traceback
import json
import time
from datetime import timedelta
from seleniumwire import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException
import requests

activity_status = {
  '0':'Idle',
  '1':'Moving',
  '2':'Scanning',
  '3':'Test Running',
  '4':'Initializing',
  '5':'Configuring',
  '6':'Upgrading',
  '7':'Drive Upgrading',
  '8':'Magazine removed',
  '9':'Magazine unlocked',
  '10':'Drive cleaning in progress',
  '11':'System starting',
  '12':'System shutting down',
  '13':'Unlocking',
  '14':'Startup halted',
  '15':'Calibrating',
  '16':'Configuring Drives',
  '20':'Stopped',
  '21':'Unit lock unlocked',
  '22':'Bottom cover removed',
  '23':'Top cover removed',
  '24':'Connection lost to module'
}

drive_load_status = {
  '0':'Empty',
  '1':'Media present',
  '2':'Seated',
  '3':'Threaded',
  '4':'Mounted',
}

def scrapeEvents(args,entry):
  """
  """

  if args.verbose:
    print('Get the events')

  # URLLIB3 emits a warning about the SSL security, disable it if we already ignore SSL verification.
  if not args.verify_ssl:
    requests.packages.urllib3.disable_warnings()

  # Read the token from the body
  token = str(entry.body.decode()).split('token=')[1]
  if args.verbose:
    print('Cookie obtained (expecting just a PHPSESSID_SECURE=..): ' + str(token))

  # Create a new requests session so we can query for data we're not able to read using headless Chrome navigated in a normal manner
  s = requests.Session()
  s.headers.update({'Accept': 'application/json, text/javascript, */*; q=0.01'})
  s.headers.update({'Accept-Language':'en-US'})
  s.headers.update({'X-Requested-With': 'XMLHttpRequest'})
  s.headers.update({'Sec-Fetch-Mode':'cors'})
  s.headers.update({'Sec-Fetch-Site':'same-origin'})
  s.headers.update({'Sec-Fetch-Dest':'empty'})
  s.headers.update({'Cache-Control':'max-age=0'})
  s.headers.update({'referer': 'https://' + args.host + '/index.php'})
  s.headers.update({'origin': 'https://' + args.host + ''})
  s.headers.update({'Cookie':entry.headers['Cookie']}) # Expecting a 'PHPSESSID_SECURE=...' cookie
  # Create a POST request to get the EVENTSINFO with TICKET, not INFOCONFIG as is what we get as the user (normally).
  # TICKETS are the open / unresolved issues that might not be directly tied to hardware / software issues
  r = s.post('https://' + args.host + '/inc/CUCEvents.php', verify=args.verify_ssl,
    data={
      'uc':'GET_EVENTSINFO',
      'data[CASE]':'TICKET',
      'data[LIMIT]':'10',
      'data[INCLUDE_CLOSED]':'FALSE',
      'token':token
    }
  )
  events = r.json()['data']
  return events


def scrapeData(args,driver):
  """
  """

  # Get the data from the URL
  if args.verbose:
    print("VERBOSE: Fetching the URL: " + url)
  driver.get(url)

  # Wait for the request to finish, ie get the response body
  if args.verbose:
    print("VERBOSE: Waiting for '/inc/CUCLogin.php' to show as a completed request")
  null = driver.wait_for_request('/inc/CUCLogin.php',timeout=args.timeout_login)

  # Find the dropdown of usernames, select the username used as the argument
  if args.verbose:
    print("VERBOSE: Selecting the username '" + str(args.username) + "' from the dropdown")
  driver.find_element_by_xpath("//select[@name='slctAccount']/option[text()='" + args.username + "']").click()
  
  # Fill in the password
  if args.verbose:
    print("VERBOSE: Typing in the password")
  driver.find_element_by_id("logPwd").send_keys(args.password)
  
  # "Click" login
  if args.verbose:
    print("VERBOSE: 'Clicking' the login button")
  driver.find_element_by_id("BTNLOGIN").click()
 
  # Wait for the QuickStatus to be fetched in the background, this is what we're really here for
  if args.verbose:
    print("VERBOSE: Waiting for '/inc/CUCQuickStatus.php' to show as a completed request")
  null = driver.wait_for_request('/inc/CUCQuickStatus.php',timeout=args.timeout_quickstatus)

  # Iterate over the returned requests - QuickStatus
  if args.verbose:
    print("VERBOSE: Iterating over requests")
  for entry in driver.requests:
    if entry.path == url + '/inc/CUCQuickStatus.php':
      # Decode the body before deserializing the JSON to Python.
      if args.verbose:
        print("VERBOSE: Decode and deserialize the JSON response")
      r = json.loads(entry.response.body.decode())
      # We just need the first response
      break

  # Bad authorization handling allows us to just query for what we're not shown in the webinterface.
  events = scrapeEvents(args,entry)

  # Store the result here
  scrapeResult = {}
  # Iterate over every key inside of 'data' in the response
  if args.verbose:
    print("VERBOSE: Transform the result into a usable dictionary")
  for status in r['data']:
    # Ignore this key, I haven't found any documentation for it
    if status == 'QUICKSTATUS_ERRORS_ADVANCED':
      continue
    # "zip" two arrays together as they are expected to be of equal lenght, one key, one val, into a dictionary
    # If multiple entries, we skip the first as thats our "headers" and just add a new entry for every data row
    scrapeResult[status] = list()
    if len(r['data'][status]) > 2:
      for i in range(len(r['data'][status])):
        if i == 0:
          continue
        scrapeResult[status].append(dict(zip(r['data'][status][0],r['data'][status][i])))
      # Continue to the next, dont add it again by letting it continue further
      continue

    # "zip" two arrays together as they are expected to be of equal lenght, one key, one val, into a dictionary
    scrapeResult[status].append(dict(zip(r['data'][status][0],r['data'][status][1])))


  for i in range(len(events['TICKET_LOG'])):
    if 'TICKET_LOG' not in scrapeResult:
      scrapeResult['TICKET_LOG'] = list()
    if i == 0:
      continue
    # "zip" two arrays together as they are expected to be of equal lenght, one key, one val, into a dictionary
    # If multiple entries, we skip the first as thats our "headers" and just add a new entry for every data row
    scrapeResult['TICKET_LOG'].append(dict(zip(events['TICKET_LOG'][0],events['TICKET_LOG'][i])))

  # Add in the logStatus
#  scrapeResult['logStatus'] = logStatus

  # Return the result
  return scrapeResult


def parse_command_line():
  """parse command line arguments
  Also add current version and version date to description
  """

  # define command line options
  parser = ArgumentParser(
    description=description + "\nVersion: " + __version__ + " (" + __version_date__ + ")",
    formatter_class=RawDescriptionHelpFormatter, add_help=False)

  group = parser.add_argument_group(title="mandatory arguments")
  group.add_argument("-H", "--host",
                     help="define the host to request. To change the port just add ':portnumber' to this parameter.")

  group = parser.add_argument_group(title="authentication arguments")
  group.add_argument("-u", "--username", help="the login user name", default="user")
  group.add_argument("-p", "--password", help="the login password")

  group = parser.add_argument_group(title="optional arguments")
  group.add_argument("-h", "--help", action='store_true',
                     help="show this help message and exit")
  group.add_argument("-w", "--warning", default="",
                     help="set warning value")
  group.add_argument("-c", "--critical", default="",
                     help="set critical value")
  group.add_argument("--timeout-login", type=int, default=10,
                     help="timeout wait for login to appear, default 10 (seconds)")
  group.add_argument("--timeout-quickstatus", type=int, default=10,
                     help="timeout wait for quickstatus to appear, default 10 (seconds)")
  group.add_argument("-v", "--verbose", action='store_true',
                     help="this will add verbose output")
  group.add_argument("-d", "--debug", action='store_true',
                     help="this will log all webdriver events to output")
  group.add_argument("-i", "--ignoreCertificateErrors", action='store_true',
                     help="ignoreCertificateErrors")

  result = parser.parse_args()

  if result.ignoreCertificateErrors:
    result.verify_ssl = False
  else:
    result.verify_ssl = True

  if result.help:
    parser.print_help()
    print("")
    exit(0)

#  if result.requested_query is None:
#    parser.error("You need to specify at least one query command.")

  # need to check this our self otherwise it's not
  # possible to put the help command into a arguments group
  if result.host is None:
    parser.error("no remote host defined")

  return result


if __name__ == "__main__":
  # Get the arguments from the command line
  args = parse_command_line()
  # If verbosity is set, increase verbosity of logging
  if args.debug:
    logging.basicConfig(level="DEBUG", format='%(asctime)s - %(levelname)s: %(message)s')

  try:
    # Create a usable URL
    url = 'https://' + args.host + ""
    # Initialize the Options from Chrome
    options = Options()
    # Headless chrome is a requirement
    options.add_argument('--headless')

    # Initialize the webdriver, verify_ssl must be set straight to seleniumwire if used
    driver = webdriver.Chrome('/usr/bin/chromedriver',options=options,seleniumwire_options={'verify_ssl':args.verify_ssl})

    # Scrape the data
    result = scrapeData(args,driver)

    output = list()
    perfdata = list()
    outputSummary = str()
    returncode = 0

    # Iterate over the event log
    eventRead = False
    for i in range(len(result['TICKET_LOG'])):
        ticket = result['TICKET_LOG'][i]
        if ticket['STATUS'] not in ['TICKET_RESOLVED','CLOSED']:
            if ticket['SEVERITY'] == 'WARNING':
              returncode = 1
            else:
              returncode = 3
            eventRead = True
            output.append('Event severity \'' + ticket['SEVERITY'] + '\' for \'' + ticket['COMPONENTTYPE'] + '\' at \'' + ticket['TIMESTAMP'] + '\' - ' +str(ticket['ERRORTEXT']))
            outputSummary = 'Event severity \'' + ticket['SEVERITY'] + '\' for \'' + ticket['COMPONENTTYPE'] + '\' at \'' + ticket['TIMESTAMP'] + '\' - ' + str(ticket['ERRORTEXT'])

    # If there was no uncleared events to print, print out the newest one that was read.
    if not eventRead:
      output.append('Latest event was at \'' + result['TICKET_LOG'][0]['TIMESTAMP'] + '\' for \'' + result['TICKET_LOG'][0]['COMPONENTTYPE'] + '\'')

    # The stack
    if int(result['QUICKSTATUS_STACK'][0]['ERRORS']) > 0 and returncode < 2:
      returncode = 2
      outputSummary = 'Number of errors in the library \'' + str(result['QUICKSTATUS_STACK'][0]['ERRORS']) + '\''
    elif int(result['QUICKSTATUS_STACK'][0]['WARNINGS']) > 0 and returncode < 1:
      returncode = 1
      outputSummary = 'Number of warnings in the library \'' + str(result['QUICKSTATUS_STACK'][0]['WARNINGS']) + '\''
    elif returncode == 0:
      outputSummary = 'The stack is currently \'' + str(activity_status[result['QUICKSTATUS_STACK'][0]['STACK_ACTIVITY_STATUS']]) + '\' and the library has been running for a total of \'' + '{}'.format(str(timedelta(seconds=int(result['QUICKSTATUS_SYSTEM'][0]['STACK_POWERON_TIME_RT'])))) + '\''
    
    # Stack Activity Status
    # Is the status currently in an unknown state?
    if int(result['QUICKSTATUS_STACK'][0]['STACK_ACTIVITY_STATUS']) in [4,5,6,7,8,14,15,16,20,22,23,24] and returncode < 3:
      returncode = 3
    # Is the status currently in a critical state?
    elif int(result['QUICKSTATUS_STACK'][0]['STACK_ACTIVITY_STATUS']) in [11,12] and returncode < 2:
      returncode = 2
    # Is the status currently in a warning state?
    elif int(result['QUICKSTATUS_STACK'][0]['STACK_ACTIVITY_STATUS']) in [10] and returncode < 1:
      returncode = 1
    
    output.append('Stack Activity Status: \'' + str(activity_status[result['QUICKSTATUS_STACK'][0]['STACK_ACTIVITY_STATUS']]) + '\'')
    perfdata.append('stack_activity_status=' + str(result['QUICKSTATUS_STACK'][0]['STACK_ACTIVITY_STATUS']))

    # The module status
    n = 0
    module_to_phys = {}
    for i in range(len(result['QUICKSTATUS_UNIT'])):
      n = n + 1
      module_to_phys[result['QUICKSTATUS_UNIT'][i]['UNIT_PHY_NUM']] = n
      if result['QUICKSTATUS_UNIT'][i]['UNIT_READY'] != 'TRUE' and returncode < 3:
        returncode = 3
        outputSummary = 'Module ' + str(n) + ' is reporting it is currently in a UNIT_READY state of \'' + str(result['QUICKSTATUS_UNIT'][i]['UNIT_READY']) + '\''
      elif int(result['QUICKSTATUS_UNIT'][i]['ERRORS']) > 0 and returncode < 2:
        returncode = 2
        outputSummary = 'Number of errors in Module ' + str(n) + '  \'' + str(result['QUICKSTATUS_UNIT'][i]['ERRORS']) + '\''
      elif int(result['QUICKSTATUS_UNIT'][i]['WARNINGS']) > 0 and returncode < 1:
        returncode = 1
        outputSummary = 'Number of warnings in Module ' + str(n) + ' \'' + str(result['QUICKSTATUS_UNIT'][i]['WARNINGS']) + '\''

      if int(result['QUICKSTATUS_UNIT'][i]['UNIT_POWER_STATUS']) != 0 and returncode < 2:
        returncode = 2
        outputSummary = 'Module ' + str(n) + ' reports its power status is not OK'
      if int(result['QUICKSTATUS_UNIT'][i]['WARNINGS_CART']) > 0 and returncode < 1:
        returncode = 1
        outputSummary = 'Module ' + str(n) + ' reports there are \'' + int(result['QUICKSTATUS_UNIT']['WARNINGS_CART']) + '\' cartridges with warnings'

      perfdata.append('module_' + str(n) + '_warnings_cart=' + str(result['QUICKSTATUS_UNIT'][i]['WARNINGS_CART']))
      perfdata.append('module_' + str(n) + '_cartridges=' + str(result['QUICKSTATUS_UNIT'][i]['CARTRIDGES']) + ';;;0;' + str(result['QUICKSTATUS_UNIT'][i]['SLOTS']))
      perfdata.append('module_' + str(n) + '_cartridges_in_drives=' + str(result['QUICKSTATUS_UNIT'][i]['CARTRIDGES_IN_DRIVES']))
      perfdata.append('module_' + str(n) + '_errors=' + str(result['QUICKSTATUS_UNIT'][i]['ERRORS']))
      perfdata.append('module_' + str(n) + '_warnings=' + str(result['QUICKSTATUS_UNIT'][i]['WARNINGS']))

      output.append('Module ' + str(n) + ' Ready: \'' + str(result['QUICKSTATUS_UNIT'][i]['UNIT_READY']) + '\'')

    # The drive status
    n = 0
    for i in range(len(result['QUICKSTATUS_DRIVE'])):
      n = n + 1
      module_int = module_to_phys[result['QUICKSTATUS_DRIVE'][i]['DRIVE_UNIT_PHY_NUM']]
      if int(result['QUICKSTATUS_DRIVE'][i]['ERRORS']) > 0 and returncode < 2:
        returncode = 2
        outputSummary = 'Number of errors in Module ' + str(module_int) + ' Drive ' + str(n) + '  \'' + str(result['QUICKSTATUS_DRIVE'][i]['ERRORS']) + '\''
      elif int(result['QUICKSTATUS_DRIVE'][i]['WARNINGS']) > 0 and returncode < 1:
        returncode = 1
        outputSummary = 'Number of warnings in Module ' + str(module_int) + ' Drive ' + str(n) + ' \'' + str(result['QUICKSTATUS_DRIVE'][i]['WARNINGS']) + '\''
      elif result['QUICKSTATUS_DRIVE'][i]['DRIVE_ERROR'] != 'FALSE' and returncode < 2:
        returncode = 2
        outputSummary = 'Module ' + str(module_int) + ' Drive ' + str(n) + ' reports it has errors'
      elif result['QUICKSTATUS_DRIVE'][i]['DRIVE_READY'] != 'TRUE' and returncode < 2:
        returncode = 2
        outputSummary = 'Module ' + str(module_int) + ' Drive ' + str(n) + ' reports it is not ready'


      output.append('Module ' + str(module_int) + ' Drive ' + str(n) + ' Load status \'' + str(drive_load_status[result['QUICKSTATUS_DRIVE'][i]['DRIVE_LOAD_STATUS']]) + '\'')
      output.append('Module ' + str(module_int) + ' Drive ' + str(n) + ' Ready \'' + str(result['QUICKSTATUS_DRIVE'][i]['DRIVE_READY']) + '\'')
      perfdata.append('module_' + str(module_int) + '_drive_' + str(n) + '_errors=' + str(result['QUICKSTATUS_DRIVE'][i]['ERRORS']))
      perfdata.append('module_' + str(module_int) + '_drive_' + str(n) + '_warnings=' + str(result['QUICKSTATUS_DRIVE'][i]['WARNINGS']))


    # Not sure what this is, seems related to security
    #output.append('STACK_PLK_TOKEN_STATUS: \'' + str(result['QUICKSTATUS_STACK'][0]['STACK_PLK_TOKEN_STATUS']) + '\'')
    if returncode == 3:
      print('UNKNOWN: ' + outputSummary)
    elif returncode == 2:
      print('CRITICAL: ' + outputSummary)
    elif returncode == 1:
      print('WARNING: ' + outputSummary)
    elif returncode == 0:
      print('OK: ' + outputSummary)
    else:
      print('UNKNOWN unhandled: ' + outputSummary)
    print('\n'.join(output) + ' | ' + ' '.join(perfdata))
#    print("-"*20)
#    if 'QUICKSTATUS_STACK' in result:
#      print(result['QUICKSTATUS_STACK'][0])
#    if 'QUICKSTATUS_UNIT' in result:
#      print(result['QUICKSTATUS_UNIT'])
#    if 'QUICKSTATUS_DRIVE' in result:
#      print(result['QUICKSTATUS_DRIVE'])
#    if 'QUICKSTATUS_SYSTEM' in result:
#      print(result['QUICKSTATUS_SYSTEM'])
  except TimeoutException:
    print("UNKNOWN: Timeout Exception occured, is the certificate trusted by the host? Try with the switch to ignore certificate errors or use the switch for verbose output")
    sys.exit(3)
  except Exception:
    print("UNKNOWN: Exception occured")
    traceback.print_exc(file=sys.stdout)
    sys.exit(3)
  finally:
    driver.close()
    driver.quit()
  sys.exit(returncode)
