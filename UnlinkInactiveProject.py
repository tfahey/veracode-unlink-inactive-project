# import sys
# import argparse
import logging
# import json
import datetime
import anticrlf
import timeit
import csv

import requests.exceptions
from veracode_api_py.api import VeracodeAPI as vapi, Applications, SCAApplications
from veracode_api_py.constants import Constants

log = logging.getLogger(__name__)


def setup_logger():
    handler = logging.FileHandler('UnlinkInactiveProject.log', encoding='utf8')
    handler.setFormatter(anticrlf.LogFormatter('%(asctime)s - %(levelname)s - %(funcName)s - %(message)s'))
    log = logging.getLogger(__name__)
    log.addHandler(handler)
    log.setLevel(logging.INFO)


def creds_expire_days_warning():
    creds = vapi().get_creds()
    exp = datetime.datetime.strptime(creds['expiration_ts'], "%Y-%m-%dT%H:%M:%S.%f%z")
    delta = exp - datetime.datetime.now().astimezone()  # we get a datetime with timezone...
    if (delta.days < 7):
        print('These API credentials expire ', creds['expiration_ts'])
    else:
        print('These API credentials are good until', creds['expiration_ts'])
        # print(creds)


def logprint(log_msg):
    log.info(log_msg)
    print(log_msg)


def unlink_project(answer, app_guid, application_name, apps_skipped, apps_unlinked, project_guid, project_name):
    # answer == "x" means stop prompting
    if answer != "x":
        answer = input(
            "About to unlink SCA project " + project_name + " from Application " + application_name + " Are you sure?y/n/x:")
        print("you answered " + answer)
    if live_mode and (answer == "y" or answer == "x"):
        logprint("Unlinking SCA project " + project_name + " from Application " + application_name)
        logprint("Unlinking SCA project guid " + project_guid + " from Application " + app_guid)
        try:
            SCAApplications().unlink_project(app_guid, project_guid)
            apps_unlinked = apps_unlinked + 1
        except requests.exceptions.RequestException:
            logprint(
                "An error was encountered trying to unlink SCA project " + project_name + " from application " + application_name)
        logprint("Running in live mode - this project has been unlinked")
    else:
        logprint("Skipping Unlinking SCA project " + project_name + " from Application " + application_name)
        apps_skipped = apps_skipped + 1
    return apps_skipped, apps_unlinked


def link_project(answer, app_guid, application_name, apps_skipped, apps_linked, project_guid, project_name):
    # answer == "x" means stop prompting
    if answer != "x":
        answer = input(
            "About to link SCA project " + project_name + " to Application " + application_name + " Are you sure?y/n/x:")
        print("you answered " + answer)
    if live_mode and (answer == "y" or answer == "x"):
        logprint("Linking SCA project " + project_name + " to Application " + application_name)
        logprint("Linking SCA project guid " + project_guid + " to Application " + app_guid)
        try:
            SCAApplications().link_project(app_guid, project_guid)
            apps_linked = apps_linked + 1
        except requests.exceptions.RequestException:
            logprint(
                "An error was encountered trying to link SCA project " + project_name + " to application " + application_name)
        logprint("Running in live mode - this project has been linked")
    else:
        logprint("Skipping linking SCA project " + project_name + " to Application " + application_name)
        apps_skipped = apps_skipped + 1
    return apps_skipped, apps_linked


deleted_apps = []
apps_with_one_GUID = []
apps_with_multiple_GUIDs = []
updated_linked_apps = []
live_mode = True
action = "unlink"  # valid values are "link" and "unlink"
# Insert your Veracode account ID here
account_ID = "00000"

def main():

    setup_logger()

    logprint('======== beginning UnlinkInactiveProject.py run ========')

    # check for trial mode
    if live_mode:
        logprint("running in live mode")
    else:
        logprint("running in trial mode")

    # CHECK FOR CREDENTIALS EXPIRATION
    creds_expire_days_warning()

    # open the linked projects file for reading -
    logprint("Opening the linked_projects file")
    linked_projects_file = open('linked_projects.csv', newline='')

    # create a dictReader object for the linked_projects file
    # note - the CSV must have column headings in top row
    linked_projects_reader = csv.DictReader(linked_projects_file)

    matchCount = 0
    apps_wrong_account = 0
    apps_not_found = 0
    apps_unlinked = 0
    apps_linked = 0
    apps_skipped = 0

    loop_start_time = timeit.default_timer()

    for this_linked_app in linked_projects_reader:
        # print(this_app['app_name'], this_app['project_name'], this_app['workspace_name'])
        app_name = this_linked_app['app_name']
        project_guid = this_linked_app['project_guid']
        # print("Application name: " + app_name + ", Linked SCA Project GUID: " + project_guid)
        # app_guid = Applications().get_by_name(app_name)  # process this carefully, it returns a list

        # logprint("Opening the legacyapps file")
        legacyapps_file = open('Apps.csv', newline='')
        # create a dictReader object for the legacyapps file
        # note - the CSV must have column headings in top row
        legacyapps_reader = csv.DictReader(legacyapps_file)

        for this_legacy_app in legacyapps_reader:
            legacy_app_name = this_legacy_app["APP_NAME"]
            legacy_app_id = this_legacy_app["APP_ID"]
            legacy_account_id = this_legacy_app["ACCOUNT_ID"]
            # print("trying to match" + app_name + " with " + legacy_app_name)
            if app_name == legacy_app_name:
                # print("Match on Application Name: " + app_name + ", capturing legacy APP_ID: " + legacy_app_id)
                this_linked_app["APP_ID"] = legacy_app_id
                this_linked_app["ACCOUNT_ID"] = legacy_account_id
                # print("This legacy app: ", this_legacy_app)
                # print("This linked app: ", this_linked_app)
                updated_linked_apps.append(this_linked_app)
                matchCount = matchCount + 1

                # close the legacyapps file, reopen for each loop, or just go back to the top of the file if possible
                # print("Closing the legacyapps file")
                legacyapps_file.close()
                break

            # else:
            #     print("no match between " + app_name + " and " + legacy_app_name)

    # Measure the elapsed time for the double nested loops
    loop_end_time = timeit.default_timer()
    loop_elapsed_time = loop_end_time - loop_start_time

    print("Closing the linkedapps file")
    linked_projects_file.close()

    print("There are " + str(matchCount) + " application profiles with legacy ID")

    api_start_time = timeit.default_timer()
    answer = ""

    for this_app in updated_linked_apps:

        # Initialize the application_found Boolean for this legacy_id
        application_found = False

        legacy_id = int(this_app["APP_ID"])
        project_guid = this_app["project_guid"]
        project_name = this_app["project_name"]
        app_guid = ""

        # Verify that the application profile is owned by the correct account ID.
        # If not, print and log a message, and break out of the loop for this application.
        if account_ID != this_app["ACCOUNT_ID"]:
            log_message = "Warning!! Application ", this_app["app_name"], " is owned by account id ", this_app["ACCOUNT_ID"], " and will be skipped!""Warning!! Application ", this_app["app_name"], " is owned by account id ", this_app["ACCOUNT_ID"], " and will be skipped!"
            logprint(log_message)
            apps_wrong_account = apps_wrong_account + 1
            continue

        logprint("Calling Applications API for app name " + this_app["app_name"] + " with legacy id " + str(legacy_id))
        app_info = Applications().get(legacy_id=legacy_id)

        # logprint(str(app_info))

        # print("app_info keys: ")

        for key, value in app_info.items():
            # if key == "applications":
            # print("Key: " + key)

            if key == "_embedded":
                if len(app_info["_embedded"]["applications"]) != 1:
                    print("WARNING! There are " + str(len(app_info["_embedded"]["applications"])) + " apps for guid!")
                app_guid = app_info["_embedded"]["applications"][0]["guid"]
                logprint("The app guid is: " + app_guid + " and the project guid is: " + project_guid)
                # print("app_info: " + str(app_info["_embedded"]["applications"][0]))

                # The Applications API found a matching application profile for this legacy_id
                application_found = True

                application_name = app_info["_embedded"]["applications"][0]["profile"]["name"]

                if action == "unlink":
                    apps_skipped, apps_unlinked = unlink_project(answer, app_guid, application_name, apps_skipped,
                                                                 apps_unlinked, project_guid, project_name)
                elif action == "link":
                    apps_skipped, apps_linked = link_project(answer, app_guid, application_name, apps_skipped,
                                                                 apps_linked, project_guid, project_name)
                else:
                    logprint("Invalid action specified")

        if not application_found:
            logprint("Warning!! Applications API did not find an application with app name" + this_app["app_name"] + " with legacy id " + str(legacy_id))
            apps_not_found = apps_not_found + 1

    # Measure the elapsed time for the API calls
    api_end_time = timeit.default_timer()
    api_elapsed_time = api_end_time - api_start_time

    logprint(str(matchCount) + " applications profiles were matched by legacy ID")
    logprint(str(apps_wrong_account) + " applications were skipped because the account id was incorrect.")
    logprint(str(apps_not_found) + " applications were skipped because the Applications API did not find them.")
    if action == "unlink":
        logprint(str(apps_unlinked) + " applications were successfully unlinked.")
    elif action == "link":
        logprint(str(apps_linked) + " applications were successfully linked.")
    else:
        logprint("Invalid action specified")
    logprint(str(apps_skipped) + " applications were skipped because the user answered 'n' or the script was in trial mode.")
    logprint("The double nested loop took " + str(loop_elapsed_time) + " seconds")
    logprint("The API calls loop took " + str(api_elapsed_time) + " seconds, or " + str(api_elapsed_time/60.) + " minutes")
    logprint('======== ending UnlinkInactiveProject.py run ========')


if __name__ == '__main__':
    main()
