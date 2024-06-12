# import sys
# import argparse
import logging
# import json
import datetime
import anticrlf
import timeit
import csv

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


def prompt_for_app(prompt_text):
    appguid = ""
    app_name_search = input(prompt_text)
    app_candidates = Applications().get_by_name(app_name_search)
    if len(app_candidates) == 0:
        print("No matches were found!")
    elif len(app_candidates) > 1:
        print("Please choose an application:")
        for idx, appitem in enumerate(app_candidates, start=1):
            print("{}) {}".format(idx, appitem["profile"]["name"]))
        i = input("Enter number: ")
        try:
            if 0 < int(i) <= len(app_candidates):
                appguid = app_candidates[int(i) - 1].get('guid')
        except ValueError:
            appguid = ""
    else:
        appguid = app_candidates[0].get('guid')

    return appguid


def get_app_guid_from_legacy_id(app_id):
    app = Applications().get(legacy_id=app_id)
    if app is None:
        return
    return app['_embedded']['applications'][0]['guid']


def get_application_name(guid):
    app = Applications().get(guid)
    return app['profile']['name']


def get_findings_by_type(app_guid, scan_type='STATIC', sandbox_guid=None):
    findings = []
    if scan_type == 'STATIC':
        findings = Findings().get_findings(app_guid, scantype=scan_type, annot='TRUE', sandbox=sandbox_guid)
    elif scan_type == 'DYNAMIC':
        findings = Findings().get_findings(app_guid, scantype=scan_type, annot='TRUE')

    return findings


def logprint(log_msg):
    log.info(log_msg)
    print(log_msg)


def filter_approved(findings, id_list):
    if id_list is not None:
        log.info('Only copying the following findings provided in id_list: {}'.format(id_list))
        findings = [f for f in findings if f['issue_id'] in id_list]

    return [f for f in findings if (f['finding_status']['resolution_status'] == 'APPROVED')]


def filter_proposed(findings, id_list):
    if id_list is not None:
        log.info('Only copying the following findings provided in id_list: {}'.format(id_list))
        findings = [f for f in findings if f['issue_id'] in id_list]

    return [f for f in findings if (f['finding_status']['resolution_status'] == 'PROPOSED')]


def format_file_path(file_path):
    # special case - omit prefix for teamcity work directories, which look like this:
    # teamcity/buildagent/work/d2a72efd0db7f7d7
    if file_path is None:
        return ''

    suffix_length = len(file_path)

    buildagent_loc = file_path.find('teamcity/buildagent/work/')

    if buildagent_loc > 0:
        # strip everything starting with this prefix plus the 17 characters after
        # (25 characters for find string, 16 character random hash value, plus / )
        formatted_file_path = file_path[(buildagent_loc + 42):suffix_length]
    else:
        formatted_file_path = file_path

    return formatted_file_path


def create_match_format_policy(app_guid, sandbox_guid, policy_findings, finding_type):
    findings = []

    if finding_type == 'STATIC':
        thesefindings = [{'app_guid': app_guid,
                          'sandbox_guid': sandbox_guid,
                          'id': pf['issue_id'],
                          'resolution': pf['finding_status']['resolution'],
                          'cwe': pf['finding_details']['cwe']['id'],
                          'procedure': pf['finding_details'].get('procedure'),
                          'relative_location': pf['finding_details'].get('relative_location'),
                          'source_file': format_file_path(pf['finding_details'].get('file_path')),
                          'line': pf['finding_details'].get('file_line_number'),
                          'finding': pf} for pf in policy_findings]
        findings.extend(thesefindings)
    elif finding_type == 'DYNAMIC':
        thesefindings = [{'app_guid': app_guid,
                          'id': pf['issue_id'],
                          'resolution': pf['finding_status']['resolution'],
                          'cwe': pf['finding_details']['cwe']['id'],
                          'path': pf['finding_details']['path'],
                          'vulnerable_parameter': pf['finding_details'].get('vulnerable_parameter', ''),
                          # vulnerable_parameter may not be populated for some info leak findings
                          'finding': pf} for pf in policy_findings]
        findings.extend(thesefindings)
    return findings


def format_application_name(guid, app_name, sandbox_guid=None):
    if sandbox_guid is None:
        formatted_name = 'application {} (guid: {})'.format(app_name, guid)
    else:
        formatted_name = 'sandbox {} in application {} (guid: {})'.format(sandbox_guid, app_name, guid)
    return formatted_name


def update_mitigation_info_rest(to_app_guid, flaw_id, action, comment, sandbox_guid=None, propose_only=False):
    # validate length of comment argument, gracefully handle overage
    if len(comment) > 2048:
        comment = comment[0:2048]

    if action == 'CONFORMS' or action == 'DEVIATES':
        log.warning('Cannot copy {} mitigation for Flaw ID {} in {}'.format(action, flaw_id, to_app_guid))
        return
    elif action == 'APPROVED' or action == 'PROPOSED':
        if propose_only:
            log.info('propose_only set to True; skipping applying approval for flaw_id {}'.format(flaw_id))
            return
        action = Constants.ANNOT_TYPE[action]
    flaw_id_list = [flaw_id]
    if sandbox_guid == None:
        Findings().add_annotation(to_app_guid, flaw_id_list, comment, action)
    else:
        Findings().add_annotation(to_app_guid, flaw_id_list, comment, action, sandbox=sandbox_guid)
    log.info(
        'Updated mitigation information to {} for Flaw ID {} in {}'.format(action, str(flaw_id_list), to_app_guid))


def set_in_memory_flaw_to_approved(findings_to, to_id):
    # use this function to update the status of target findings in memory, so that, if it is found
    # as a match for multiple flaws, we only copy the mitigations once.
    for finding in findings_to:
        if all(k in finding for k in ("id", "finding")):
            if (finding["id"] == to_id):
                finding['finding']['finding_status']['resolution_status'] = 'APPROVED'


def set_in_memory_flaw_to_proposed(findings_to, to_id):
    # use this function to update the status of target findings in memory, so that, if it is found
    # as a match for multiple flaws, we only copy the mitigations once.
    for finding in findings_to:
        if all(k in finding for k in ("id", "finding")):
            if (finding["id"] == to_id):
                finding['finding']['finding_status']['resolution_status'] = 'PROPOSED'


def match_for_scan_type(from_app_guid, to_app_guid, dry_run, scan_type='STATIC', from_sandbox_guid=None,
                        to_sandbox_guid=None, propose_only=False, id_list=[], fuzzy_match=False):
    results_from_app_name = get_application_name(from_app_guid)
    formatted_from = format_application_name(from_app_guid, results_from_app_name, from_sandbox_guid)
    logprint('Getting {} findings for {}'.format(scan_type.lower(), formatted_from))
    findings_from = get_findings_by_type(from_app_guid, scan_type=scan_type, sandbox_guid=from_sandbox_guid)
    count_from = len(findings_from)
    logprint('Found {} {} findings in "from" {}'.format(count_from, scan_type.lower(), formatted_from))
    if count_from == 0:
        return 0  # no source findings to copy!

    findings_from_approved = filter_approved(findings_from, id_list)
    findings_from_proposed = filter_proposed(findings_from, id_list)

    if len(findings_from_approved) == 0:
        logprint('No approved findings in "from" {}. Exiting.'.format(formatted_from))
    elif len(findings_from_proposed) == 0:
        logprint('No proposed findings in "from" {}. Exiting.'.format(formatted_from))
        return 0

    results_to_app_name = get_application_name(to_app_guid)
    formatted_to = format_application_name(to_app_guid, results_to_app_name, to_sandbox_guid)

    logprint('Getting {} findings for {}'.format(scan_type.lower(), formatted_to))
    findings_to = get_findings_by_type(to_app_guid, scan_type=scan_type, sandbox_guid=to_sandbox_guid)
    count_to = len(findings_to)
    logprint('Found {} {} findings in "to" {}'.format(count_to, scan_type.lower(), formatted_to))
    if count_to == 0:
        return 0  # no destination findings to mitigate!

    # CREATE LIST OF UNIQUE VALUES FOR BUILD COPYING TO
    copy_array_to = create_match_format_policy(app_guid=to_app_guid, sandbox_guid=to_sandbox_guid,
                                               policy_findings=findings_to, finding_type=scan_type)

    # We'll return how many mitigations we applied
    counter = 0

    # look for a match for each finding in the TO list and apply mitigations of the matching flaw, if found
    for this_to_finding in findings_to:
        to_id = this_to_finding['issue_id']

        if this_to_finding['finding_status']['resolution_status'] == 'APPROVED':
            logprint('Flaw ID {} in {} already has an accepted mitigation; skipped.'.format(to_id, formatted_to))
            continue
        elif this_to_finding['finding_status']['resolution_status'] == 'PROPOSED':
            logprint('Flaw ID {} in {} already has a proposed mitigation; skipped.'.format(to_id, formatted_to))
            continue

        match = Findings().match(this_to_finding, findings_from, approved_matches_only=False,
                                 allow_fuzzy_match=fuzzy_match)

        if match == None:
            log.info('No approved or proposed match found for finding {} in {}'.format(to_id, formatted_from))
            continue

        from_id = match.get('id')

        log.info(
            'Source flaw {} in {} has a possible target match in flaw {} in {}.'.format(from_id, formatted_from, to_id,
                                                                                        formatted_to))
        mitigation_list = ''
        if match['finding'].get('annotations') == None:
            logprint('{} annotations for flaw ID {} in {}...'.format(len(mitigation_list), to_id, formatted_to))
        else:
            mitigation_list = match['finding']['annotations']
            logprint(
                'Applying {} annotations for flaw ID {} in {}...'.format(len(mitigation_list), to_id, formatted_to))

        for mitigation_action in reversed(mitigation_list):  # findings API puts most recent action first
            proposal_action = mitigation_action['action']
            proposal_comment = '(COPIED FROM APP {}) {}'.format(from_app_guid, mitigation_action['comment'])
            if not (dry_run):
                update_mitigation_info_rest(to_app_guid, to_id, proposal_action, proposal_comment, to_sandbox_guid,
                                            propose_only)

        set_in_memory_flaw_to_approved(copy_array_to, to_id)  # so we don't attempt to mitigate approved finding twice
        set_in_memory_flaw_to_proposed(copy_array_to, to_id)  # so we don't attempt to mitigate proposed finding twice
        counter += 1

    print('[*] Updated {} flaws in {}. See log file for details.'.format(str(counter), formatted_to))


deleted_apps = []
apps_with_one_GUID = []
apps_with_multiple_GUIDs = []
updated_linked_apps = []


def main():

    setup_logger()

    logprint('======== beginning UnlinkInactiveProject.py run ========')

    # CHECK FOR CREDENTIALS EXPIRATION
    creds_expire_days_warning()

    # with open('att_linked_projects_2.csv', newline='') as appsfile:
    #     data = list(csv.reader(appsfile))
    #
    # print(data)

    # print("There are", len(data), "applications.")

    # open the linked projects file for reading -
    print("Opening the linkedapps file")
    linkedapps_file = open('att_linked_projects_2.csv', newline='')
    # open the legacy apps file for reading -
    # legacyapps_file = open('AT&T_Apps.csv', newline='')

    # create a dictReader object for the linkedapps file
    # note - the CSV must have column headings in top row
    linkedapps_reader = csv.DictReader(linkedapps_file)

    # create a dictReader object for the legacyapps file
    # note - the CSV must have column headings in top row
    # legacyapps_reader = csv.DictReader(legacyapps_file)

    matchCount = 0
    loop_start_time = timeit.default_timer()

    for this_linked_app in linkedapps_reader:
        # print(this_app['app_name'], this_app['project_name'], this_app['workspace_name'])
        app_name = this_linked_app['app_name']
        project_guid = this_linked_app['project_guid']
        # print("Application name: " + app_name + ", Linked SCA Project GUID: " + project_guid)
        # app_guid = Applications().get_by_name(app_name)  # process this carefully, it returns a list

        # print("Opening the legacyapps file")
        legacyapps_file = open('AT&T_Apps.csv', newline='')
        legacyapps_reader = csv.DictReader(legacyapps_file)

        for this_legacy_app in legacyapps_reader:
            legacy_app_name = this_legacy_app["APP_NAME"]
            legacy_app_id = this_legacy_app["APP_ID"]
            # print("trying to match" + app_name + " with " + legacy_app_name)
            if app_name == legacy_app_name:
                # print("Match on Application Name: " + app_name + ", capturing legacy APP_ID: " + legacy_app_id)
                this_linked_app["APP_ID"] = legacy_app_id
                # print(this_linked_app)
                updated_linked_apps.append(this_linked_app)
                matchCount = matchCount + 1

                # close the legacyapps file, reopen for each loop, or just go back to the top of the file if possible
                # print("Closing the legacyapps file")
                legacyapps_file.close()
                break

            # else:
            #     print("no match between " + app_name + " and " + legacy_app_name)

        # printing the list using loop
        # print("For Application name " + app_name + " the App GUID list has " + str(len(app_guid)) + " items")
        # if len(app_guid) == 0:
        #     deleted_apps.append(this_linked_app)
        # elif len(app_guid) == 1:
        #     apps_with_one_GUID.append(this_linked_app)
        # else:
        #     apps_with_multiple_GUIDs.append(this_linked_app)
        # for x in range(len(app_guid)):
        #     print(app_guid[x])
        # print("Application GUID: " + app_guid)

    # Measure the elapsed time for the double nested loops
    loop_end_time = timeit.default_timer()
    loop_elapsed_time = loop_end_time - loop_start_time

    # Print the number of updated linked_apps (each is a dictionary of key:value pairs)
    # print("The number of updated linked apps is " + str(len(updated_linked_apps)))
    # print("row 0: " + str(updated_linked_apps[0]))

    print("Closing the linkedapps file")
    linkedapps_file.close()

    print("There are " + str(matchCount) + " application profiles with legacy ID")

    api_start_time = timeit.default_timer()
    answer = ""

    for this_app in updated_linked_apps:
        legacy_id = int(this_app["APP_ID"])
        project_guid = this_app["project_guid"]
        project_name = this_app["project_name"]
        app_info = Applications().get(legacy_id=legacy_id)

        # print("app_info keys: ")

        for key, value in app_info.items():
            # if key == "applications":
            # print("Key: " + key)

            if key == "_embedded":
                if len(app_info["_embedded"]["applications"]) != 1:
                    print("WARNING! There are " + str(len(app_info["_embedded"]["applications"])) + " apps for guid!")
                print("app_info guid: " + app_info["_embedded"]["applications"][0]["guid"])
                # print("app_info: " + str(app_info["_embedded"]["applications"][0]))
                application_name = app_info["_embedded"]["applications"][0]["profile"]["name"]
                if answer != "x":
                    answer = input("About to unlink SCA project " + project_name + " from Application " + application_name + " Are you sure?y/n/x:")
                    print("you answered " + answer)
                if answer != "n":
                    print("Unlinking SCA project " + project_name + " from Application " + application_name)
                # SCAApplications().unlink_project(app_info["guid"], project_guid)

    # Measure the elapsed time for the API calls
    api_end_time = timeit.default_timer()
    api_elapsed_time = api_end_time - api_start_time

    # print("There are " + str(len(deleted_apps)) + " deleted application profiles")
    # print("There are " + str(len(apps_with_one_GUID)) + " application profiles that exactly match the application name")
    # print("There are " + str(len(apps_with_multiple_GUIDs)) + " application profiles that dont exactly match")

    # make a new variable - apps - for Python's CSV reader object -
    # apps = csv.reader(appsfile)

    # read whatever you want from the reader object
    # print it or use it any way you like
    # for this_app in apps:
    #     print("Application name: " + this_app[0] + ", Linked SCA Project Name: " + this_app[1])
    # print(this_app[1])

    # save and close the file
    # appsfile.close()

    print("The double nested loop took " + str(loop_elapsed_time) + " seconds")
    print("The API calls loop took " + str(api_elapsed_time) + " seconds, or " + str(api_elapsed_time/60.) + " minutes")
    logprint('======== ending UnlinkInactiveProject.py run ========')


if __name__ == '__main__':
    main()
