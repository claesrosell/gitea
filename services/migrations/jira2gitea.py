import requests
from requests.auth import HTTPBasicAuth
import re
from io import StringIO
from io import BytesIO
import uuid
import json
from gitea import *
import unicodedata


# Inspired from https://gist.github.com/toudi/67d775066334dc024c24
# Tested on Jira Cloud and Gitlab 13.8 (Hosted) with Python 3.8.5
JIRA_URL = 'http://172.16.5.16:8080/'
JIRA_ACCOUNT = ('claes.rosell@solme.se', 'dfloCalgn6AZn5nSKHmW')
# the JIRA project ID (short)
JIRA_PROJECT = 'AVIX'
# Jira Query
#JQL = 'key=PRO-1182'
#JQL = 'project=%s+AND+(resolution=Unresolved+OR+Sprint+in+openSprints())+ORDER+BY+createdDate+ASC&maxResults=10000' % JIRA_PROJECT
#JQL = 'createdDate >= startOfMonth()'
#JQL = 'issuekey = AVIX-6049'
JQL = 'issuekey = CUS-577'

GITEA_URL = 'http://172.16.10.41:3000'  # No trailing /

# this is needed for importing attachments. The script will login to gitlab under the hood.
GITLAB_ACCOUNT = ('root', 'u8rdR2oiPyn71F1oVhSk')

# this token will be used whenever the API is invoked and
# the script will be unable to match the jira's author of the comment / attachment / issue
# this identity will be used instead.
GITEA_TOKEN = 'f8a3899903dcb6945bf2ea739d2eba91d1eda230' # marcus-api-token

GITEA_AUTH = None

GITEA_SELECTED_ORG = "SolmeAB"

# Gitlab headers to pass when making API call
GITLAB_HEADERS = {
    'PRIVATE-TOKEN': GITEA_TOKEN
}

# If you are runninig Gitlab on-premise set to True.  Hosted Gitlab has not sudo option
GITLAB_SUDO = True

# the project in gitlab that you are importing issues to.
# the numeric project ID. If you don't know it, the script will search for it
# based on the project name.
# GITLAB_PROJECT_ID = 12345678

#If you use either milestones or iterations set that here.
# Options here are either milestones or iterations
# Note this is used in the API call so make sure it is lower case and plural
# Note: The API doesn't support creating iterations yet
# Note: Not fully implemented..
GITLAB_SPRINT_TYPE = 'milestones'

# ID of the group that contains your users.  In our case we have an everyone group
GITLAB_GROUP_USERS = 2

# Add a comment with the JIRA Sprint name to the new GL issue
ADD_SPRINT_COMMENT = True

# set this to false if JIRA / Gitlab is using self-signed certificate.
VERIFY_SSL_CERTIFICATE = False

# Add a comment with the link to the Jira issue
ADD_A_LINK = False

# the Jira Epic custom field
JIRA_EPIC_FIELD = 'customfield_10006'

# the Jira Sprints custom field
JIRA_SPRINT_FIELD = 'customfield_10005'

# the Jira story points custom field
JIRA_STORY_POINTS_FIELD = 'customfield_10002'

# Used for progress tracking, so we don't reprocess the same issues in the event
# of a script failure or re-run
ISSUE_TRACKING = True  # set to False to disable
TRACKING_FILE = "migrated_issues.txt"

# jira user name as key, gitlab as value
# if you want dates and times to be correct, make sure every user is (temporarily) admin
GITLAB_USER_NAMES = {
    'jira displayName': 'gitlab Username',
    'jira displayName': 'gitlab Username'
}

# Convert Jira issue types to Gitlab labels
# Warning: If a Jira issue type isn't in the map, the issue will be skipped!
ISSUE_TYPES_MAP = {
    'Bug': 'bug',
    'Improvement': 'enhancement',
    'Spike': 'spike',
    'Story': 'story',
    'story': 'story',
    'Task': 'task'
}

# filter only certain components to match up from Jira to GL project
COMPONENT_MAP = {
    'Resource Balance': 'Resource Balance',
    'Shop floor viewer': 'Shop floor viewer',
    'General_Editors': 'General_Editors',
    'DFX': 'DFX',
    'UAS': 'UAS',
    'Customizations': 'Customizations',
    'FMEA': 'FMEA',
    'General': 'General',
    'Reporting': 'Reporting',
    'SMED': 'SMED',
    'Method': 'Method',
    'General_Integration': 'General_Integration',
    'Media Player': 'Media Player'
}

PROJECT_MAPPING = { 
    'AVIX': {
        'DEFAULT': 'avix'
    },
    
    'CUS': {
#        'DEFAULT': 'customizations',
        'Scania': 'scania',
        'Epiroc': 'epiroc',
        'ZKW': 'ZKW'
    }
}

# setup labels based on components
LABEL_MAP = {
    'frontend': 'Frontend Label',
    'backend': 'Backend Label'
}

LABELS_CACHE_MAP = {
}


# Labels that will be added to all issues that are imported
DEFAULT_LABELS = ['Set any default labels here']

# (Enterprise/Ultimate version) Convert Jira story points to Gitlab issue weight
STORY_POINTS_MAP = {
    1.0: 1,
    2.0: 2,
    3.0: 3,
    5.0: 5,
    8.0: 8,
    13.0: 13,
    20.0: 21,
    21.0: 21,
    34.0: 34,
    40.0: 34
}

# Project numbers gathered from the web UI
PROJECT_MAP = {
    'frontend': 'Gitlab project number',
    'backend': 'Gitlab project number'
}

# IMPORTANT !!!
# make sure that user (in gitlab) has access to the project you are trying to
# import into. Otherwise the API request will fail.
#use the gitlab python module
# connect to Gitlab
gitea = Gitea(GITEA_URL, GITEA_TOKEN)
gitea.headers['Content-Type'] = gitea.headers['Content-type']
gitea.headers['Content-type'] = None

print("Gitea Version: " + gitea.get_version())
print("API-Token belongs to user: " + gitea.get_user().username)

# Gitlab markdown : https://docs.gitlab.com/ee/user/markdown.html
# Jira text formatting notation : https://jira.atlassian.com/secure/WikiRendererHelpAction.jspa?section=all


def multiple_replace(text, adict):
    if text is None:
        return ''
    t = text
    t = re.sub(r'\xa0', ' ', t) # hard white

    t = re.sub(r'(\r\n){1}', r'  \1', t)  # line breaks
    t = re.sub(r'\{code:([a-z]+)\}\s*', r'\n```\1\n', t)  # Block code
    t = re.sub(r'\{code\}\s*', r'\n```\n', t)  # Block code
    t = re.sub(r'\n\s*bq\. (.*)\n', r'\n\> \1\n', t)  # Block quote
    t = re.sub(r'\{quote\}', r'\n\>\>\>\n', t)  # Block quote #2
    t = re.sub(r'\{color:[\#\w]+\}(.*)\{color\}', r'> **\1**', t)  # Colors
    t = re.sub(r'\n-{4,}\n', r'---', t)  # Ruler
    t = re.sub(r'\[~([a-z]+)\]', r'@\1', t)  # Links to users
    t = re.sub(r'\[([^|\]]*)\]', r'\1', t)  # Links without alt
    t = re.sub(r'\[(?:(.+)\|)([a-z]+://.+)\]',
               r'[\1](\2)', t)  # Links with alt
    t = re.sub(r'(\b%s-\d+\b)' % JIRA_PROJECT,
               r'[\1](%sbrowse/\1)' % JIRA_URL, t)  # Links to other issues
    # Lists
    t = re.sub(r'\n *\# ', r'\n 1. ', t)  # Ordered list
    t = re.sub(r'\n *[\*\-\#]\# ', r'\n   1. ', t)  # Ordered sub-list
    t = re.sub(r'\n *[\*\-\#]{2}\# ', r'\n     1. ', t)  # Ordered sub-sub-list
    t = re.sub(r'\n *\* ', r'\n - ', t)  # Unordered list
    t = re.sub(r'\n *[\*\-\#][\*\-] ', r'\n   - ', t)  # Unordered sub-list
    # Unordered sub-sub-list
    t = re.sub(r'\n *[\*\-\#]{2}[\*\-] ', r'\n     - ', t)
    # Text effects
    t = re.sub(r'(^|[\W])\*(\S.*\S)\*([\W]|$)', r'\1**\2**\3', t)  # Bold
    t = re.sub(r'(^|[\W])_(\S.*\S)_([\W]|$)', r'\1*\2*\3', t)  # Emphasis
    # Deleted / Strikethrough
    t = re.sub(r'(^|[\W])-(\S.*\S)-([\W]|$)', r'\1~~\2~~\3', t)
    t = re.sub(r'(^|[\W])\+(\S.*\S)\+([\W]|$)', r'\1__\2__\3', t)  # Underline
    t = re.sub(r'(^|[\W])\{\{(.*)\}\}([\W]|$)', r'\1`\2`\3', t)  # Inline code
    # Titles
    t = re.sub(r'\n?\bh1\. ', r'\n# ', t)
    t = re.sub(r'\n?\bh2\. ', r'\n## ', t)
    t = re.sub(r'\n?\bh3\. ', r'\n### ', t)
    t = re.sub(r'\n?\bh4\. ', r'\n#### ', t)
    t = re.sub(r'\n?\bh5\. ', r'\n##### ', t)
    t = re.sub(r'\n?\bh6\. ', r'\n###### ', t)
    # Emojis : https://emoji.codes
    t = re.sub(r':\)', r':smiley:', t)
    t = re.sub(r':\(', r':disappointed:', t)
    t = re.sub(r':P', r':yum:', t)
    t = re.sub(r':D', r':grin:', t)
    t = re.sub(r';\)', r':wink:', t)
    t = re.sub(r'\(y\)', r':thumbsup:', t)
    t = re.sub(r'\(n\)', r':thumbsdown:', t)
    t = re.sub(r'\(i\)', r':information_source:', t)
    t = re.sub(r'\(/\)', r':white_check_mark:', t)
    t = re.sub(r'\(x\)', r':x:', t)
    t = re.sub(r'\(!\)', r':warning:', t)
    t = re.sub(r'\(\+\)', r':heavy_plus_sign:', t)
    t = re.sub(r'\(-\)', r':heavy_minus_sign:', t)
    t = re.sub(r'\(\?\)', r':grey_question:', t)
    t = re.sub(r'\(on\)', r':bulb:', t)
    # t = re.sub(r'\(off\)', r'::', t) # Not found
    t = re.sub(r'\(\*[rgby]?\)', r':star:', t)
    for k, v in adict.items():
        t = re.sub(k, v, t)
    return t

# We use UUID in place of the filename to prevent 500 errors on unicode chars


def move_attachements(gitea, attachments,gitea_repo, gitea_issue_nr):
    replacements = {}
    if len(attachments):
        for attachment in attachments:
            author = attachment['author']['displayName']

            _file = requests.get(
                attachment['content'],
                auth=HTTPBasicAuth(*JIRA_ACCOUNT),
                verify=VERIFY_SSL_CERTIFICATE,
            )

            _content = BytesIO(_file.content)

            repo_owner = gitea_repo.owner.name
            repo_name = gitea_repo.name

            myHeaders = gitea.headers.copy()
            myHeaders['accept'] = "application/json"
            myHeaders['Content-Type'] = "multipart/form-data"

            giteaFilename = attachment['filename']

            file_info = requests.post(
                gitea.url + '/api/v1/repos/' + repo_owner +'/' + repo_name + '/issues/' + str(gitea_issue_nr) + '/assets' + '?name=' + giteaFilename,
                headers=myHeaders,
                files={
                    'file': (
                        '@' + giteaFilename,
                        _content,
                        "application/pdf"
                    )
                },
                verify=VERIFY_SSL_CERTIFICATE
            ).json()

            del _content

            # now we got the upload URL. Let's post the comment with an
            # attachment
            if 'url' in file_info:
                key = "!%s[^!]*!" % attachment['filename']
                value = "![%s](%s)" % (
                    attachment['filename'], file_info['url'])
                replacements[key] = value
    return replacements

def move_attachements_new(attachments, repo, issue_nr):

    CREATE_ASSET = """/repos/{owner}/{repo}/issues/{issue}/assets?name={name}"""

    replacements = {}
    if len(attachments):
        for attachment in attachments:
            author = attachment['author']['displayName']

            _file = requests.get(
                attachment['content'],
                auth=HTTPBasicAuth(*JIRA_ACCOUNT),
                verify=VERIFY_SSL_CERTIFICATE,
            )

            _content = BytesIO(_file.content)

            if GITLAB_SUDO:
                GITLAB_HEADERS['Sudo'] = resolve_login(author)

            args = {"owner": repo.owner.username, "repo": repo.name, "issue": issue_nr, "name": "MY-ATTACHMENT" }
            data = {"title": title, "body": body}
            result = gitea.requests_post(CREATE_ASSET.format(**args), data=data)


            file_info = requests.post(
                GITEA_URL + '/api/v1/repos/' + repo_owner +'/' + repo_name + '/issues/' + str(gitea_issue_nr) + '/assets',
                headers=GITLAB_HEADERS,
                files={
                    'file': (
                        str(uuid.uuid4()),
                        _content
                    )
                },
                verify=VERIFY_SSL_CERTIFICATE
            ).json()

            del _content

            # now we got the upload URL. Let's post the comment with an
            # attachment
            if 'url' in file_info:
                key = "!%s[^!]*!" % attachment['filename']
                value = "![%s](%s)" % (
                    attachment['filename'], file_info['url'])
                replacements[key] = value
    return replacements


def create_comment(gitea, repo: Repository, issue_nr, title: str, body: str = ""):
    CREATE_COMMENT = """/repos/{owner}/{repo}/issues/{issue}/comments"""

    args = {"owner": repo.owner.username, "repo": repo.name, "issue": issue_nr }
    data = {"title": title, "body": body}
    result = gitea.requests_post(CREATE_COMMENT.format(**args), data=data)
    return Issue.parse_response(gitea, result)


# if you use milestones to track sprints
# def get_milestone_id(string):
#     for milestone in gl_milestones:
#         if milestone['title'] == string:
#             return milestone['id']
#
#     # Milestone doesn't yet exist, so we create it
#     milestone = requests.post(
#         GITEA_URL + 'api/v4/projects/{}/{}'.format(GITLAB_PROJECT_ID,GITLAB_SPRINT_TYPE),
#         headers=GITLAB_HEADERS,
#         verify=VERIFY_SSL_CERTIFICATE,
#         data={
#             'title': string
#         }
#     ).json()
#     gl_milestones.append(milestone)
#
#     return milestone['id']

# Get the user name from the GITLAB_USER_NAMES dict
# Or if logins match between Jira and Gitlab, use it
# In other cases (eg. inactive Jira user not created in Gitlab) we use GITLAB_ACCOUNT

def resolve_login(jira_user):
    if jira_user in GITLAB_USER_NAMES:
        return GITLAB_USER_NAMES[jira_user]
    for user in gitea_org_members:
        if user.full_name == jira_user:
            return user.username
    return GITLAB_ACCOUNT[0]

def createLabel(project_id, labelName, labelType):

    project = gl.projects.get(project_id) #get project info

    color = '#6699cc'
    if labelType == 'release':
        color = '#c39953'
    elif labelType == 'component':
        color = '##f7e7ce'
    elif labelType == 'status':
        color = '#3cb371'
    elif labelType == 'epic':
        color = '#5555ff'
    
    label = project.labels.create({'name': labelName, 'color': color})


def createAllWorkflowLabels(project_id):
    createLabel(project_id, 'Needs specification', 'status')
    createLabel(project_id, 'Specification in Progress', 'status')
    createLabel(project_id, 'Specification Done', 'status')
    createLabel(project_id, 'Ready for Development', 'status')
    createLabel(project_id, 'Development in Progress', 'status')
    createLabel(project_id, 'Ready for Testing', 'status')
    createLabel(project_id, 'Testing in progress', 'status')
    createLabel(project_id, 'Needs Development', 'status')


## Code below is not used due to the fact that we have multiple projects in
## Gitlab compared to how Jira handles issues
# if not GITLAB_PROJECT_ID:
#     # find out the ID of the project.
#     result = requests.get(GITEA_URL + 'api/v4/projects',headers={'PRIVATE-TOKEN': GITLAB_TOKEN},verify=VERIFY_SSL_CERTIFICATE)
#     for project in requests.get(
#         GITEA_URL + 'api/v4/projects',
#         headers=GITLAB_HEADERS,
#         verify=VERIFY_SSL_CERTIFICATE
#     ).json():
#         if project['path_with_namespace'] == GITLAB_PROJECT:
#             GITLAB_PROJECT_ID = project['id']
#             break
#
# if not GITLAB_PROJECT_ID:
#     raise Exception("Unable to find %s in gitlab!" % GITLAB_PROJECT)

# Get all the milestones for multiple projects
# def get_all_milestones(p_id):
#     gl_milestones = requests.get(
#         GITEA_URL + "api/v4/projects/{}/{}".format(p_id,GITLAB_SPRINT_TYPE),
#         headers=GITLAB_HEADERS,
#         verify=VERIFY_SSL_CERTIFICATE
#     ).json()
#     return gl_milestones

# Get epic or create one if it doesn't exist
def get_epic_id(project_id,epic_title):
    project = gl.projects.get(project_id) #get project info
    parentProject = project.namespace['parent_id']
    
    try:
        group = gl.groups.get(parentProject) #get group info for project parent
        epics = group.epics.list() #get all the epics

        for epic in epics:
            if epic.title == epic_title:
                return epic
        # Epic doesn't exist, so let's create it
        new_epic = group.epics.create({"title":epic_title})
        new_epic.labels = DEFAULT_LABELS.copy()
        new_epic.save()
        return new_epic
    
    except :
        pass

# Get all of the Gitea users in the configured organization

solmeAB_org =  Organization.request(gitea, GITEA_SELECTED_ORG)
gitea_org_members = solmeAB_org.get_members()

def resolve_username_from_displayname(jira_display_name):
    
    gitea_user = ''
    for user in gitea_org_members:
        if user.full_name == jira_display_name:
            gl_assignee = user.id
            gitea_user = user.username
            break

    return gitea_user

# Get all of the milestones for the project(s)
# gl_milestones = []
# for pid in PROJECT_MAP.values():
#     gl_milestones.append(get_all_milestones(pid))

# Read all of the existing issues we have migrated from file
if ISSUE_TRACKING:
    try:
        with open(TRACKING_FILE, 'r') as tracking_file:
            processed_jiras = tracking_file.read().splitlines()
    except IOError:
        processed_jiras = []

# Jira API documentation : https://developer.atlassian.com/static/rest/jira/6.1.html
jira_issues = requests.get(
    JIRA_URL + 'rest/api/2/search?jql=' + JQL,
    auth=HTTPBasicAuth(*JIRA_ACCOUNT),
    verify=VERIFY_SSL_CERTIFICATE,
    headers={'Content-Type': 'application/json'}
).json()['issues']

for issue in jira_issues:

    jiraProjectName = issue['fields']['project']['key']

    if ISSUE_TRACKING and (issue['key'] in processed_jiras):
        print("{} is already imported".format(issue['key']))
        continue
    else:
        print("migrating issue: {}".format(issue['fields']['summary']))
        jiraIssueTypeName = issue['fields']['issuetype']['name'];
        if jiraIssueTypeName not in ISSUE_TYPES_MAP:
            print("Missing Jira to GITLab mapping for Jira issue type: {}".format(jiraIssueTypeName))
            continue

        #hardcoded project-mapping
        gitlabProjectName = ''

        if jiraProjectName in PROJECT_MAPPING:
            jiraProjectMapping = PROJECT_MAPPING[jiraProjectName]
            
            jiraLabels = issue['fields']['labels']
            gitlabProjectName = jiraProjectMapping.get('DEFAULT', '')

            for jiraLabel in jiraLabels:
                if jiraLabel in jiraProjectMapping:
                    gitlabProjectName = jiraProjectMapping[jiraLabel]
                    break

        if gitlabProjectName == '':
            print("No project mapping found for '" + jiraProjectName + "' and labels " + str(jiraLabels)[1:-1] )
            continue

        #map jira user to GL user
        gitea_assignee = ''

        if issue['fields']['assignee']:
           jirAssigneeDisplayName = issue['fields']['assignee']['displayName']
           
           gitea_assignee = resolve_username_from_displayname(jirAssigneeDisplayName)

        if gitea_assignee == '':
            print("No User with full name '" + jirAssigneeDisplayName + "' found in Gitea. Skipping issue" )
            continue

        # Handle labels
        labels = [ISSUE_TYPES_MAP[issue['fields']['issuetype']['name']]]

        #Add current Status as label
#        if issue['fields']['status']['statusCategory']['name'] == "In Progress":
        labels.append(issue['fields']['status']['name'])

        #Add components as labels
        jiraComponenets = issue['fields']['components']

        for comp in jiraComponenets:
            if comp['name'] in COMPONENT_MAP:
                labels.append(comp['name'])
            else:
                print("Uknown component! {}".format(comp['name']))

        #Add fixVersions as labels
        jiraFixVersions = issue['fields']['fixVersions']

        for fixVersion in jiraFixVersions:
            if fixVersion != None:
                labels.append(fixVersion['name'])


        # Add Epic name to labels
        if issue['fields'][JIRA_EPIC_FIELD]:
            epic_info = requests.get(
                JIRA_URL + 'rest/api/2/issue/%s/?fields=summary' % issue['fields'][JIRA_EPIC_FIELD],
                auth=HTTPBasicAuth(*JIRA_ACCOUNT),
                verify=VERIFY_SSL_CERTIFICATE,
                headers={'Content-Type': 'application/json'}
            ).json()
            labels.append(epic_info['fields']['summary'])

        # Use the name of the last sprint as milestone
        # milestone_id = None
        milestone_name = ''
        if issue['fields'][JIRA_SPRINT_FIELD]:
            for sprint in issue['fields'][JIRA_SPRINT_FIELD]:
                if isinstance(sprint, str):
                    sprint = sprint[sprint.find('[')+1:sprint.find(']')]
                    assignments = sprint.split(',')
                    sprint = dict()
                    for assignment in assignments:
                        assignment = assignment.split('=')
                        sprint[assignment[0]]=assignment[1]

                if sprint['name']:
                    name = sprint['name']
                    milestone_name = sprint['name']
        #     if name:
        #         # milestone_id = get_milestone_id(m.group(1))
        #         milestone_id = get_milestone_id(name)

        # # Gitlab expect the timezone in +00:00 format without milliseconds while Jira gives +0000 with milliseconds
        reporter = issue['fields']['reporter']['displayName']

        # get comments and attachments from Jira
        issue_info = requests.get(
            JIRA_URL + 'rest/api/2/issue/%s/?fields=attachment,comment' % issue['id'],
            auth=HTTPBasicAuth(*JIRA_ACCOUNT),
            verify=VERIFY_SSL_CERTIFICATE,
            headers={'Content-Type': 'application/json'}
        ).json()

        # Here we loop through each project for the inserts since we map certain Jira
        # components to certain projects in GL
        if gitlabProjectName != '':

            gl_project = None

            target_gitea_repository = solmeAB_org.get_repository(gitlabProjectName)

            title = issue['fields']['summary'] + " (" + issue['key'] + ")"

            # Add issue to Gitlab

            # Add sudo header if appropriate
            if GITLAB_SUDO:
                GITLAB_HEADERS['Sudo'] = resolve_login(reporter)

            gitea_assignees = [gitea_assignee]
            gitea_issue = target_gitea_repository.create_issue(title,  gitea_assignees, "NOT-IMPORTED-YET")
            gitea_issue_nr = gitea_issue.number
            gitea_issue_id = gitea_issue.id

            # TODO: add labels, created date, milestone etc

            replacements = move_attachements(gitea, issue_info['fields']['attachment'], target_gitea_repository, gitea_issue_nr)

            originalJiraBody = issue['fields']['description']

            #build out the description
            description = ""
            description = multiple_replace(originalJiraBody, replacements)

            #Add a link to the Jira issue in the description
            if ADD_A_LINK:
                description = description + "\n\nImported from Jira issue [%(k)s](%(u)sbrowse/%(k)s)" % {'k': issue['key'], 'u': JIRA_URL}

            # Add the reporter to the description
            description = description + "Originally reported by {}\n\n".format(reporter)
            
            # Add the Jira sprint information to Gitlab issue description
            if ADD_SPRINT_COMMENT:
                if milestone_name != '':
                    description = description + "\n\nOriginal Jira sprint name {}".format(milestone_name)

            # Add labels we have added from Jira plus project specific ones
            newlabels = labels.copy()

            milestone_id = 1

            # print("Project ID {}".format(gitlabProjectId))

            gitea_issue.body = description
            
            gitea_issue.commit()

            data = {
                'assignee_ids': [gitea_assignee],
                'title': title,
                'description': description,
                'milestone_id': milestone_id,
                'labels': ", ".join(newlabels),
                'created_at': issue['fields']['created']
            }

            # Issue weight
            if JIRA_STORY_POINTS_FIELD in issue['fields'] and issue['fields'][JIRA_STORY_POINTS_FIELD]:
                data['weight'] = STORY_POINTS_MAP[issue['fields'][JIRA_STORY_POINTS_FIELD]]


            # Recreate each Jira comment in Gitlab
            for comment in issue_info['fields']['comment']['comments']:
                author = comment['author']['displayName']
                author_username = resolve_username_from_displayname(author)

                commentbody = ""
                # Add sudo header if appropriate
                if GITLAB_SUDO:
                    sudo_user = resolve_login(author)
                    GITLAB_HEADERS['Sudo'] = sudo_user
                else:
                    commentbody = 'Original comment by {}\n\n'.format(author)
                commentbody = commentbody + multiple_replace(comment['body'], replacements)
                body = {'body':commentbody}
                comment_note = create_comment(gitea,target_gitea_repository, gitea_issue_nr, "title?", commentbody)
                print("test")

            # If Jira has an epic associted with it, move that epic and relationship over
#            if issue['fields'][JIRA_EPIC_FIELD]:
#                # print(epic_info['fields']['summary'])
#                epic = get_epic_id(gitlabProjectId,epic_info['fields']['summary'])
#                ei = epic.issues.create({'issue_id':gl_issue.id})

            # If the Jira issue was closed, mark the Gitlab one closed as well
            if issue['fields']['status']['statusCategory']['key'] == "done":
#                gitea_issue.state = Issue.CLOSED
                gitea_issue.commit()
            if ISSUE_TRACKING:
                with open(TRACKING_FILE, 'a') as tracking_file:
                    tracking_file.write(issue['key']+'\n')
                processed_jiras.append(issue['key'])
