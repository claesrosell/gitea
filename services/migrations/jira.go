// Copyright 2021 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package migrations

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"code.gitea.io/gitea/modules/log"
	base "code.gitea.io/gitea/modules/migration"
	"code.gitea.io/gitea/modules/structs"
	"github.com/google/uuid"
)

const (
	JiraTimeFormat = "2006-01-02T15:04:05.999-0700"
	JiraDateFormat = "2006-01-02"
)

var (
	_ base.Downloader        = &JiraDownloader{}
	_ base.DownloaderFactory = &JiraDownloaderFactory{}
)

func init() {
	RegisterDownloaderFactory(&JiraDownloaderFactory{})
}

type JiraExtraOptions struct {
	// defining struct variables
	Url        string `json:"jira_url"`
	ProjectKey string `json:"jira_project_key"`
	UserName   string `json:"jira_username"`
	Password   string `json:"jira_password"`
}

type JiraUser struct {
	userNumber  int
	name        string
	email       string
	displayName string
}

// JiraDownloaderFactory defines a Jira downloader factory
type JiraDownloaderFactory struct{}

// New returns a Downloader related to this factory according MigrateOptions
func (f *JiraDownloaderFactory) New(ctx context.Context, opts base.MigrateOptions) (base.Downloader, error) {
	u, err := url.Parse(opts.CloneAddr)
	if err != nil {
		return nil, err
	}

	fields := strings.Split(u.Path, "/")
	if len(fields) < 2 {
		return nil, fmt.Errorf("invalid path: %s", u.Path)
	}
	baseURL := u.Scheme + "://" + u.Host + strings.TrimSuffix(strings.Join(fields[:len(fields)-2], "/"), "/git")

	oldOwner := fields[len(fields)-2]
	oldName := strings.TrimSuffix(fields[len(fields)-1], ".git")

	log.Trace("Create Jira downloader. BaseURL: %s RepoOwner: %s RepoName: %s", baseURL, oldOwner, oldName)

	var jiraExtraOptions JiraExtraOptions

	json.Unmarshal([]byte(opts.Description), &jiraExtraOptions)

	return NewJiraDownloader(ctx, baseURL, opts.AuthUsername, opts.AuthPassword, opts.AuthToken, oldOwner, oldName, jiraExtraOptions), nil
}

// GitServiceType returns the type of git service
func (f *JiraDownloaderFactory) GitServiceType() structs.GitServiceType {
	return structs.JiraService
}

// JiraDownloader implements a Downloader interface to get repository information
// from Jira via GithubDownloader
type JiraDownloader struct {
	base.NullDownloader
	ctx                context.Context
	bitbucketClient    *http.Client
	jiraClient         *http.Client
	bitbucketBaseUrl   string
	jiraBaseUrl        string
	repoOwner          string
	repoName           string
	userName           string
	password           string
	curClientIdx       int
	maxPerPage         int
	SkipReactions      bool
	SkipReviews        bool
	jiraProjectKey     string
	currentIssueNumber int64
	userIdMap          map[int]*JiraUser
	userEmailMap       map[string]*JiraUser
}

type jiraIssueContext struct {
	BogusField  bool // Not used
	OriginalKey string
}

// String implements Stringer
func (g *JiraDownloader) String() string {
	return fmt.Sprintf("migration from Jira server %s %s/%s", g.bitbucketBaseUrl, g.repoOwner, g.repoName)
}

func (g *JiraDownloader) LogString() string {
	if g == nil {
		return "<JiraDownloader nil>"
	}
	return fmt.Sprintf("<JiraDownloader %s %s/%s>", g.bitbucketBaseUrl, g.repoOwner, g.repoName)
}

// NewJiraDownloader creates a Jira downloader
func NewJiraDownloader(ctx context.Context, baseURL, userName, password, token, repoOwner, repoName string, jiraExtraOptions JiraExtraOptions) *JiraDownloader {
	JiraDownloader := JiraDownloader{}
	JiraDownloader.bitbucketBaseUrl = baseURL
	JiraDownloader.bitbucketClient = &http.Client{
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				if len(userName) > 0 && len(password) > 0 {
					req.SetBasicAuth(userName, password)
				}
				return nil, nil
			},
		},
	}
	JiraDownloader.jiraBaseUrl = jiraExtraOptions.Url
	JiraDownloader.jiraClient = &http.Client{
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				if len(jiraExtraOptions.UserName) > 0 && len(jiraExtraOptions.Password) > 0 {
					req.SetBasicAuth(jiraExtraOptions.UserName, jiraExtraOptions.Password)
				}
				return nil, nil
			},
		},
	}

	JiraDownloader.repoName = repoName
	JiraDownloader.repoOwner = repoOwner
	JiraDownloader.currentIssueNumber = 1
	JiraDownloader.userIdMap = make(map[int]*JiraUser)
	JiraDownloader.userEmailMap = make(map[string]*JiraUser)
	JiraDownloader.jiraProjectKey = jiraExtraOptions.ProjectKey

	return &JiraDownloader
}

// SupportGetRepoComments return true if it supports get repo comments
func (g *JiraDownloader) SupportGetRepoComments() bool {
	return false
}

// GetRepoInfo returns repository information
func (d *JiraDownloader) GetRepoInfo() (*base.Repository, error) {
	//	info := make([]struct {
	//		ID          int64  `json:"id"`
	//		Name        string `json:"name"`
	//		Description string `json:"description"`
	//	}, 0, 1)

	//	resp, err := d.bitbucketClient.Get(fmt.Sprintf("%s/rest/api/2/project/%s", d.bitbucketBaseUrl, "AVIX")) // Get project name from settings.
	//	if err != nil {
	//		return nil, err
	//	}

	//	body, err := io.ReadAll(resp.Body)
	//	fmt.Println(string(body))
	//	defer resp.Body.Close()

	// Get all users and populate map!
	body, err := d.callApi(fmt.Sprintf("%srest/api/2/user/search?username=.&includeInactive=true", d.jiraBaseUrl))
	// Parse JSON into an empty interface
	var result interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, nil
	}

	// Accessing dynamic JSON fields
	userList, ok := result.([]interface{})
	if !ok {
		return nil, nil
	}

	for index, userEntry := range userList {
		userMap := userEntry.(map[string]interface{})
		name := userMap["name"].(string)

		components := strings.Split(name, "@")
		if len(components) > 1 {
			name, _ = components[0], components[1]
		}

		jiraUser := &JiraUser{
			userNumber:  index,
			name:        name,
			email:       userMap["emailAddress"].(string),
			displayName: userMap["displayName"].(string),
		}
		d.userIdMap[jiraUser.userNumber] = jiraUser
		d.userEmailMap[jiraUser.email] = jiraUser
	}

	return &base.Repository{
		Name:        "Test name",
		Description: "Test description",
		CloneURL:    fmt.Sprintf("%s/%s/%s.git", d.bitbucketBaseUrl, d.repoOwner, d.repoName),
		//		OriginalURL: originalURL.String(),
	}, nil
}

// GetLabels returns labels
func (d *JiraDownloader) GetLabels() ([]*base.Label, error) {
	labels := make([]*base.Label, 0, d.maxPerPage)

	body, err := d.callApi(fmt.Sprintf("%srest/api/2/project/%s", d.jiraBaseUrl, d.jiraProjectKey))

	// Parse JSON into an empty interface
	var result interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, nil
	}

	// Accessing dynamic JSON fields
	projectInfo, ok := result.(map[string]interface{})
	if !ok {
		return nil, nil
	}

	// Handling components
	componentsList := projectInfo["components"].([]interface{})
	for _, componentEntry := range componentsList {
		componentMap := componentEntry.(map[string]interface{})

		description := ""
		if componentMap["description"] != nil {
			description = componentMap["description"].(string)
		}

		createdLabel := &base.Label{
			Name:        fmt.Sprintf("Component/%s", componentMap["name"].(string)),
			Description: description,
			Color:       "#009999",
			Exclusive:   true,
		}
		labels = append(labels, createdLabel)
	}

	// Handling Issue types
	issueTypesList := projectInfo["issueTypes"].([]interface{})
	for _, issueTypeEntry := range issueTypesList {
		issueTypeMap := issueTypeEntry.(map[string]interface{})

		description := ""
		if issueTypeMap["description"] != nil {
			description = issueTypeMap["description"].(string)
		}

		createdLabel := &base.Label{
			Name:        fmt.Sprintf("IssueType/%s", issueTypeMap["name"].(string)),
			Description: description,
			Color:       "#009900",
			Exclusive:   true,
		}
		labels = append(labels, createdLabel)
	}
	return labels, nil
}

// GetMilestones returns milestones
func (d *JiraDownloader) GetMilestones() ([]*base.Milestone, error) {
	milestones := make([]*base.Milestone, 0, d.maxPerPage)
	body, err := d.callApi(fmt.Sprintf("%srest/api/2/project/%s", d.jiraBaseUrl, d.jiraProjectKey))

	// Parse JSON into an empty interface
	var result interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, nil
	}

	// Accessing dynamic JSON fields
	projectInfo, ok := result.(map[string]interface{})
	if !ok {
		return nil, nil
	}

	// Handling versions
	versionsList := projectInfo["versions"].([]interface{})
	for _, versionEntry := range versionsList {
		versionMap := versionEntry.(map[string]interface{})

		todayStr := time.Now().Local().Format(JiraDateFormat)
		bool(versionMap["archived"])
		versionMap["releaseDate"].(string) // Planned date?
		time.Parse(JiraDateFormat, "")

		versionMap["userReleaseDate"].(string) // Actual date?

		state := "open"
		released, err := strconv.ParseBool(versionMap["released"].(string))
		if err == nil && !released {
			state = "closed"
		}

		createdMilestone := &base.Milestone{
			Title:       versionMap["name"].(string),
			Description: "",
			Created:     createdAT,
			Updated:     updatedAT,
			Closed:      ms[i].Closed,
			State:       state,
		}
		milestones = append(milestones, createdMilestone)
	}

	return milestones, nil
}

// GetIssues returns issues
func (d *JiraDownloader) GetIssues(page, perPage int) ([]*base.Issue, bool, error) {
	allIssues := make([]*base.Issue, 0, 10)

	//	issues := make([]*base.Issue, 0, len(rawIssues))
	//	allIssues = append(allIssues, convertJiraIssue(issue))
	jiraJql := "issuekey%20in(AVIX-7259,AVIX-7293)"
	body, err := d.callApi(fmt.Sprintf("%srest/api/2/search?jql=%s", d.jiraBaseUrl, jiraJql))

	// Parse JSON into an empty interface
	var result interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, true, nil
	}

	// Accessing dynamic JSON fields
	dataMap, ok := result.(map[string]interface{})
	if !ok {
		return nil, true, nil
	}

	jiraIssues, jiraIssuesExists := dataMap["issues"].([]interface{})
	if jiraIssuesExists {
		for _, jiraIssue := range jiraIssues {
			jiraIssueMap := jiraIssue.(map[string]interface{})
			convertedIssue := d.HandleJiraIssue(jiraIssueMap)
			convertedIssue.Number = d.currentIssueNumber
			d.currentIssueNumber = d.currentIssueNumber + 1

			allIssues = append(allIssues, convertedIssue)
		}
	}

	return allIssues, true, nil
}

func (d *JiraDownloader) callApi(endpoint string) ([]byte, error) {
	//
	req, err := http.NewRequest("GET", endpoint, nil)
	req.Header.Set("Content-Type", "application/json")

	if err != nil {
		return nil, err
	}

	resp, err := d.jiraClient.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()
	return body, err
}

func (d *JiraDownloader) HandleJiraIssue(issue map[string]interface{}) *base.Issue {
	issueKey := issue["key"].(string)

	issueInfoRequestUrl := fmt.Sprintf("%srest/api/2/issue/%s?expand=changelog", d.jiraBaseUrl, issueKey)

	body, err := d.callApi(issueInfoRequestUrl)
	// Parse JSON into an empty interface
	var result interface{}
	err = json.Unmarshal(body, &result)

	// Accessing dynamic JSON fields
	issue, ok := result.(map[string]interface{})
	if !ok {
		return nil
	}

	issueFieldsMap := issue["fields"].(map[string]interface{})
	title := fmt.Sprintf("%s %s", issue["key"].(string), issueFieldsMap["summary"].(string))
	reporterMap := issueFieldsMap["reporter"].(map[string]interface{})
	reporterEmail := reporterMap["emailAddress"].(string)

	created, err := time.Parse(JiraTimeFormat, issueFieldsMap["created"].(string))
	if err != nil {
		created = time.Now()
	}

	updated, err := time.Parse(JiraTimeFormat, issueFieldsMap["updated"].(string))
	if err != nil {
		updated = time.Now()
	}

	description := issueFieldsMap["description"]
	originalJiraBody := ""
	if description != nil {
		originalJiraBody = issueFieldsMap["description"].(string)
	}

	content := multipleReplace(originalJiraBody, nil, d.jiraProjectKey, "")

	jiraUser := d.getJiraUserByEmail(reporterEmail)

	// Handle attachments
	attachmentList := issueFieldsMap["attachment"].([]interface{})
	resultingAttachments := make([]*base.Attachment, 0, 10)
	if attachmentList != nil {
		for _, attachmentEntry := range attachmentList {
			attachmentMap := attachmentEntry.(map[string]interface{})
			attachmentId, _ := strconv.ParseInt((attachmentMap["id"].(string)), 10, 64)
			attachmentName := attachmentMap["filename"].(string)
			attachmentCreated, err := time.Parse(JiraTimeFormat, attachmentMap["created"].(string))
			if err != nil {
				attachmentCreated = time.Now()
			}
			attachmentMime := attachmentMap["mimeType"].(string)
			tempAttachmentSize, _ := attachmentMap["size"].(float64) // strconv.ParseFloat(attachmentMap["size"].(string), 64)
			attachmentSize := int(tempAttachmentSize)
			attachmentDownloadUrl := attachmentMap["content"].(string)
			attachmentStringID := fmt.Sprintf("jira:%s", attachmentMap["id"].(string))
			tempUUID, _ := nameUUIDFromBytes([]byte(attachmentStringID))
			attachmentUUID := tempUUID.String()

			attachmentObj := &base.Attachment{
				ID:          attachmentId,
				UUID:        attachmentUUID,
				Name:        attachmentName,
				Size:        &attachmentSize,
				ContentType: &attachmentMime,
				Created:     attachmentCreated,
				DownloadFunc: func() (io.ReadCloser, error) {
					req, err := http.NewRequest("GET", attachmentDownloadUrl, nil)
					resp, err := d.jiraClient.Do(req)

					if err != nil {
						return nil, err
					}

					// resp.Body is closed by the uploader
					return resp.Body, nil
				},
			}
			resultingAttachments = append(resultingAttachments, attachmentObj)
		}
	}

	return &base.Issue{
		Title:       title,
		Content:     content,
		PosterID:    int64(jiraUser.userNumber),
		PosterEmail: jiraUser.email,
		PosterName:  jiraUser.name,
		Created:     created,
		Updated:     updated,
		Context:     jiraIssueContext{BogusField: false, OriginalKey: issue["key"].(string)},
		Attachments: resultingAttachments,
		/*		Number:       issue.Index,
				PosterID:     issue.Poster.ID,
				PosterName:   issue.Poster.Login,
				PosterEmail:  issue.Poster.Email,
				Content:      issue.Body,
				Milestone:    milestone,
				State:        string(issue.State),
				Created:      issue.Created,
				Updated:      issue.Updated,
				Labels:       labels,
				Closed:       closed,
				ForeignIndex: issue.Index,*/
	}
}

func nameUUIDFromBytes(name []byte) (uuid.UUID, error) {
	md := md5.New()
	_, err := md.Write(name)
	if err != nil {
		return uuid.Nil, err
	}

	md5Bytes := md.Sum(nil)

	// Set version (4 most significant bits to 0011)
	md5Bytes[6] &= 0x0f
	md5Bytes[6] |= 0x30

	// Set variant (2 most significant bits to 10)
	md5Bytes[8] &= 0x3f
	md5Bytes[8] |= 0x80

	return uuid.FromBytes(md5Bytes)
}

// GetComments returns comments
func (d *JiraDownloader) GetComments(commentable base.Commentable) ([]*base.Comment, bool, error) {
	context, ok := commentable.GetContext().(jiraIssueContext)
	if !ok {
		return nil, false, fmt.Errorf("unexpected context: %+v", context)
	}

	changeLogRequestUrl := fmt.Sprintf("%srest/api/2/issue/%s?expand=changelog", d.jiraBaseUrl, context.OriginalKey)
	body, err := d.callApi(changeLogRequestUrl)
	if err != nil {
		return nil, true, err
	}

	// Parse JSON into an empty interface
	var result interface{}
	err = json.Unmarshal(body, &result)

	// Accessing dynamic JSON fields
	dataMap, ok := result.(map[string]interface{})
	if !ok {
		return nil, true, nil
	}

	fieldsMap := dataMap["fields"].(map[string]interface{})
	changeLogMap, changeLogExists := dataMap["changelog"].(map[string]interface{})
	commentMap, commentsEntriesExists := fieldsMap["comment"].(map[string]interface{})
	commentsEntries := commentMap["comments"].([]interface{})

	comments := make([]*base.Comment, 0, 10)
	if changeLogExists {
		historiesEntry := changeLogMap["histories"].([]interface{})

		for _, historyEntry := range historiesEntry {
			historyEntryMap := historyEntry.(map[string]interface{})
			giteaComments := d.convertJiraChangelogEntry(historyEntryMap)

			for _, createdComment := range giteaComments {
				createdComment.IssueIndex = commentable.GetLocalIndex()
			}

			comments = append(comments, giteaComments...)
		}
	}

	if commentsEntriesExists {
		for _, commentEntry := range commentsEntries {
			commentMap := commentEntry.(map[string]interface{})
			giteaComment := d.convertJiraCommentEntry(commentMap)
			if giteaComment != nil {
				giteaComment.IssueIndex = commentable.GetLocalIndex()
				comments = append(comments, giteaComment)
			}
		}
	}

	return comments, true, nil
}

func (d *JiraDownloader) convertJiraCommentEntry(commentEntryMap map[string]interface{}) *base.Comment {
	commentBody := commentEntryMap["body"].(string)
	authorMap := commentEntryMap["author"].(map[string]interface{})
	created, err := time.Parse(JiraTimeFormat, commentEntryMap["created"].(string))
	if err != nil {
		created = time.Now()
	}
	commentContent := multipleReplace(commentBody, nil, "CUS", "")
	jiraUser := d.getJiraUserByEmail(authorMap["emailAddress"].(string))
	comment := &base.Comment{
		PosterID:    int64(jiraUser.userNumber),
		PosterName:  jiraUser.name,
		PosterEmail: jiraUser.email,
		CommentType: "",
		Content:     commentContent,
		Created:     created,
		Updated:     created,
	}
	return comment
}

func (d *JiraDownloader) convertJiraChangelogEntry(historyEntryMap map[string]interface{}) []*base.Comment {
	authorMap := historyEntryMap["author"].(map[string]interface{})
	itemsList := historyEntryMap["items"].([]interface{})

	created, err := time.Parse(JiraTimeFormat, historyEntryMap["created"].(string))
	if err != nil {
		created = time.Now()
	}

	comments := make([]*base.Comment, 0, 10)
	if len(itemsList) > 0 {
		// Loop through the items to see if the status has changed. If it have, see if it was closed or re-opened
		for _, item := range itemsList {
			itemMap := item.(map[string]interface{})
			changedField := itemMap["field"]

			var commentMetaType string
			var commentContent string

			if changedField == "status" {
				toString := itemMap["toString"].(string)
				fromString := itemMap["fromString"].(string)
				if toString == "Closed" {
					commentMetaType = "close"
					commentContent = "That shit!"
				} else if fromString == "Closed" {
					commentMetaType = "reopen"
					commentContent = toString
				}

				if commentMetaType != "" {
					jiraUser := d.getJiraUserByEmail(authorMap["emailAddress"].(string))
					comment := &base.Comment{
						PosterID:    int64(jiraUser.userNumber),
						PosterName:  jiraUser.name,
						PosterEmail: jiraUser.email,
						CommentType: commentMetaType,
						Content:     commentContent,
						Created:     created,
						Updated:     created,
					}
					comments = append(comments, comment)
				}
			} else if changedField == "assignee" {
				jiraUser := d.getJiraUserByEmail(authorMap["emailAddress"].(string))

				assigneeName := ""
				removedAssigneeName := ""
				if itemMap["to"] != nil {
					assigneeJiraUser := d.getJiraUserByEmail(itemMap["to"].(string))
					if assigneeJiraUser != nil {
						assigneeName = assigneeJiraUser.name
					}
				}

				if itemMap["from"] != nil {
					removedAssigneeJiraUser := d.getJiraUserByEmail(itemMap["from"].(string))
					if removedAssigneeJiraUser != nil {
						removedAssigneeName = removedAssigneeJiraUser.name
					}
				}

				if removedAssigneeName != "" {
					localMeta := make(map[string]interface{})
					localMeta["AssigneeName"] = removedAssigneeName
					localMeta["RemovedAssigneeID"] = "true"

					comment := &base.Comment{
						PosterID:    int64(jiraUser.userNumber),
						PosterName:  jiraUser.name,
						PosterEmail: jiraUser.email,
						CommentType: "assignees",
						Content:     commentContent,
						Created:     created,
						Updated:     created,
						Meta:        localMeta,
					}
					comments = append(comments, comment)
				}

				if assigneeName != "" {
					localMeta := make(map[string]interface{})
					localMeta["AssigneeName"] = assigneeName
					comment := &base.Comment{
						PosterID:    int64(jiraUser.userNumber),
						PosterName:  jiraUser.name,
						PosterEmail: jiraUser.email,
						CommentType: "assignees",
						Content:     commentContent,
						Created:     created,
						Updated:     created,
						Meta:        localMeta,
					}
					comments = append(comments, comment)
				}
			}
		}

	}

	return comments
}

func (d *JiraDownloader) getJiraUserByEmail(userEmail string) *JiraUser {
	return d.userEmailMap[userEmail]
}

func multipleReplace(text string, adict map[string]string, jiraProject string, jiraUrl string) string {
	if text == "" {
		return ""
	}

	t := text
	t = regexp.MustCompile(`\xa0`).ReplaceAllString(t, " ")                                  // hard white
	t = regexp.MustCompile(`(\r\n){1}`).ReplaceAllString(t, "  $1")                          // line breaks
	t = regexp.MustCompile(`\{code:([a-z]+)\}\s*`).ReplaceAllString(t, "\n```$1\n")          // Block code
	t = regexp.MustCompile(`\{code\}\s*`).ReplaceAllString(t, "\n```\n")                     // Block code
	t = regexp.MustCompile(`\n\s*bq\. (.*)\n`).ReplaceAllString(t, "\n> $1\n")               // Block quote
	t = regexp.MustCompile(`\{quote\}`).ReplaceAllString(t, "\n>>>\n")                       // Block quote #2
	t = regexp.MustCompile(`\{color:[\#\w]+\}(.*)\{color\}`).ReplaceAllString(t, "> **$1**") // Colors
	t = regexp.MustCompile(`\n-{4,}\n`).ReplaceAllString(t, "---")                           // Ruler
	t = regexp.MustCompile(`\[~([a-z]+)\]`).ReplaceAllString(t, "@$1")                       // Links to users
	t = regexp.MustCompile(`\[([^|\]]*)\]`).ReplaceAllString(t, "$1")                        // Links without alt
	t = regexp.MustCompile(`\[(?:(.+)\|)([a-z]+://.+)\]`).ReplaceAllString(t, "[$1]($2)")
	t = regexp.MustCompile(`(\b`+jiraProject+`-\d+\b)`).ReplaceAllString(t, "[$1]("+jiraUrl+"browse/$1)")
	t = regexp.MustCompile(`\n *\# `).ReplaceAllString(t, "\n 1. ")
	t = regexp.MustCompile(`\n *[\*\-\#]\# `).ReplaceAllString(t, "\n   1. ")
	t = regexp.MustCompile(`\n *[\*\-\#]{2}\# `).ReplaceAllString(t, "\n     1. ")
	t = regexp.MustCompile(`\n *\* `).ReplaceAllString(t, "\n - ")
	t = regexp.MustCompile(`\n *[\*\-\#][\*\-] `).ReplaceAllString(t, "\n   - ")
	t = regexp.MustCompile(`\n *[\*\-\#]{2}[\*\-] `).ReplaceAllString(t, "\n     - ")

	// Text effects
	t = regexp.MustCompile(`(^|[\W])\*(\S.*\S)\*([\W]|$)`).ReplaceAllString(t, "$1**$2**$3") // Bold
	t = regexp.MustCompile(`(^|[\W])_(\S.*\S)_([\W]|$)`).ReplaceAllString(t, "$1*$2*$3")
	// Deleted / Strikethrough
	t = regexp.MustCompile(`(^|[\W])-(\S.*\S)-([\W]|$)`).ReplaceAllString(t, "$1~~$2~~$3")
	t = regexp.MustCompile(`(^|[\W])\+(\S.*\S)\+([\W]|$)`).ReplaceAllString(t, "$1__$2__$3")
	t = regexp.MustCompile(`(^|[\W])\{\{(.*)\}\}([\W]|$)`).ReplaceAllString(t, "$1`$2`$3")
	// Titles
	t = regexp.MustCompile(`\n?\bh1\. `).ReplaceAllString(t, "\n# ")
	t = regexp.MustCompile(`\n?\bh2\. `).ReplaceAllString(t, "\n## ")
	t = regexp.MustCompile(`\n?\bh3\. `).ReplaceAllString(t, "\n### ")
	t = regexp.MustCompile(`\n?\bh4\. `).ReplaceAllString(t, "\n#### ")
	t = regexp.MustCompile(`\n?\bh5\. `).ReplaceAllString(t, "\n##### ")
	t = regexp.MustCompile(`\n?\bh6\. `).ReplaceAllString(t, "\n###### ")
	// Emojies
	t = regexp.MustCompile(`:\)`).ReplaceAllString(t, ":smiley:")
	t = regexp.MustCompile(`:\(`).ReplaceAllString(t, ":disappointed:")
	t = regexp.MustCompile(`:P`).ReplaceAllString(t, ":yum:")
	t = regexp.MustCompile(`:D`).ReplaceAllString(t, ":grin:")
	t = regexp.MustCompile(`;\)`).ReplaceAllString(t, ":wink:")
	t = regexp.MustCompile(`\(y\)`).ReplaceAllString(t, ":thumbsup:")
	t = regexp.MustCompile(`\(n\)`).ReplaceAllString(t, ":thumbsdown:")
	t = regexp.MustCompile(`\(i\)`).ReplaceAllString(t, ":information_source:")
	t = regexp.MustCompile(`\(/\)`).ReplaceAllString(t, ":white_check_mark:")
	t = regexp.MustCompile(`\(x\)`).ReplaceAllString(t, ":x:")
	t = regexp.MustCompile(`\(!\)`).ReplaceAllString(t, ":warning:")
	t = regexp.MustCompile(`\(\+\)`).ReplaceAllString(t, ":heavy_plus_sign:")
	t = regexp.MustCompile(`\(-\)`).ReplaceAllString(t, ":heavy_minus_sign:")
	t = regexp.MustCompile(`\(\?\)`).ReplaceAllString(t, ":grey_question:")
	t = regexp.MustCompile(`\(on\)`).ReplaceAllString(t, ":bulb:")
	t = regexp.MustCompile(`\(\*[rgby]?\)`).ReplaceAllString(t, ":star:")

	// Add image handling here

	for k, v := range adict {
		t = regexp.MustCompile(k).ReplaceAllString(t, v)
	}

	return t
}
