// Copyright 2021 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package migrations

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"code.gitea.io/gitea/modules/log"
	base "code.gitea.io/gitea/modules/migration"
	"code.gitea.io/gitea/modules/structs"
)

var (
	_ base.Downloader        = &JiraDownloader{}
	_ base.DownloaderFactory = &JiraDownloaderFactory{}
)

func init() {
	RegisterDownloaderFactory(&JiraDownloaderFactory{})
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
	return NewJiraDownloader(ctx, baseURL, opts.AuthUsername, opts.AuthPassword, opts.AuthToken, oldOwner, oldName), nil
}

// GitServiceType returns the type of git service
func (f *JiraDownloaderFactory) GitServiceType() structs.GitServiceType {
	return structs.JiraService
}

// JiraDownloader implements a Downloader interface to get repository information
// from Jira via GithubDownloader
type JiraDownloader struct {
	base.NullDownloader
	ctx           context.Context
	baseURL       string
	repoOwner     string
	repoName      string
	userName      string
	password      string
	curClientIdx  int
	maxPerPage    int
	SkipReactions bool
	SkipReviews   bool
}

// String implements Stringer
func (g *JiraDownloader) String() string {
	return fmt.Sprintf("migration from Jira server %s %s/%s", g.baseURL, g.repoOwner, g.repoName)
}

func (g *JiraDownloader) LogString() string {
	if g == nil {
		return "<JiraDownloader nil>"
	}
	return fmt.Sprintf("<JiraDownloader %s %s/%s>", g.baseURL, g.repoOwner, g.repoName)
}

// NewJiraDownloader creates a Jira downloader
func NewJiraDownloader(ctx context.Context, baseURL, userName, password, token, repoOwner, repoName string) *JiraDownloader {
	JiraDownloader := JiraDownloader{}
	JiraDownloader.baseURL = baseURL
	return &JiraDownloader
}

// SupportGetRepoComments return true if it supports get repo comments
func (g *JiraDownloader) SupportGetRepoComments() bool {
	return false
}

// GetRepoInfo returns repository information
func (d *JiraDownloader) GetRepoInfo() (*base.Repository, error) {
	info := make([]struct {
		ID          int64  `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}, 0, 1)

	return &base.Repository{
		Name:        info[0].Name,
		Description: info[0].Description,
		//		CloneURL:    cloneURL.String(),
		//		OriginalURL: originalURL.String(),
	}, nil
}
