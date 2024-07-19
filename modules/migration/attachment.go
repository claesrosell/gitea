// Copyright 2019 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package migration

import (
	"io"
	"time"
)

type Attachment struct {
	ID            int64
	UUID          string
	Name          string
	ContentType   *string `yaml:"content_type"`
	Size          *int
	DownloadCount *int `yaml:"download_count"`
	Created       time.Time
	Updated       time.Time

	DownloadURL *string `yaml:"download_url"` // SECURITY: It is the responsibility of downloader to make sure this is safe
	// if DownloadURL is nil, the function should be invoked
	DownloadFunc func() (io.ReadCloser, error) `yaml:"-"` // SECURITY: It is the responsibility of downloader to make sure this is safe
}
