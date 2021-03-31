package log

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

type writeCloser struct {
	io.Writer
}

func (writeCloser) Close() error { return nil }

func TestUTC(t *testing.T) {
	buf := &bytes.Buffer{}
	Init(nil, writeCloser{buf}, nil, nil, nil)
	Errorln("test")
	actual := buf.String()

	if !strings.Contains(actual, "Z: test") {
		t.Errorf("expected UTC time, actual '" + actual + "'")
	}
}

func TestNewlineMultipleLogLines(t *testing.T) {
	buf := &bytes.Buffer{}
	Init(nil, writeCloser{buf}, nil, nil, nil)
	// Have to concatenate, because Go doesn't allow you to test multiple trailing newline behavior.
	Errorln("foo\n\nbar\n" + "\n" + "\n")
	actual := buf.String()

	// verify the log message gets broken up into multiple log lines
	if !strings.Contains(actual, "foo\nERROR") || !strings.Contains(actual, "Z: bar") {
		t.Errorf("expected message with newlines to have a log line per line, actual '" + actual + "'")
	}

	// verify the multiple newlines inside the message were preserved
	if !strings.Contains(actual, "Z: \nERROR") {
		t.Errorf("expected newlines inside message to be preserved, actual '" + actual + "'")
	}

	// verify multiple trailing newlines were collapsed
	if !strings.HasSuffix(actual, "Z: bar\n") {
		t.Errorf("expected multiple trailing newlines to be removed, actual '" + actual + "'")
	}
}
