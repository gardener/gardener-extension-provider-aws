// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package infrastructure

import (
	_ "embed"
	"fmt"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/gardener/gardener/pkg/utils"
)

var (
	//go:embed templates/main.tpl.tf
	tplContentMainTF string
	tplNameMainTF    = "main.tf"
	tplMainTF        *template.Template
)

func init() {
	var err error
	tplMainTF, err = template.
		New(tplNameMainTF).
		Funcs(utils.MergeMaps(sprig.TxtFuncMap(), map[string]interface{}{
			"joinQuotes":           joinQuotes,
			"commonTags":           commonTags,
			"commonTagsWithSuffix": commonTagsWithSuffix,
		})).
		Parse(tplContentMainTF)
	if err != nil {
		panic(err)
	}
}

const (
	terraformTFVars = `# New line is needed! Do not remove this comment.
`
	variablesTF = `variable "ACCESS_KEY_ID" {
  description = "AWS Access Key ID of technical user"
  type        = string
}

variable "SECRET_ACCESS_KEY" {
  description = "AWS Secret Access Key of technical user"
  type        = string
}`
)

// Helper functions for template rendering

func joinQuotes(data []string) string {
	var out string

	for _, v := range data {
		out += fmt.Sprintf("%q", v)
	}

	return strings.TrimSuffix(out, ",")
}

func commonTags(clusterName string) string {
	return commonTagsWithSuffix(clusterName, "")
}

func commonTagsWithSuffix(clusterName, suffix string) string {
	var sfx string
	if len(suffix) > 0 {
		sfx = "-" + suffix
	}

	return fmt.Sprintf(`tags = {
  Name = "%s%s"
  "kubernetes.io/cluster/%s" = "1"
}`, clusterName, sfx, clusterName)
}
