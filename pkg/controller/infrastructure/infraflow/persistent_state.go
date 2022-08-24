// Copyright (c) 2022 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package infraflow

import (
	"fmt"

	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
	"k8s.io/apimachinery/pkg/util/json"
)

const (
	// PersistentStateVersion is the current version used for persisting the state.
	PersistentStateVersion = "1.0"
)

type persistentStateMarker struct {
	FlowVersion string `json:"flowVersion"`
}

// PersistentState is the state which is persisted as part of the infrastructure status.
type PersistentState struct {
	FlowVersion string `json:"flowVersion"`

	Data map[string]string `json:"data"`
	/*
		ZoneIds                map[string]string `json:"zoneIds,omitempty"`
		KeyPairFingerprint     string            `json:"keyPairFingerprint,omitempty"`
		KeyPairSpecFingerprint string            `json:"keyPairSpecFingerprint,omitempty"`
		MigratedFromTerraform  bool              `json:"migratedFromTerraform,omitempty"`
		TerraformCleanedUp     bool              `json:"terraformCleanedUp,omitempty"`
	*/
}

// NewPersistentState creates empty PersistentState
func NewPersistentState() *PersistentState {
	return &PersistentState{
		FlowVersion: PersistentStateVersion,
		Data:        map[string]string{},
		//		ZoneIds:     map[string]string{},
	}
}

// NewPersistentStateFromJSON unmarshals PersistentState from JSON or YAML.
// Returns nil if input contains no "flowVersion" field.
func NewPersistentStateFromJSON(raw []byte) (*PersistentState, error) {
	// first check if state is from flow or Terraformer
	marker := &persistentStateMarker{}
	if err := json.Unmarshal(raw, marker); err != nil {
		return nil, err
	}
	if marker.FlowVersion == "" {
		// no flow state
		return nil, nil
	}

	state := &PersistentState{}
	if err := json.Unmarshal(raw, state); err != nil {
		return nil, err
	}
	if !state.HasValidVersion() {
		return nil, fmt.Errorf("unsupported flowVersion %s", state.FlowVersion)
	}

	if state.Data == nil {
		state.Data = map[string]string{}
	}
	return state, nil
}

// NewPersistentStateFromFlatMap create new PersistentState and initialises data from input.
func NewPersistentStateFromFlatMap(flatState shared.FlatMap) *PersistentState {
	state := NewPersistentState()

	/*
		data := shared.NewWhiteboard()
		data.ImportFromFlatMap(flatState)
		state.KeyPairFingerprint = safestr(data.Get(KeyPairFingerprint))
		state.KeyPairSpecFingerprint = safestr(data.Get(KeyPairSpecFingerprint))
		state.MigratedFromTerraform = safestr(data.Get(MarkerMigratedFromTerraform)) == "true"
		state.TerraformCleanedUp = safestr(data.Get(MarkerTerraformCleanedUp)) == "true"
		zonesChild := data.GetChild(ChildIdZones)
		for _, zoneKey := range zonesChild.GetChildrenKeys() {
			suffix := zonesChild.GetChild(zoneKey).Get(IdentifierZoneSuffix)
			if suffix != nil {
				state.ZoneIds[zoneKey] = *suffix
			}
		}
	*/
	state.Data = copyMap(flatState)
	return state
}

// HasValidVersion checks if flow version is supported.
func (s *PersistentState) HasValidVersion() bool {
	return s != nil && s.FlowVersion == PersistentStateVersion
}

// ToFlatMap returns a copy of state as FlatMap
func (s *PersistentState) ToFlatMap() shared.FlatMap {
	/*
		data := shared.NewWhiteboard()

		if s.KeyPairFingerprint != "" {
			data.Set(KeyPairFingerprint, s.KeyPairFingerprint)
		}
		if s.KeyPairSpecFingerprint != "" {
			data.Set(KeyPairSpecFingerprint, s.KeyPairSpecFingerprint)
		}
		if s.MigratedFromTerraform {
			data.Set(MarkerMigratedFromTerraform, "true")
		}
		if s.TerraformCleanedUp {
			data.Set(MarkerTerraformCleanedUp, "true")
		}
		zonesChild := data.GetChild(ChildIdZones)
		for key, value := range s.ZoneIds {
			zonesChild.GetChild(key).Set(IdentifierZoneSuffix, value)
		}
		return data.ExportAsFlatMap()
	*/
	return copyMap(s.Data)
}

// ToJSON marshals state as JSON
func (s *PersistentState) ToJSON() ([]byte, error) {
	return json.Marshal(s)
}

// MigratedFromTerraform returns trus if marker MarkerMigratedFromTerraform is set.
func (s *PersistentState) MigratedFromTerraform() bool {
	return s.Data[MarkerMigratedFromTerraform] == "true"
}

// SetMigratedFromTerraform sets the marker MarkerMigratedFromTerraform
func (s *PersistentState) SetMigratedFromTerraform() {
	s.Data[MarkerMigratedFromTerraform] = "true"
}

// TerraformCleanedUp returns trus if marker MarkerTerraformCleanedUp is set.
func (s *PersistentState) TerraformCleanedUp() bool {
	return s.Data[MarkerTerraformCleanedUp] == "true"
}

// SetTerraformCleanedUp sets the marker MarkerTerraformCleanedUp
func (s *PersistentState) SetTerraformCleanedUp() {
	s.Data[MarkerTerraformCleanedUp] = "true"
}

func safestr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
