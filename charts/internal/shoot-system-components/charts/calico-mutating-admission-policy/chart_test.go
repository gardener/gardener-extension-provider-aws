// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// Package calicomutatingadmissionpolicy contains tests for the calico
// MutatingAdmissionPolicy chart. The tests render the chart for each
// supported apiVersion and assert behavioural properties of the produced
// MutatingAdmissionPolicy: that it targets both the calico-node and the
// aws-custom-route-controller service accounts, that it only intercepts
// flips of NetworkUnavailable from False (or unset) to True, and that it
// strips NetworkUnavailable from the new conditions while restoring it
// from the old object.
package calicomutatingadmissionpolicy_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"gopkg.in/yaml.v3"
)

const (
	calicoNodeUser              = "system:serviceaccount:kube-system:calico-node"
	awsCustomRouteControllerUser = "system:serviceaccount:kube-system:aws-custom-route-controller"
)

// renderCalicoMAPChart renders the chart's mutating-admission-policy.yaml for
// the given values. It uses Go's text/template (which is the engine helm uses
// under the hood) and intentionally does not pull in the helm engine for this
// test, since the chart only references {{ .Values.enabled }} and
// {{ .Values.apiVersion }} and uses no sprig helpers or chart partials.
func renderCalicoMAPChart(t *testing.T, values map[string]interface{}) string {
	t.Helper()

	path := filepath.Join("templates", "mutating-admission-policy.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read chart template: %v", err)
	}

	// helm's whitespace-trim syntax {{- ... -}} is identical to Go's
	// text/template trim markers. The chart additionally uses sprig
	// dictionary access via {{ .Values.foo }}, which is just standard
	// Go template field access on a map.
	tpl, err := template.New("map").Parse(string(raw))
	if err != nil {
		t.Fatalf("parse chart template: %v", err)
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, map[string]interface{}{"Values": values}); err != nil {
		t.Fatalf("execute chart template: %v", err)
	}
	return buf.String()
}

// parseDocs splits a multi-document YAML stream and decodes each non-empty
// document into a generic map.
func parseDocs(t *testing.T, in string) []map[string]interface{} {
	t.Helper()
	var out []map[string]interface{}
	dec := yaml.NewDecoder(strings.NewReader(in))
	for {
		var doc map[string]interface{}
		err := dec.Decode(&doc)
		if err != nil {
			break
		}
		if doc != nil {
			out = append(out, doc)
		}
	}
	return out
}

func TestCalicoMAPChart_DisabledRendersEmpty(t *testing.T) {
	got := renderCalicoMAPChart(t, map[string]interface{}{"enabled": false, "apiVersion": "v1beta1"})
	if strings.TrimSpace(got) != "" {
		t.Fatalf("expected empty render when enabled=false, got:\n%s", got)
	}
}

func TestCalicoMAPChart_RendersAPIVersion(t *testing.T) {
	for _, apiVersion := range []string{"v1alpha1", "v1beta1", "v1"} {
		t.Run(apiVersion, func(t *testing.T) {
			out := renderCalicoMAPChart(t, map[string]interface{}{"enabled": true, "apiVersion": apiVersion})
			docs := parseDocs(t, out)
			if len(docs) != 2 {
				t.Fatalf("expected 2 documents (binding + policy), got %d", len(docs))
			}
			for _, d := range docs {
				gotAV, _ := d["apiVersion"].(string)
				want := "admissionregistration.k8s.io/" + apiVersion
				if gotAV != want {
					t.Errorf("doc kind=%v apiVersion = %q, want %q", d["kind"], gotAV, want)
				}
			}
		})
	}
}

func TestCalicoMAPChart_PolicyAndBinding(t *testing.T) {
	out := renderCalicoMAPChart(t, map[string]interface{}{"enabled": true, "apiVersion": "v1beta1"})
	docs := parseDocs(t, out)
	if len(docs) != 2 {
		t.Fatalf("expected 2 documents, got %d", len(docs))
	}

	var binding, policy map[string]interface{}
	for _, d := range docs {
		switch d["kind"] {
		case "MutatingAdmissionPolicyBinding":
			binding = d
		case "MutatingAdmissionPolicy":
			policy = d
		}
	}
	if binding == nil {
		t.Fatal("MutatingAdmissionPolicyBinding not rendered")
	}
	if policy == nil {
		t.Fatal("MutatingAdmissionPolicy not rendered")
	}

	bindingPolicyName, _ := bindingSpec(binding)["policyName"].(string)
	policyName, _ := metaName(policy)
	if bindingPolicyName != policyName {
		t.Errorf("binding.spec.policyName=%q does not match policy.metadata.name=%q", bindingPolicyName, policyName)
	}
}

func TestCalicoMAPChart_MatchConditions_TargetBothServiceAccounts(t *testing.T) {
	policy := getPolicy(t, "v1beta1")

	mc := matchConditions(policy)
	if len(mc) < 2 {
		t.Fatalf("expected at least 2 matchConditions, got %d", len(mc))
	}

	// The first match condition selects the SAs whose writes we want to
	// intercept. Both calico-node and aws-custom-route-controller must be
	// covered: the prod-haas RCA (issues-live#9754) showed that the
	// route controller is the dominant writer of NetworkUnavailable=True
	// during overlay disablement, and the previously calico-only MAP let
	// those writes through.
	saExpr := matchExpression(mc[0])
	for _, want := range []string{calicoNodeUser, awsCustomRouteControllerUser} {
		if !strings.Contains(saExpr, want) {
			t.Errorf("matchCondition[0].expression should reference %q, got:\n%s", want, saExpr)
		}
	}
}

func TestCalicoMAPChart_MatchConditions_OnlyInterceptFalseOrNilToTrueFlip(t *testing.T) {
	policy := getPolicy(t, "v1beta1")
	mc := matchConditions(policy)

	// We must intercept *only* updates that try to flip NetworkUnavailable
	// from False (or unset) to True. Steady-state =True heartbeats and
	// any =False write must be allowed through, so that:
	//   - the route controller can still mark a node ready after the VPC
	//     route exists, and
	//   - a node that is genuinely network-unavailable stays marked as such.
	flipExpr := ""
	for _, c := range mc {
		expr := matchExpression(c)
		if strings.Contains(expr, "object.status.conditions") &&
			strings.Contains(expr, "NetworkUnavailable") {
			flipExpr = expr
		}
	}
	if flipExpr == "" {
		t.Fatal("did not find a matchCondition referencing object.status.conditions / NetworkUnavailable")
	}

	// New object must have NetworkUnavailable=True.
	if !strings.Contains(flipExpr, "c.status == 'True'") {
		t.Errorf("flip matchCondition must require new NetworkUnavailable.status == 'True', got:\n%s", flipExpr)
	}
	// Old object must NOT already have NetworkUnavailable=True (otherwise
	// the rule would suppress legitimate heartbeat refreshes on a node that
	// is genuinely network-unavailable).
	if !strings.Contains(flipExpr, "oldObject") {
		t.Errorf("flip matchCondition must inspect oldObject to detect a real flip, got:\n%s", flipExpr)
	}
	if !strings.Contains(flipExpr, "!oldObject.status.conditions.exists") {
		t.Errorf("flip matchCondition must require old NetworkUnavailable!=True, got:\n%s", flipExpr)
	}
}

func TestCalicoMAPChart_StripsNetworkUnavailableAndRestoresFromOld(t *testing.T) {
	policy := getPolicy(t, "v1beta1")

	// The mutation must replace /status/conditions with finalConditions.
	mut := mutations(policy)
	if len(mut) == 0 {
		t.Fatal("expected at least one mutation")
	}
	patchExpr := jsonPatchExpression(mut[0])
	for _, want := range []string{`op: "replace"`, `path: "/status/conditions"`, "variables.finalConditions"} {
		if !strings.Contains(patchExpr, want) {
			t.Errorf("mutation jsonPatch.expression missing %q, got:\n%s", want, patchExpr)
		}
	}

	// finalConditions must be conditionsWithoutNetworkUnavailable PLUS the
	// old NetworkUnavailable condition (when there was one) — i.e. the old
	// value of NetworkUnavailable is preserved while the rest of the new
	// conditions land.
	vars := variables(policy)
	finalExpr := variableExpression(vars, "finalConditions")
	if finalExpr == "" {
		t.Fatal("variable finalConditions not found")
	}
	for _, want := range []string{
		"variables.conditionsWithoutNetworkUnavailable",
		"variables.oldNetworkUnavailableCondition",
	} {
		if !strings.Contains(finalExpr, want) {
			t.Errorf("finalConditions expression missing %q, got:\n%s", want, finalExpr)
		}
	}

	stripExpr := variableExpression(vars, "conditionsWithoutNetworkUnavailable")
	if !strings.Contains(stripExpr, "c.type != 'NetworkUnavailable'") {
		t.Errorf("conditionsWithoutNetworkUnavailable must filter out NetworkUnavailable, got:\n%s", stripExpr)
	}
}

// helpers

func getPolicy(t *testing.T, apiVersion string) map[string]interface{} {
	t.Helper()
	out := renderCalicoMAPChart(t, map[string]interface{}{"enabled": true, "apiVersion": apiVersion})
	for _, d := range parseDocs(t, out) {
		if d["kind"] == "MutatingAdmissionPolicy" {
			return d
		}
	}
	t.Fatal("MutatingAdmissionPolicy not found in rendered chart")
	return nil
}

func metaName(d map[string]interface{}) (string, bool) {
	m, ok := d["metadata"].(map[string]interface{})
	if !ok {
		return "", false
	}
	n, ok := m["name"].(string)
	return n, ok
}

func bindingSpec(d map[string]interface{}) map[string]interface{} {
	if s, ok := d["spec"].(map[string]interface{}); ok {
		return s
	}
	return nil
}

func matchConditions(policy map[string]interface{}) []map[string]interface{} {
	spec, _ := policy["spec"].(map[string]interface{})
	raw, _ := spec["matchConditions"].([]interface{})
	out := make([]map[string]interface{}, 0, len(raw))
	for _, c := range raw {
		if m, ok := c.(map[string]interface{}); ok {
			out = append(out, m)
		}
	}
	return out
}

func matchExpression(c map[string]interface{}) string {
	s, _ := c["expression"].(string)
	return s
}

func variables(policy map[string]interface{}) []map[string]interface{} {
	spec, _ := policy["spec"].(map[string]interface{})
	raw, _ := spec["variables"].([]interface{})
	out := make([]map[string]interface{}, 0, len(raw))
	for _, c := range raw {
		if m, ok := c.(map[string]interface{}); ok {
			out = append(out, m)
		}
	}
	return out
}

func variableExpression(vars []map[string]interface{}, name string) string {
	for _, v := range vars {
		if n, _ := v["name"].(string); n == name {
			s, _ := v["expression"].(string)
			return s
		}
	}
	return ""
}

func mutations(policy map[string]interface{}) []map[string]interface{} {
	spec, _ := policy["spec"].(map[string]interface{})
	raw, _ := spec["mutations"].([]interface{})
	out := make([]map[string]interface{}, 0, len(raw))
	for _, c := range raw {
		if m, ok := c.(map[string]interface{}); ok {
			out = append(out, m)
		}
	}
	return out
}

func jsonPatchExpression(m map[string]interface{}) string {
	jp, _ := m["jsonPatch"].(map[string]interface{})
	s, _ := jp["expression"].(string)
	return s
}
