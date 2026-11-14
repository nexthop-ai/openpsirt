// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package uploadclient

// shape is what the deployment reads of a SARIF object: each member it reads,
// with the shape of that member where the member is an object or a list of
// objects, and nil where it is kept whole. A member named "*" is the shape of
// every member of an object keyed by name, such as a rule's message strings.
//
// Every other member is removed before a run is forwarded. A command line, an
// environment, a web request's headers, a notification's message and a
// property bag carry whatever the CI job held, its tokens included, and
// nothing that reads a run needs them.
type shape map[string]shape

var (
	messageShape = shape{"text": nil, "markdown": nil, "id": nil, "arguments": nil}
	// The position stays until settling resolves it to the path it names.
	artifactShape = shape{"uri": nil, "uriBaseId": nil, "index": nil}
	regionShape   = shape{"startLine": nil, "startColumn": nil, "endLine": nil, "endColumn": nil, "snippet": nil}
	locationShape = shape{
		"physicalLocation": {"artifactLocation": artifactShape, "region": regionShape, "contextRegion": regionShape},
		"logicalLocations": {"fullyQualifiedName": nil, "name": nil},
		"message":          messageShape,
	}
	ruleShape = shape{
		"id": nil, "name": nil, "helpUri": nil,
		"shortDescription": messageShape, "fullDescription": messageShape,
		"messageStrings":       {"*": messageShape},
		"defaultConfiguration": {"level": nil},
		"properties":           {"tags": nil, "security-severity": nil, "precision": nil},
	}
	componentShape = shape{"name": nil, "version": nil, "semanticVersion": nil, "rules": ruleShape}
	resultShape    = shape{
		"ruleId": nil, "level": nil, "kind": nil, "baselineState": nil,
		"suppressions":     {"status": nil},
		"message":          messageShape,
		"locations":        locationShape,
		"relatedLocations": locationShape,
		"codeFlows": {"threadFlows": {"locations": {
			"location": locationShape, "nestingLevel": nil,
		}}},
		"partialFingerprints": nil, "fingerprints": nil,
	}
	notificationShape = shape{"level": nil, "descriptor": {"id": nil}}
	invocationShape   = shape{
		"exitCode": nil, "executionSuccessful": nil, "workingDirectory": artifactShape,
		"toolExecutionNotifications":     notificationShape,
		"toolConfigurationNotifications": notificationShape,
	}
	// The results and invocations are pruned on their own and counted apart,
	// and the properties are filtered by name.
	runShape = shape{
		"tool":              {"driver": componentShape, "extensions": componentShape},
		"results":           nil,
		"invocations":       nil,
		"automationDetails": {"id": nil},
		"properties":        nil,
	}
)

// prune removes from v every member s does not name, at every depth s
// describes, and counts them. A list is pruned member by member.
func prune(v any, s shape) int {
	n := 0
	switch t := v.(type) {
	case obj:
		for key, member := range t {
			sub, ok := s[key]
			if !ok {
				sub, ok = s["*"]
			}
			if !ok {
				delete(t, key)
				n++
				continue
			}
			if sub != nil {
				n += prune(member, sub)
			}
		}
	case list:
		for _, member := range t {
			n += prune(member, s)
		}
	}
	return n
}
