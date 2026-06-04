package main

import (
	"bytes"
	"testing"
	"text/template"

	"github.com/compliance-framework/agent/runner/proto"
)

func TestBuildSubjectTemplates(t *testing.T) {
	templates := buildSubjectTemplates()
	if len(templates) != 1 {
		t.Fatalf("expected 1 subject template, got %d", len(templates))
	}

	tpl := templates[0]
	if tpl.Name != "aws-ec2-instance" {
		t.Fatalf("unexpected template name: %s", tpl.Name)
	}
	if tpl.Type != proto.SubjectType_SUBJECT_TYPE_COMPONENT {
		t.Fatalf("unexpected template type: %v", tpl.Type)
	}

	expectedIdentityKeys := []string{"provider", "region", "instance-id"}
	if len(tpl.IdentityLabelKeys) != len(expectedIdentityKeys) {
		t.Fatalf("unexpected identity key count: %d", len(tpl.IdentityLabelKeys))
	}
	for i, key := range expectedIdentityKeys {
		if tpl.IdentityLabelKeys[i] != key {
			t.Fatalf("unexpected identity key at %d: %s", i, tpl.IdentityLabelKeys[i])
		}
	}

	if len(tpl.SelectorLabels) != 1 {
		t.Fatalf("unexpected selector count: %d", len(tpl.SelectorLabels))
	}
	if tpl.SelectorLabels[0].Key != "type" || tpl.SelectorLabels[0].Value != "ec2" {
		t.Fatalf("unexpected selector label: %s=%s", tpl.SelectorLabels[0].Key, tpl.SelectorLabels[0].Value)
	}

	expectedSchemaKeys := []string{"provider", "type", "instance-id", "_vpc-id", "_subnet-id", "region"}
	if len(tpl.LabelSchema) != len(expectedSchemaKeys) {
		t.Fatalf("unexpected label schema count: %d", len(tpl.LabelSchema))
	}
	for i, key := range expectedSchemaKeys {
		if tpl.LabelSchema[i].Key != key {
			t.Fatalf("unexpected label schema key at %d: %s", i, tpl.LabelSchema[i].Key)
		}
	}
}

func TestBuildSubjectTemplatesRenderCurrentLabels(t *testing.T) {
	tpl := buildSubjectTemplates()[0]
	labels := map[string]string{
		"provider":    "aws",
		"type":        "ec2",
		"region":      "eu-west-2",
		"instance-id": "i-0123456789abcdef0",
		"_vpc-id":     "vpc-0123456789abcdef0",
		"_subnet-id":  "subnet-0123456789abcdef0",
	}

	title := executeTemplate(t, tpl.TitleTemplate, labels)
	if title != "AWS EC2 instance i-0123456789abcdef0 in eu-west-2" {
		t.Fatalf("unexpected title: %s", title)
	}

	description := executeTemplate(t, tpl.DescriptionTemplate, labels)
	expectedDescription := "Amazon EC2 instance i-0123456789abcdef0 in subnet subnet-0123456789abcdef0 and VPC vpc-0123456789abcdef0 within AWS region eu-west-2."
	if description != expectedDescription {
		t.Fatalf("unexpected description: %s", description)
	}
}

func executeTemplate(t *testing.T, source string, data map[string]string) string {
	t.Helper()

	tpl, err := template.New("subject").Parse(source)
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute template: %v", err)
	}

	return buf.String()
}
