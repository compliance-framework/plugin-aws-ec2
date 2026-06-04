package main

import "github.com/compliance-framework/agent/runner/proto"

func buildSubjectTemplates() []*proto.SubjectTemplate {
	return []*proto.SubjectTemplate{
		{
			Name:                "aws-ec2-instance",
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       `AWS EC2 instance {{ index . "instance-id" }} in {{ .region }}`,
			DescriptionTemplate: `Amazon EC2 instance {{ index . "instance-id" }} in subnet {{ index . "_subnet-id" }} and VPC {{ index . "_vpc-id" }} within AWS region {{ .region }}.`,
			PurposeTemplate:     "Represents an AWS EC2 instance evaluated for compute, network exposure, and recovery posture.",
			IdentityLabelKeys:   []string{"provider", "region", "instance-id"},
			SelectorLabels:      selectorLabelsForType("ec2"),
			LabelSchema: labelSchema(
				label("provider", "Cloud provider for the evaluated resource"),
				label("type", "EC2 plugin resource type"),
				label("instance-id", "AWS EC2 instance identifier"),
				label("_vpc-id", "AWS VPC identifier containing the instance"),
				label("_subnet-id", "AWS subnet identifier containing the instance"),
				label("region", "AWS region containing the instance"),
			),
		},
	}
}

func selectorLabelsForType(resourceType string) []*proto.SubjectLabelSelector {
	return []*proto.SubjectLabelSelector{
		{
			Key:   "type",
			Value: resourceType,
		},
	}
}

func label(key string, description string) *proto.SubjectLabelSchema {
	return &proto.SubjectLabelSchema{
		Key:         key,
		Description: description,
	}
}

func labelSchema(labels ...*proto.SubjectLabelSchema) []*proto.SubjectLabelSchema {
	return labels
}
