package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-aws-ec2/internal"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"iter"
	"os"
	"slices"
)

type CompliancePlugin struct {
	logger hclog.Logger
	config map[string]string
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.config = req.GetConfig()
	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.TODO()
	evalStatus := proto.ExecutionStatus_SUCCESS
	var accumulatedErrors error

	activities := make([]*proto.Activity, 0)
	activities = append(activities, &proto.Activity{
		Title:       "Collect EC2 Machine configurations",
		Description: "Using the Golang AWS SDK, fetch all EC2 information and metadata.",
		Steps: []*proto.Step{
			{
				Title:       "Configure AWS Client",
				Description: "Using the default configuration loaders, create a AWS client for querying the AWS API",
			},
			{
				Title:       "Create a new EC2 Client",
				Description: "In order to list and describe individual EC2 instances, we instantiate a new EC2 AWS client using the Golang AWS sdk.",
			},
			{
				Title:       "Describe EC2 instances",
				Description: "Using the newly constructed AWS client, Describe all EC2 instances available in the API, and store them in local memory.",
			},
		},
	})

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(os.Getenv("AWS_REGION")))
	if err != nil {
		l.logger.Error("unable to load SDK config", "error", err)
		evalStatus = proto.ExecutionStatus_FAILURE
		accumulatedErrors = errors.Join(accumulatedErrors, err)
	}

	client := ec2.NewFromConfig(cfg)

	// Run policy checks
	for instance, err := range getEC2Instances(ctx, client) {
		if err != nil {
			l.logger.Error("unable to get instance", "error", err)
			evalStatus = proto.ExecutionStatus_FAILURE
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			break
		}

		labels := map[string]string{
			"provider":    "aws",
			"type":        "ec2",
			"instance-id": aws.ToString(instance.InstanceId),
			"_vpc-id":     aws.ToString(instance.VpcId),
			"_subnet-id":  aws.ToString(instance.SubnetId),
		}

		actors := []*proto.OriginActor{
			{
				Title: "The Continuous Compliance Framework",
				Type:  "assessment-platform",
				Links: []*proto.Link{
					{
						Href: "https://compliance-framework.github.io/docs/",
						Rel:  internal.StringAddressed("reference"),
						Text: internal.StringAddressed("The Continuous Compliance Framework"),
					},
				},
			},
			{
				Title: "Continuous Compliance Framework - Local SSH Plugin",
				Type:  "tool",
				Links: []*proto.Link{
					{
						Href: "https://github.com/compliance-framework/plugin-local-ssh",
						Rel:  internal.StringAddressed("reference"),
						Text: internal.StringAddressed("The Continuous Compliance Framework' Local SSH Plugin"),
					},
				},
			},
		}
		components := []*proto.Component{
			{
				Identifier:  "common-components/amazon-ec2",
				Type:        "service",
				Title:       "Amazon EC2",
				Description: "Amazon EC2 provides scalable compute capacity in the AWS cloud. It supports secure bootstrapping, access controls, encryption, and networking isolation.",
				Purpose:     "Elastic virtual compute infrastructure for cloud-based applications.",
			},
		}
		inventory := []*proto.InventoryItem{
			{
				Identifier: fmt.Sprintf("aws-ec2/%s", aws.ToString(instance.InstanceId)),
				Type:       "web-server",
				Title:      fmt.Sprintf("Amazon EC2 Instance [%s]", aws.ToString(instance.InstanceId)),
				Props: []*proto.Property{
					{
						Name:  "instance-id",
						Value: aws.ToString(instance.InstanceId),
					},
					{
						Name:  "vpc-id",
						Value: aws.ToString(instance.VpcId),
					},
					{
						Name:  "subnet-id",
						Value: aws.ToString(instance.SubnetId),
					},
				},
				ImplementedComponents: []*proto.InventoryItemImplementedComponent{
					{
						Identifier: "common-components/amazon-ec2",
					},
				},
			},
		}
		subjects := []*proto.Subject{
			{
				Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
				Identifier: "common-components/amazon-ec2",
			},
			{
				Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
				Identifier: fmt.Sprintf("aws-ec2/%s", aws.ToString(instance.InstanceId)),
			},
		}

		evidences := make([]*proto.Evidence, 0)

		for _, policyPath := range request.GetPolicyPaths() {

			// Explicitly reset steps to make things readable
			processor := policyManager.NewPolicyProcessor(
				l.logger,
				internal.MergeMaps(
					labels,
					map[string]string{
						"_policy_path": policyPath,
					},
				),
				subjects,
				components,
				inventory,
				actors,
				activities,
			)
			evidence, err := processor.GenerateResults(ctx, policyPath, instance)
			evidences = slices.Concat(evidences, evidence)
			if err != nil {
				accumulatedErrors = errors.Join(accumulatedErrors, err)
			}
		}

		if err = apiHelper.CreateEvidence(ctx, evidences); err != nil {
			l.logger.Error("Failed to send evidences", "error", err)
			evalStatus = proto.ExecutionStatus_FAILURE
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			// We don't stop here, but rather continue to the next instance
			continue
		}
	}

	return &proto.EvalResponse{
		Status: evalStatus,
	}, accumulatedErrors
}

func getEC2Instances(ctx context.Context, client *ec2.Client) iter.Seq2[types.Instance, error] {
	return func(yield func(types.Instance, error) bool) {
		result, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
		if err != nil {
			yield(types.Instance{}, err)
			return
		}

		for _, reservation := range result.Reservations {
			for _, instance := range reservation.Instances {
				if !yield(instance, nil) {
					return
				}
			}
		}
	}
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	compliancePluginObj := &CompliancePlugin{
		logger: logger,
	}
	// pluginMap is the map of plugins we can dispense.
	logger.Debug("Initiating AWS EC2 plugin")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerGRPCPlugin{
				Impl: compliancePluginObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
