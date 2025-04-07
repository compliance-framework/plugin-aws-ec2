package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/plugin-aws-ec2/internal"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"os"
	"slices"
)

type CompliancePlugin struct {
	logger hclog.Logger
	config map[string]string
}

type Tag struct {
	Key   string `json:"Key"`
	Value string `json:"Value"`
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

	svc := ec2.NewFromConfig(cfg)

	// Get instances
	result, err := svc.DescribeInstances(ctx, &ec2.DescribeInstancesInput{})
	if err != nil {
		l.logger.Error("unable to list instances", "error", err)
		evalStatus = proto.ExecutionStatus_FAILURE
		accumulatedErrors = errors.Join(accumulatedErrors, err)
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, accumulatedErrors
	}

	// Parse instances
	var instances []map[string]interface{}
	for _, reservation := range result.Reservations {
		for _, instance := range reservation.Instances {
			l.logger.Debug("instance", instance)

			var tags []Tag
			for _, tag := range instance.Tags {
				tags = append(tags, Tag{Key: *tag.Key, Value: *tag.Value})
			}

			// Append instance to list
			instances = append(instances, map[string]interface{}{
				"InstanceID":          aws.ToString(instance.InstanceId),
				"InstanceType":        string(instance.InstanceType),
				"ImageID":             aws.ToString(instance.ImageId),
				"PrivateIP":           aws.ToString(instance.PrivateIpAddress),
				"PublicIP":            aws.ToString(instance.PublicIpAddress),
				"State":               string(instance.State.Name),
				"Tags":                tags,
				"LaunchTime":          instance.LaunchTime,
				"SubnetID":            aws.ToString(instance.SubnetId),
				"VpcID":               aws.ToString(instance.VpcId),
				"KeyName":             aws.ToString(instance.KeyName),
				"Architecture":        string(instance.Architecture),
				"Platform":            string(instance.Platform),
				"PlatformDetails":     aws.ToString(instance.PlatformDetails),
				"RootDeviceType":      string(instance.RootDeviceType),
				"RootDeviceName":      aws.ToString(instance.RootDeviceName),
				"VirtualizationType":  string(instance.VirtualizationType),
				"Monitoring":          instance.Monitoring.State,
				"SecurityGroups":      instance.SecurityGroups,
				"BlockDeviceMappings": instance.BlockDeviceMappings,
				"NetworkInterfaces":   instance.NetworkInterfaces,
				"Hypervisor":          string(instance.Hypervisor),
				"EbsOptimized":        instance.EbsOptimized,
				"CpuOptions":          instance.CpuOptions,
				"Placement":           instance.Placement,
				"UsageOperation":      aws.ToString(instance.UsageOperation),
				"MetadataOptions":     instance.MetadataOptions,
				"MaintenanceOptions":  instance.MaintenanceOptions,
				"HibernationOptions":  instance.HibernationOptions,
				"InstanceLifecycle":   string(instance.InstanceLifecycle),
				"EnclaveOptions":      instance.EnclaveOptions,
				"TpmSupport":          aws.ToString(instance.TpmSupport),
				"SriovNetSupport":     aws.ToString(instance.SriovNetSupport),
			})
		}
	}

	l.logger.Debug("evaluating data", instances)

	// Run policy checks
	for _, instance := range instances {
		labels := map[string]string{
			"type":        "aws",
			"service":     "ec2",
			"instance-id": fmt.Sprintf("%v", instance["InstanceID"]),
		}
		subjects := []*proto.SubjectReference{
			{
				Type: "aws-ec2-instance",
				Attributes: map[string]string{
					"type":        "aws",
					"service":     "ec2",
					"instance-id": fmt.Sprintf("%v", instance["InstanceID"]),
					"image-id":    fmt.Sprintf("%v", instance["ImageID"]),
					"vpc-id":      fmt.Sprintf("%v", instance["VpcID"]),
				},
				Title: internal.StringAddressed("AWS EC2 Instance"),
				Props: []*proto.Property{
					{
						Name:  "vpc-id",
						Value: fmt.Sprintf("%v", instance["VpcID"]),
					},
					{
						Name:  "instance-id",
						Value: fmt.Sprintf("%v", instance["InstanceID"]),
					},
					{
						Name:  "image-id",
						Value: fmt.Sprintf("%v", instance["ImageID"]),
					},
				},
			},
			{
				Type: "aws-vpc",
				Attributes: map[string]string{
					"type":    "aws",
					"service": "vpc",
					"vpc-id":  fmt.Sprintf("%v", instance["VpcID"]),
				},
				Title: internal.StringAddressed("AWS VPC"),
				Props: []*proto.Property{
					{
						Name:  "vpc-id",
						Value: fmt.Sprintf("%v", instance["VpcID"]),
					},
				},
			},
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
		components := []*proto.ComponentReference{
			{
				Identifier: "common-components/aws-ec2",
			},
			{
				Identifier: "common-components/aws-ec2-instance",
			},
		}

		findings := make([]*proto.Finding, 0)
		observations := make([]*proto.Observation, 0)

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
				actors,
				activities,
			)
			obs, finds, err := processor.GenerateResults(ctx, policyPath, instance)
			observations = slices.Concat(observations, obs)
			findings = slices.Concat(findings, finds)
			if err != nil {
				accumulatedErrors = errors.Join(accumulatedErrors, err)
			}
		}

		if err = apiHelper.CreateObservations(ctx, observations); err != nil {
			l.logger.Error("Failed to send observations", "error", err)
			evalStatus = proto.ExecutionStatus_FAILURE
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			// We don't stop here, but rather continue to the next instance
			continue
		}

		if err = apiHelper.CreateFindings(ctx, findings); err != nil {
			l.logger.Error("Failed to send findings", "error", err)
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
