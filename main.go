package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/compliance-framework/plugin-aws-ec2/internal"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/configuration-service/sdk"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/protobuf/types/known/timestamppb"
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
	startTime := time.Now()
	evalStatus := proto.ExecutionStatus_SUCCESS
	var accumulatedErrors error

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
		activities := make([]*proto.Activity, 0)
		findings := make([]*proto.Finding, 0)
		observations := make([]*proto.Observation, 0)

		subjectAttributeMap := map[string]string{
			"type":        "aws",
			"service":     "ec2",
			"instance-id": fmt.Sprintf("%v", instance["InstanceID"]),
			"image-id":    fmt.Sprintf("%v", instance["ImageID"]),
			"vpc-id":      fmt.Sprintf("%v", instance["VpcID"]),
		}
		subjects := []*proto.SubjectReference{
			{
				Type:       "aws-ec2-instance",
				Attributes: subjectAttributeMap,
				Title:      internal.StringAddressed("AWS EC2 Instance"),
				Props: []*proto.Property{
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

		for _, policyPath := range request.GetPolicyPaths() {

			steps := make([]*proto.Step, 0)
			steps = append(steps, &proto.Step{
				Title:       "Compile policy bundle",
				Description: "Using a locally addressable policy path, compile the policy files to an in memory executable.",
			})
			steps = append(steps, &proto.Step{
				Title:       "Execute policy bundle",
				Description: "Using previously collected JSON-formatted Security Group configuration, execute the compiled policies",
			})

			results, err := policyManager.New(ctx, l.logger, policyPath).Execute(ctx, "compliance_plugin", instance)
			if err != nil {
				l.logger.Error("policy evaluation failed", "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				continue
			}

			activities = append(activities, &proto.Activity{
				Title:       "Execute policy",
				Description: "Prepare and compile policy bundles, and execute them using the prepared Security Group data",
				Steps:       steps,
			})

			for _, result := range results {

				// Observation UUID should differ for each individual subject, but remain consistent when validating the same policy for the same subject.
				// This acts as an identifier to show the history of an observation.
				observationUUIDMap := internal.MergeMaps(subjectAttributeMap, map[string]string{
					"type":        "observation",
					"policy":      result.Policy.Package.PurePackage(),
					"policy_file": result.Policy.File,
					"policy_path": policyPath,
				})
				observationUUID, err := sdk.SeededUUID(observationUUIDMap)
				if err != nil {
					accumulatedErrors = errors.Join(accumulatedErrors, err)
					// We've been unable to do much here, but let's try the next one regardless.
					continue
				}

				// Finding UUID should differ for each individual subject, but remain consistent when validating the same policy for the same subject.
				// This acts as an identifier to show the history of a finding.
				findingUUIDMap := internal.MergeMaps(subjectAttributeMap, map[string]string{
					"type":        "finding",
					"policy":      result.Policy.Package.PurePackage(),
					"policy_file": result.Policy.File,
					"policy_path": policyPath,
				})
				findingUUID, err := sdk.SeededUUID(findingUUIDMap)
				if err != nil {
					accumulatedErrors = errors.Join(accumulatedErrors, err)
					// We've been unable to do much here, but let's try the next one regardless.
					continue
				}

				observation := proto.Observation{
					ID:         uuid.New().String(),
					UUID:       observationUUID.String(),
					Collected:  timestamppb.New(startTime),
					Expires:    timestamppb.New(startTime.Add(24 * time.Hour)),
					Origins:    []*proto.Origin{{Actors: actors}},
					Subjects:   subjects,
					Activities: activities,
					Components: components,
					RelevantEvidence: []*proto.RelevantEvidence{
						{
							Description: fmt.Sprintf("Policy %v was executed against the AWS Security Group configuration, using the Local AWS Security Group Plugin", result.Policy.Package.PurePackage()),
						},
					},
				}

				newFinding := func() *proto.Finding {
					return &proto.Finding{
						ID:        uuid.New().String(),
						UUID:      findingUUID.String(),
						Collected: timestamppb.New(time.Now()),
						Labels: map[string]string{
							"type":         "aws",
							"service":      "ec2",
							"instance-id":  fmt.Sprintf("%v", instance["InstanceID"]),
							"image-id":     fmt.Sprintf("%v", instance["ImageID"]),
							"vpc-id":       fmt.Sprintf("%v", instance["VpcID"]),
							"_policy":      result.Policy.Package.PurePackage(),
							"_policy_path": result.Policy.File,
						},
						Origins:             []*proto.Origin{{Actors: actors}},
						Subjects:            subjects,
						Components:          components,
						RelatedObservations: []*proto.RelatedObservation{{ObservationUUID: observation.ID}},
						Controls:            nil,
					}
				}

				// There are no violations reported from the policies.
				// We'll send the observation back to the agent
				if len(result.Violations) == 0 {

					observation.Title = internal.StringAddressed("The plugin succeeded. No compliance issues to report.")
					observation.Description = "The plugin policies did not return any violations. The configuration is in compliance with policies."
					observations = append(observations, &observation)

					finding := newFinding()
					finding.Title = fmt.Sprintf("No violations found on %s", result.Policy.Package.PurePackage())
					finding.Description = fmt.Sprintf("No violations were found on the %s policy within the AWS EC2 Compliance Plugin.", result.Policy.Package.PurePackage())
					finding.Status = &proto.FindingStatus{
						State: runner.FindingTargetStatusSatisfied,
					}
					findings = append(findings, finding)
					continue
				}

				// There are violations in the policy checks.
				// We'll send these observations back to the agent
				if len(result.Violations) > 0 {
					observation.Title = internal.StringAddressed(fmt.Sprintf("Validation on %s failed.", result.Policy.Package.PurePackage()))
					observation.Description = fmt.Sprintf("Observed %d violation(s) on the %s policy within the AWS EC2 Compliance Plugin.", len(result.Violations), result.Policy.Package.PurePackage())
					observations = append(observations, &observation)

					for _, violation := range result.Violations {
						finding := newFinding()
						finding.Title = violation.Title
						finding.Description = violation.Description
						finding.Remarks = internal.StringAddressed(violation.Remarks)
						finding.Status = &proto.FindingStatus{
							State: runner.FindingTargetStatusNotSatisfied,
						}
						findings = append(findings, finding)
					}
				}
			}
		}

		if err = apiHelper.CreateObservations(ctx, observations); err != nil {
			l.logger.Error("Failed to send observations", "error", err)
			return &proto.EvalResponse{
				Status: proto.ExecutionStatus_FAILURE,
			}, err
		}

		if err = apiHelper.CreateFindings(ctx, findings); err != nil {
			l.logger.Error("Failed to send findings", "error", err)
			return &proto.EvalResponse{
				Status: proto.ExecutionStatus_FAILURE,
			}, err
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
