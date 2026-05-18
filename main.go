package main

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"os"
	"slices"
	"strings"

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
)

type CompliancePlugin struct {
	logger     hclog.Logger
	config     map[string]string
	policyData map[string]interface{}
}

type EC2SnapshotPermission struct {
	SnapshotID              string                         `json:"snapshot_id"`
	CreateVolumePermissions []types.CreateVolumePermission `json:"create_volume_permissions,omitempty"`
	PublicShareEnabled      bool                           `json:"public_share_enabled"`
}

type EC2SnapshotInventoryItem struct {
	SnapshotID              string                         `json:"snapshot_id"`
	VolumeID                string                         `json:"volume_id,omitempty"`
	State                   string                         `json:"state,omitempty"`
	StartTime               string                         `json:"start_time,omitempty"`
	Encrypted               bool                           `json:"encrypted"`
	KmsKeyID                string                         `json:"kms_key_id,omitempty"`
	OwnerID                 string                         `json:"owner_id,omitempty"`
	StorageTier             string                         `json:"storage_tier,omitempty"`
	Description             string                         `json:"description,omitempty"`
	Tags                    map[string]string              `json:"tags,omitempty"`
	CreateVolumePermissions []types.CreateVolumePermission `json:"create_volume_permissions,omitempty"`
	PublicShareEnabled      bool                           `json:"public_share_enabled"`
}

type EC2PolicyInput struct {
	Region              string                                         `json:"region"`
	Instance            types.Instance                                 `json:"instance"`
	SecurityGroups      []types.SecurityGroup                          `json:"security_groups,omitempty"`
	Volumes             []types.Volume                                 `json:"volumes,omitempty"`
	Snapshots           []types.Snapshot                               `json:"snapshots,omitempty"`
	SnapshotInventory   []EC2SnapshotInventoryItem                     `json:"snapshot_inventory,omitempty"`
	SnapshotPermissions []EC2SnapshotPermission                        `json:"snapshot_permissions,omitempty"`
	Images              []types.Image                                  `json:"images,omitempty"`
	FastSnapshotRestore []types.DescribeFastSnapshotRestoreSuccessItem `json:"fast_snapshot_restore,omitempty"`
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	l.config = req.GetConfig()

	// Convert protobuf.Struct to map[string]interface{}
	policyDataStruct := req.GetPolicyData()
	if policyDataStruct != nil {
		l.policyData = policyDataStruct.AsMap()
	} else {
		l.policyData = nil
	}

	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) Init(req *proto.InitRequest, apiHelper runner.ApiHelper) (*proto.InitResponse, error) {
	return &proto.InitResponse{}, nil
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.TODO()
	evalStatus := proto.ExecutionStatus_SUCCESS
	var accumulatedErrors error
	regions := getConfiguredRegions(l.config)
	if len(regions) == 0 {
		err := errors.New("no AWS regions configured and AWS_REGION is not set")
		l.logger.Error("unable to determine AWS regions", "error", err)
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
	}

	activities := make([]*proto.Activity, 0)
	activities = append(activities, &proto.Activity{
		Title:       "Collect EC2 Machine configurations",
		Description: "Using the Golang AWS SDK, fetch EC2, EBS, snapshot, and recovery metadata for each in-scope instance.",
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
			{
				Title:       "Describe attached EBS volumes and snapshots",
				Description: "For each instance, collect the attached EBS volumes, account-owned snapshots for those volumes, and the snapshot restore permissions.",
			},
			{
				Title:       "Describe recovery artifacts",
				Description: "Collect related account-owned AMIs and Fast Snapshot Restore state so recovery and resiliency policies can use a single composed input.",
			},
		},
	})

	for _, region := range regions {
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
		if err != nil {
			l.logger.Error("unable to load SDK config", "region", region, "error", err)
			accumulatedErrors = errors.Join(accumulatedErrors, err)
			continue
		}

		client := ec2.NewFromConfig(cfg)
		l.logger.Info("evaluating AWS region", "region", region)

		for instance, err := range getEC2Instances(ctx, client) {
			if err != nil {
				l.logger.Error("unable to get instance", "region", region, "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				break
			}

			policyInput, err := buildEC2PolicyInput(ctx, client, region, instance)
			if err != nil {
				l.logger.Error("unable to build policy input", "region", region, "instance_id", aws.ToString(instance.InstanceId), "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				continue
			}

			instanceID := aws.ToString(policyInput.Instance.InstanceId)
			inventoryID := fmt.Sprintf("aws-ec2/%s/%s", region, instanceID)
			instanceName := ""
			for _, t := range policyInput.Instance.Tags {
				if aws.ToString(t.Key) == "Name" {
					instanceName = aws.ToString(t.Value)
					break
				}
			}

			l.logger.Info(
				"collected ec2 evidence",
				"region", region,
				"instance_id", instanceID,
				"security_groups", len(policyInput.SecurityGroups),
				"volumes", len(policyInput.Volumes),
				"snapshots", len(policyInput.Snapshots),
				"snapshot_permissions", len(policyInput.SnapshotPermissions),
				"images", len(policyInput.Images),
				"fast_snapshot_restore", len(policyInput.FastSnapshotRestore),
			)

			labels := map[string]string{
				"provider":    "aws",
				"type":        "ec2",
				"region":      region,
				"instance-id": instanceID,
				"_vpc-id":     aws.ToString(policyInput.Instance.VpcId),
				"_subnet-id":  aws.ToString(policyInput.Instance.SubnetId),
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
					Title: "Continuous Compliance Framework - AWS EC2 Plugin",
					Type:  "tool",
					Links: []*proto.Link{
						{
							Href: "https://github.com/compliance-framework/plugin-aws-ec2",
							Rel:  internal.StringAddressed("reference"),
							Text: internal.StringAddressed("The Continuous Compliance Framework AWS EC2 Plugin"),
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
					Identifier: inventoryID,
					Type:       "web-server",
					Title:      fmt.Sprintf("Amazon EC2 Instance [%s]", instanceID),
					Props: []*proto.Property{
						{
							Name:  "region",
							Value: region,
						},
						{
							Name:  "instance-id",
							Value: instanceID,
						},
						{
							Name:  "security-group-count",
							Value: fmt.Sprintf("%d", len(policyInput.SecurityGroups)),
						},
						{
							Name:  "vpc-id",
							Value: aws.ToString(policyInput.Instance.VpcId),
						},
						{
							Name:  "subnet-id",
							Value: aws.ToString(policyInput.Instance.SubnetId),
						},
						{
							Name:  "volume-count",
							Value: fmt.Sprintf("%d", len(policyInput.Volumes)),
						},
						{
							Name:  "snapshot-count",
							Value: fmt.Sprintf("%d", len(policyInput.Snapshots)),
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
					Identifier: inventoryID,
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
					l.policyData,
				)

				evidence, err := processor.GenerateResults(ctx, policyPath, policyInput)
				if instanceName != "" {
					for i := range evidence {
						evidence[i].Title = fmt.Sprintf("%s | %s", instanceName, evidence[i].Title)
					}
				}
				evidences = slices.Concat(evidences, evidence)
				if err != nil {
					evalStatus = proto.ExecutionStatus_FAILURE
					accumulatedErrors = errors.Join(accumulatedErrors, err)
				}
			}

			if err = apiHelper.CreateEvidence(ctx, evidences); err != nil {
				l.logger.Error("Failed to send evidences", "region", region, "instance_id", instanceID, "error", err)
				evalStatus = proto.ExecutionStatus_FAILURE
				accumulatedErrors = errors.Join(accumulatedErrors, err)
				continue
			}
		}
	}

	return &proto.EvalResponse{
		Status: evalStatus,
	}, accumulatedErrors
}

func getEC2Instances(ctx context.Context, client *ec2.Client) iter.Seq2[types.Instance, error] {
	return func(yield func(types.Instance, error) bool) {
		var nextToken *string
		for {
			result, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
				Filters: []types.Filter{
					{
						Name:   aws.String("instance-state-name"),
						Values: []string{"running", "stopped", "stopping", "starting"},
					},
				},
				NextToken: nextToken,
			})
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

			if aws.ToString(result.NextToken) == "" {
				return
			}

			nextToken = result.NextToken
		}
	}
}

func getInstanceSecurityGroups(ctx context.Context, client *ec2.Client, instance types.Instance) ([]types.SecurityGroup, error) {
	groupIDs := getInstanceSecurityGroupIDs(instance)
	if len(groupIDs) == 0 {
		return nil, nil
	}

	result, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: groupIDs,
	})
	if err != nil {
		return nil, err
	}

	return result.SecurityGroups, nil
}

func getInstanceSecurityGroupIDs(instance types.Instance) []string {
	groupIDs := make([]string, 0, len(instance.SecurityGroups))
	seen := make(map[string]struct{}, len(instance.SecurityGroups))

	for _, group := range instance.SecurityGroups {
		groupID := aws.ToString(group.GroupId)
		if groupID == "" {
			continue
		}

		if _, exists := seen[groupID]; exists {
			continue
		}

		seen[groupID] = struct{}{}
		groupIDs = append(groupIDs, groupID)
	}

	for _, networkInterface := range instance.NetworkInterfaces {
		for _, group := range networkInterface.Groups {
			groupID := aws.ToString(group.GroupId)
			if groupID == "" {
				continue
			}

			if _, exists := seen[groupID]; exists {
				continue
			}

			seen[groupID] = struct{}{}
			groupIDs = append(groupIDs, groupID)
		}
	}

	return groupIDs
}

func buildEC2PolicyInput(ctx context.Context, client *ec2.Client, region string, instance types.Instance) (EC2PolicyInput, error) {
	securityGroups, err := getInstanceSecurityGroups(ctx, client, instance)
	if err != nil {
		return EC2PolicyInput{}, err
	}

	volumes, err := getInstanceVolumes(ctx, client, aws.ToString(instance.InstanceId))
	if err != nil {
		return EC2PolicyInput{}, err
	}

	volumeIDs := getVolumeIDs(volumes)
	snapshots, err := getSnapshotsForVolumes(ctx, client, volumeIDs)
	if err != nil {
		return EC2PolicyInput{}, err
	}

	snapshotPermissions, err := getSnapshotPermissions(ctx, client, snapshots)
	if err != nil {
		return EC2PolicyInput{}, err
	}

	snapshotInventory := buildSnapshotInventory(snapshots, snapshotPermissions)

	snapshotIDs := getSnapshotIDs(snapshots)
	images, err := getOwnedImagesForInstance(ctx, client, instance, snapshotIDs)
	if err != nil {
		return EC2PolicyInput{}, err
	}

	fastSnapshotRestore, err := getFastSnapshotRestore(ctx, client, snapshotIDs)
	if err != nil {
		return EC2PolicyInput{}, err
	}

	return EC2PolicyInput{
		Region:              region,
		Instance:            instance,
		SecurityGroups:      securityGroups,
		Volumes:             volumes,
		Snapshots:           snapshots,
		SnapshotInventory:   snapshotInventory,
		SnapshotPermissions: snapshotPermissions,
		Images:              images,
		FastSnapshotRestore: fastSnapshotRestore,
	}, nil
}

func getInstanceVolumes(ctx context.Context, client *ec2.Client, instanceID string) ([]types.Volume, error) {
	if instanceID == "" {
		return nil, nil
	}

	volumes := make([]types.Volume, 0)
	var nextToken *string

	for {
		result, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
			Filters: []types.Filter{
				{
					Name:   aws.String("attachment.instance-id"),
					Values: []string{instanceID},
				},
			},
			NextToken: nextToken,
		})
		if err != nil {
			return nil, err
		}

		volumes = append(volumes, result.Volumes...)
		if aws.ToString(result.NextToken) == "" {
			return volumes, nil
		}

		nextToken = result.NextToken
	}
}

func chunkIDs(ids []string, chunkSize int) [][]string {
	var chunks [][]string
	for i := 0; i < len(ids); i += chunkSize {
		end := i + chunkSize
		if end > len(ids) {
			end = len(ids)
		}
		chunks = append(chunks, ids[i:end])
	}
	return chunks
}

func getSnapshotsForVolumes(ctx context.Context, client *ec2.Client, volumeIDs []string) ([]types.Snapshot, error) {
	if len(volumeIDs) == 0 {
		return nil, nil
	}

	snapshots := make([]types.Snapshot, 0)
	chunks := chunkIDs(volumeIDs, 200)

	for _, chunk := range chunks {
		var nextToken *string
		for {
			result, err := client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
				OwnerIds: []string{"self"},
				Filters: []types.Filter{
					{
						Name:   aws.String("volume-id"),
						Values: chunk,
					},
				},
				NextToken: nextToken,
			})
			if err != nil {
				return nil, err
			}

			snapshots = append(snapshots, result.Snapshots...)
			if aws.ToString(result.NextToken) == "" {
				break
			}

			nextToken = result.NextToken
		}
	}

	return snapshots, nil
}

func getSnapshotPermissions(ctx context.Context, client *ec2.Client, snapshots []types.Snapshot) ([]EC2SnapshotPermission, error) {
	permissions := make([]EC2SnapshotPermission, 0, len(snapshots))

	for _, snapshot := range snapshots {
		snapshotID := aws.ToString(snapshot.SnapshotId)
		if snapshotID == "" {
			continue
		}

		result, err := client.DescribeSnapshotAttribute(ctx, &ec2.DescribeSnapshotAttributeInput{
			Attribute:  types.SnapshotAttributeNameCreateVolumePermission,
			SnapshotId: aws.String(snapshotID),
		})
		if err != nil {
			continue
		}

		permission := EC2SnapshotPermission{
			SnapshotID:              snapshotID,
			CreateVolumePermissions: result.CreateVolumePermissions,
		}

		for _, createVolumePermission := range result.CreateVolumePermissions {
			if createVolumePermission.Group == types.PermissionGroupAll {
				permission.PublicShareEnabled = true
				break
			}
		}

		permissions = append(permissions, permission)
	}

	return permissions, nil
}

func buildSnapshotInventory(snapshots []types.Snapshot, snapshotPermissions []EC2SnapshotPermission) []EC2SnapshotInventoryItem {
	permissionsBySnapshotID := make(map[string]EC2SnapshotPermission, len(snapshotPermissions))
	for _, permission := range snapshotPermissions {
		permissionsBySnapshotID[permission.SnapshotID] = permission
	}

	inventory := make([]EC2SnapshotInventoryItem, 0, len(snapshots))
	for _, snapshot := range snapshots {
		snapshotID := aws.ToString(snapshot.SnapshotId)
		permission := permissionsBySnapshotID[snapshotID]

		inventoryItem := EC2SnapshotInventoryItem{
			SnapshotID:              snapshotID,
			VolumeID:                aws.ToString(snapshot.VolumeId),
			State:                   string(snapshot.State),
			Encrypted:               aws.ToBool(snapshot.Encrypted),
			KmsKeyID:                aws.ToString(snapshot.KmsKeyId),
			OwnerID:                 aws.ToString(snapshot.OwnerId),
			StorageTier:             string(snapshot.StorageTier),
			Description:             aws.ToString(snapshot.Description),
			Tags:                    tagsToMap(snapshot.Tags),
			CreateVolumePermissions: permission.CreateVolumePermissions,
			PublicShareEnabled:      permission.PublicShareEnabled,
		}

		if snapshot.StartTime != nil {
			inventoryItem.StartTime = snapshot.StartTime.Format("2006-01-02T15:04:05Z07:00")
		}

		inventory = append(inventory, inventoryItem)
	}

	return inventory
}

func getOwnedImagesForInstance(ctx context.Context, client *ec2.Client, instance types.Instance, snapshotIDs []string) ([]types.Image, error) {
	imagesByID := make(map[string]types.Image)

	if imageID := aws.ToString(instance.ImageId); imageID != "" {
		result, err := client.DescribeImages(ctx, &ec2.DescribeImagesInput{
			Owners:   []string{"self"},
			ImageIds: []string{imageID},
		})
		if err != nil {
			return nil, err
		}

		for _, image := range result.Images {
			imagesByID[aws.ToString(image.ImageId)] = image
		}
	}

	if len(snapshotIDs) == 0 {
		return mapsToImages(imagesByID), nil
	}

	chunks := chunkIDs(snapshotIDs, 200)
	for _, chunk := range chunks {
		var nextToken *string
		for {
			result, err := client.DescribeImages(ctx, &ec2.DescribeImagesInput{
				Owners: []string{"self"},
				Filters: []types.Filter{
					{
						Name:   aws.String("block-device-mapping.snapshot-id"),
						Values: chunk,
					},
				},
				NextToken: nextToken,
			})
			if err != nil {
				return nil, err
			}

			for _, image := range result.Images {
				imagesByID[aws.ToString(image.ImageId)] = image
			}

			if aws.ToString(result.NextToken) == "" {
				break
			}

			nextToken = result.NextToken
		}
	}

	return mapsToImages(imagesByID), nil
}

func getFastSnapshotRestore(ctx context.Context, client *ec2.Client, snapshotIDs []string) ([]types.DescribeFastSnapshotRestoreSuccessItem, error) {
	if len(snapshotIDs) == 0 {
		return nil, nil
	}

	fastSnapshotRestore := make([]types.DescribeFastSnapshotRestoreSuccessItem, 0)
	chunks := chunkIDs(snapshotIDs, 200)

	for _, chunk := range chunks {
		var nextToken *string
		for {
			result, err := client.DescribeFastSnapshotRestores(ctx, &ec2.DescribeFastSnapshotRestoresInput{
				Filters: []types.Filter{
					{
						Name:   aws.String("snapshot-id"),
						Values: chunk,
					},
				},
				NextToken: nextToken,
			})
			if err != nil {
				return nil, err
			}

			fastSnapshotRestore = append(fastSnapshotRestore, result.FastSnapshotRestores...)
			if aws.ToString(result.NextToken) == "" {
				break
			}

			nextToken = result.NextToken
		}
	}

	return fastSnapshotRestore, nil
}

func getVolumeIDs(volumes []types.Volume) []string {
	volumeIDs := make([]string, 0, len(volumes))
	seen := make(map[string]struct{}, len(volumes))

	for _, volume := range volumes {
		volumeID := aws.ToString(volume.VolumeId)
		if volumeID == "" {
			continue
		}

		if _, exists := seen[volumeID]; exists {
			continue
		}

		seen[volumeID] = struct{}{}
		volumeIDs = append(volumeIDs, volumeID)
	}

	return volumeIDs
}

func getSnapshotIDs(snapshots []types.Snapshot) []string {
	snapshotIDs := make([]string, 0, len(snapshots))
	seen := make(map[string]struct{}, len(snapshots))

	for _, snapshot := range snapshots {
		snapshotID := aws.ToString(snapshot.SnapshotId)
		if snapshotID == "" {
			continue
		}

		if _, exists := seen[snapshotID]; exists {
			continue
		}

		seen[snapshotID] = struct{}{}
		snapshotIDs = append(snapshotIDs, snapshotID)
	}

	return snapshotIDs
}

func getConfiguredRegions(pluginConfig map[string]string) []string {
	regionValue := ""
	if pluginConfig != nil {
		regionValue = pluginConfig["regions"]
		if regionValue == "" {
			regionValue = pluginConfig["region"]
		}
	}

	if regionValue == "" {
		envRegion := strings.TrimSpace(os.Getenv("AWS_REGION"))
		if envRegion == "" {
			return nil
		}

		return []string{envRegion}
	}

	parts := strings.Split(regionValue, ",")
	regions := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		region := strings.TrimSpace(part)
		if region == "" {
			continue
		}

		if _, exists := seen[region]; exists {
			continue
		}

		seen[region] = struct{}{}
		regions = append(regions, region)
	}

	if len(regions) == 0 {
		envRegion := strings.TrimSpace(os.Getenv("AWS_REGION"))
		if envRegion == "" {
			return nil
		}

		return []string{envRegion}
	}

	return regions
}

func tagsToMap(tags []types.Tag) map[string]string {
	if len(tags) == 0 {
		return nil
	}

	result := make(map[string]string, len(tags))
	for _, tag := range tags {
		key := aws.ToString(tag.Key)
		if key == "" {
			continue
		}

		result[key] = aws.ToString(tag.Value)
	}

	if len(result) == 0 {
		return nil
	}

	return result
}

func mapsToImages(imagesByID map[string]types.Image) []types.Image {
	images := make([]types.Image, 0, len(imagesByID))
	for _, image := range imagesByID {
		images = append(images, image)
	}

	return images
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
			"runner": &runner.RunnerV2GRPCPlugin{
				Impl: compliancePluginObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
