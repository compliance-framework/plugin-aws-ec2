# AWS EC2 CCF Plugin

This plugin collects read-only AWS EC2, EBS, snapshot, and recovery metadata, evaluates CCF Rego policy bundles, and emits evidence back through the CCF agent.

## Supported resource families

The collector can evaluate policies for:

- EC2 instances
- attached security groups
- attached EBS volumes
- account-owned EBS snapshots for attached volumes
- snapshot restore permissions
- account-owned AMIs related to the instance or collected snapshots
- Fast Snapshot Restore state for collected snapshots

## How it fits in CCF

The CCF agent starts this binary through HashiCorp `go-plugin`, passes configuration and policy paths over gRPC, and receives generated evidence through the runner callback. This repository does not call the CCF API directly.

During `Init`, the plugin also registers EC2 subject templates and risk templates discovered from the supplied policy bundles.

## Default policy bundle mapping

| Repository | Behavior | Primary input |
| --- | --- | --- |
| `plugin-aws-ec2-policies` | `ec2` | `input.instance` plus related EC2, EBS, and recovery fields |

## Configuration

The plugin expects:

- AWS credentials through the default AWS SDK credential chain
- target regions from `config.regions`
- `AWS_REGION` env as a fallback when plugin config does not provide a region

`config.regions` can contain a comma-separated list. Duplicate and empty region values are ignored.

Any agent-supplied `policy_data` is passed through to Rego as `data.*`.

## Data collected

For each running, stopped, stopping, or starting EC2 instance in each configured region, the plugin can collect and correlate:

- instance details and metadata options
- VPC and subnet identifiers
- attached security groups
- attached EBS volumes
- account-owned snapshots for attached volumes
- derived snapshot inventory, including encryption and public restore flags
- snapshot create-volume permissions
- account-owned AMIs that match the instance image or collected snapshots
- Fast Snapshot Restore entries for collected snapshots

## Development

Run the local test suite with:

```shell
go test ./...
```

Or use the Makefile wrapper:

```shell
make test
```

Build the plugin binary with:

```shell
make build
```

This writes the compiled plugin to `dist/plugin`.

## Related repositories

- [plugin-aws-ec2-policies](https://github.com/compliance-framework/plugin-aws-ec2-policies)
