import * as iam from '@aws-cdk/aws-iam';
import * as autoscaling from '@aws-cdk/aws-autoscaling';
import * as ec2 from '@aws-cdk/aws-ec2';
import * as cdk from '@aws-cdk/core';
import { Vpc6 } from './vpc6';

// Replacement for UserData.addSignalOnExitCommand()
// -> https://github.com/aws/aws-cdk/issues/10231
function addSignalOnExitCommand(userData: ec2.UserData, resource: cdk.CfnElement) {
    const stack = cdk.Stack.of(resource);
    const resourceID = resource.logicalId;
    userData.addOnExitCommands(`/opt/aws/bin/cfn-signal --stack ${stack.stackName} --resource ${resourceID} --region ${stack.region} -e $exitCode || echo 'Failed to send Cloudformation Signal'`);
}

function ifelse(predicate: cdk.CfnCondition | boolean, iftrue: string, iffalse: string): string {
    if (cdk.Token.isUnresolved(predicate)) {
        return cdk.Fn.conditionIf((predicate as cdk.CfnCondition).logicalId, iftrue, iffalse).toString();
    } else {
        return predicate ? iftrue : iffalse;
    }
}

// A version of amazon-eks-vpc-private-subnets.yaml which includes IPv6 cidrs
class EksVpcPrivateSubnetsStack extends cdk.Stack {
    constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        const inner = new EksVpcPrivateSubnets(this, 'Stack');

        new cdk.CfnOutput(this, 'SubnetIds', {
            description: 'Subnet IDs in the VPC',
            value: cdk.Fn.join(',', inner.subnets.map((s) => s.subnetId)),
        });

        new cdk.CfnOutput(this, 'SecurityGroups', {
            description: 'Security group for the cluster control plane communicating with worker nodes',
            value: cdk.Fn.join(',', [inner.securityGroup.securityGroupId]),
        });

        new cdk.CfnOutput(this, 'VpcId', {
            description: 'The VPC Id',
            value: inner.vpc.vpcId,
        });

    }
}

export class EksVpcPrivateSubnets extends cdk.Construct {
    public readonly subnets: ec2.ISubnet[];
    public readonly securityGroup: ec2.SecurityGroup;
    public readonly vpc: ec2.Vpc;

    constructor(scope: cdk.Construct, id: string) {
        super(scope, id);

        const vpc6 = new Vpc6(this, 'VPC', {
            cidr: '192.168.0.0/16',
            enableDnsSupport: true,
            enableDnsHostnames: true,
        });
        this.vpc = vpc6;

        for (const subnet of vpc6.publicSubnets) {
            cdk.Tags.of(subnet).add('kubernetes.io/role/elb', '1', {
                includeResourceTypes: ['AWS::EC2::Subnet'],
            });
        }
        for (const subnet of vpc6.privateSubnets) {
            cdk.Tags.of(subnet).add('kubernetes.io/role/internal-elb', '1', {
                includeResourceTypes: ['AWS::EC2::Subnet'],
            });
        }

        const allSubnets = [...vpc6.publicSubnets, ...vpc6.privateSubnets, ...vpc6.isolatedSubnets];
        this.subnets = allSubnets;

        const secGroup = new ec2.SecurityGroup(this, 'ControlPlaneSecurityGroup', {
            description: 'Cluster communication with worker nodes',
            vpc: vpc6,
        });
        this.securityGroup = secGroup;
    }
}

// IPv6-enabled version of amazon-eks-nodegroup.yaml
class EksNodegroupStack extends cdk.Stack {
    constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        const bootstrapArgs = new cdk.CfnParameter(this, 'BootstrapArguments', {
            type: 'String',
            default: '',
            description: 'Arguments to pass to the bootstrap script. See files/bootstrap.sh in https://github.com/awslabs/amazon-eks-ami',
        }).valueAsString;

        const clusterCPSecurityGroupId = new cdk.CfnParameter(this, 'ClusterControlPlaneSecurityGroup', {
            type: 'AWS::EC2::SecurityGroup::Id',
            description: 'The security group of the cluster control plane.',
        }).valueAsString;
        const clusterCPSecurityGroup = ec2.SecurityGroup.fromSecurityGroupId(this, 'ClusterControlPlaneSecurityGroupRef', clusterCPSecurityGroupId);

        const clusterName = new cdk.CfnParameter(this, 'ClusterName', {
            type: 'String',
            description: 'The cluster name provided when the cluster was created. If it is incorrect, nodes will not be able to join the cluster.',
        }).valueAsString;

        const keyName = new cdk.CfnParameter(this, 'KeyName', {
            type: 'AWS::EC2::KeyPair::KeyName',
            description: 'The EC2 Key Pair to allow SSH access to the instances',
        }).valueAsString;

        const nodeAsgCapacity = new cdk.CfnParameter(this, 'NodeAutoScalingGroupDesiredCapacity', {
            type: 'Number',
            default: 3,
            description: 'Desired capacity of Node Group ASG.',
        }).valueAsNumber;

        const nodeAsgMax = new cdk.CfnParameter(this, 'NodeAutoScalingGroupMaxSize', {
            type: 'Number',
            default: 4,
            description: 'Maximum size of Node Group ASG. Set to at least 1 greater than NodeAutoScalingGroupDesiredCapacity.',
        }).valueAsNumber;

        const nodeAsgMin = new cdk.CfnParameter(this, 'NodeAutoScalingGroupMinSize', {
            type: 'Number',
            default: 1,
            description: 'Minimum size of Node Group ASG.',
        }).valueAsNumber;

        const nodeAsgName = new cdk.CfnParameter(this, 'NodeGroupName', {
            type: 'String',
            description: 'Unique identifier for the Node Group.',
        }).valueAsString;

        const nodeImageId = new cdk.CfnParameter(this, 'NodeImageId', {
            type: 'String',
            default: '',
            description: '(Optional) Specify your own custom image ID. This value overrides any AWS Systems Manager Parameter Store value specified above.',
        }).valueAsString;

        const nodeImageSSM = new cdk.CfnParameter(this, 'NodeImageIdSSMParam', {
            type: 'AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>',
            default: '/aws/service/eks/optimized-ami/1.17/amazon-linux-2/recommended/image_id',
            description: 'AWS Systems Manager Parameter Store parameter of the AMI ID for the worker node instances. Change this value to match the version of Kubernetes you are using.',
        }).valueAsString;

        const hasNodeImage = new cdk.CfnCondition(this, 'HasNodeImageId', {
            expression: cdk.Fn.conditionNot(
                cdk.Fn.conditionEquals(nodeImageId, ''),
            ),
        });
        const nodeImage = {
            imageId: ifelse(hasNodeImage, nodeImageId, nodeImageSSM),
            osType: ec2.OperatingSystemType.LINUX,
            userData: ec2.UserData.forLinux(),
        };

        const disableImdsV1 = new cdk.CfnParameter(this, 'DisableIMDSv1', {
            type: 'String',
            default: 'false',
            allowedValues: ['true', 'false'],
        }).valueAsString;
        const imdsV1Disabled = new cdk.CfnCondition(this, 'IMDSv1Disabled', {
            expression: cdk.Fn.conditionEquals(disableImdsV1, 'true'),
        });

        const instanceType = new cdk.CfnParameter(this, 'NodeInstanceType', {
            type: 'String',
            default: 't3.medium',
            description: 'EC2 instance type for the node instances',
        }).valueAsString;

        const nodeVolumeSize = new cdk.CfnParameter(this, 'NodeVolumeSize', {
            type: 'Number',
            default: 20,
            description: 'Node volume size',
        }).valueAsNumber;

        const subnetIds = new cdk.CfnParameter(this, 'Subnets', {
            type: 'List<AWS::EC2::Subnet::Id>',
            description: 'The subnets where workers can be created.',
        }).valueAsList;

        const vpcId = new cdk.CfnParameter(this, 'VpcId', {
            type: 'AWS::EC2::VPC::Id',
            description: 'The VPC of the worker instances',
        }).valueAsString;

        const vpc = ec2.Vpc.fromVpcAttributes(this, 'VPC', {
            vpcId: vpcId,
            availabilityZones: ['dummy'],
        });

        const inner = new EksNodegroup(this, 'Stack', {
            bootstrapArguments: bootstrapArgs,
            clusterControlPlaneSecurityGroup: clusterCPSecurityGroup,
            clusterName: clusterName,
            keyName: keyName,
            nodeAutoScalingGroupProps: {
                desiredCapacity: cdk.Token.asString(nodeAsgCapacity),
                maxSize: cdk.Token.asString(nodeAsgMax),
                minSize: cdk.Token.asString(nodeAsgMin),
            },
            nodeImage: {getImage: _scope => nodeImage},
            disableIMDSv1: imdsV1Disabled,
            instanceType: new ec2.InstanceType(instanceType),
            nodeVolumeSize: nodeVolumeSize,
            subnetIds: subnetIds,
            vpc: vpc,
        });

        cdk.Tags.of(inner).add('Name', `${clusterName}-${nodeAsgName}-Node`, {
            includeResourceTypes: ['AWS::EC2::AutoScalingGroup'],
            applyToLaunchedInstances: true,
        });

        new cdk.CfnOutput(this, 'NodeInstanceRoleOutput', {
            description: 'The node instance role',
            value: inner.instanceRole.roleArn,
        }).overrideLogicalId('NodeInstanceRole');

        new cdk.CfnOutput(this, 'NodeSecurityGroupOutput', {
            description: 'The security group for the node group',
            value: inner.securityGroup.securityGroupId,
        }).overrideLogicalId('NodeSecurityGroup');

        new cdk.CfnOutput(this, 'NodeAutoScalingGroupOutput', {
            description: 'The autoscaling group',
            value: inner.asg.autoScalingGroupName,
        }).overrideLogicalId('NodeAutoScalingGroup');
    }
}

export interface EksNodegroupProps {
    readonly bootstrapArguments?: string;
    readonly clusterControlPlaneSecurityGroup: ec2.ISecurityGroup;
    readonly clusterName?: string;
    readonly keyName?: string;
    readonly nodeAutoScalingGroupProps?: autoscaling.CfnAutoScalingGroupProps;
    readonly nodeImage: ec2.IMachineImage;
    readonly disableIMDSv1?: cdk.CfnCondition | boolean;
    readonly instanceType?: ec2.InstanceType;
    readonly nodeVolumeSize?: number;
    readonly subnetIds: string[];
    readonly vpc: ec2.IVpc;
}

export class EksNodegroup extends cdk.Construct {
    public readonly instanceRole: iam.Role;
    public readonly securityGroup: ec2.SecurityGroup;
    public readonly asg: autoscaling.IAutoScalingGroup;

    constructor(scope: cdk.Construct, id: string, props: EksNodegroupProps) {
        super(scope, id);

        const bootstrapArgs = props.bootstrapArguments ?? '';
        const clusterCPSecurityGroup = props.clusterControlPlaneSecurityGroup;
        const clusterName = props.clusterName || this.node.uniqueId;
        const keyName = props.keyName;
        const nodeAsgProps= props.nodeAutoScalingGroupProps || {maxSize: '3', minSize: '1'};
        const nodeImage = props.nodeImage;
        const imdsV1Disabled = props.disableIMDSv1 ?? false;
        const instanceType = props.instanceType ?? new ec2.InstanceType('t3.medium');
        const nodeVolumeSize = props.nodeVolumeSize || 20;
        const subnetIds = props.subnetIds;
        const vpc = props.vpc;

        // Limit to a single subnet, to make the fake-PD routing easier.
        // (Not part of a final solution)
        const subnetId = cdk.Fn.select(0, subnetIds);

        const instanceRole = new iam.Role(this, 'NodeInstanceRole', {
            assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
        });
        ['AmazonEKSWorkerNodePolicy', 'AmazonEKS_CNI_Policy', 'AmazonEC2ContainerRegistryReadOnly'].forEach((p) => {
            instanceRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName(p));
        });
        this.instanceRole = instanceRole;

        const instanceProfile = new iam.CfnInstanceProfile(this, 'NodeInstanceProfile', {
            path: '/',
            roles: [instanceRole.roleName],
        });

        const secGroup = new ec2.SecurityGroup(this, 'NodeSecurityGroup', {
            description: 'Security group for all nodes in the cluster',
            vpc: vpc,
            // Urgh, "all" means "only IPv4" :(
            // Have to set this to 'false' to avoid:
            // "Ignoring Egress rule since 'allowAllOutbound' is set to true"
            allowAllOutbound: false,
        });

        // This is allowAllOutbound=true, where "all" _includes_ IPv6!
        [ec2.Peer.anyIpv4(), ec2.Peer.anyIpv6()].forEach((l3) => {
            // Urgh, CDK errors out if we use Port.allTraffic() here
            // because of the allowAllOutbound=false wars, so we have
            // to allow each of tcp/udp/icmp separately.
            // https://github.com/aws/aws-cdk/pull/7827#discussion_r456199699
            [ec2.Port.allTcp(), ec2.Port.allUdp()].forEach((l4) => {
                secGroup.connections.allowTo(l3, l4);
            });
        });
        secGroup.connections.allowTo(ec2.Peer.anyIpv4(), ec2.Port.allIcmp());
        secGroup.connections.allowTo(ec2.Peer.anyIpv6(), new ec2.Port({
            protocol: ec2.Protocol.ICMPV6,
            fromPort: -1,
            toPort: -1,
            stringRepresentation: 'ALL ICMPV6',
        }));

        secGroup.connections.allowInternally(
            ec2.Port.allTraffic(),
            'Allow node to communicate with each other');
        secGroup.connections.allowTo(
            clusterCPSecurityGroup, ec2.Port.tcp(443),
            'Allow pods to communicate with the cluster API Server');
        secGroup.connections.allowFrom(
            clusterCPSecurityGroup, ec2.Port.tcpRange(1025, 65535),
            'Allow the cluster control plane to communicate with worker Kubelet and pods');
        secGroup.connections.allowFrom(
            clusterCPSecurityGroup, ec2.Port.tcp(443),
            'Allow the cluster control plane to communicate with pods running extension API servers on port 443')
        this.securityGroup = secGroup;

        const userData = ec2.UserData.forLinux();
        userData.addCommands('set -o xtrace');

        // Allow session manager
        userData.addCommands('yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm');
        instanceRole.addManagedPolicy(iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'));

        userData.addCommands(`/etc/eks/bootstrap.sh ${clusterName} ${bootstrapArgs}`);

        const launchTemplate = new ec2.CfnLaunchTemplate(this, 'NodeLaunchTemplate', {
            launchTemplateData: {
                blockDeviceMappings: [{
                    deviceName: '/dev/xvda',
                    ebs: {
                        deleteOnTermination: true,
                        volumeSize: nodeVolumeSize,
                        volumeType: ec2.EbsDeviceVolumeType.GP2,
                    },
                }],
                iamInstanceProfile: {
                    arn: instanceProfile.attrArn,
                },
                imageId: nodeImage.getImage(this).imageId,
                instanceType: instanceType.toString(),
                keyName: keyName,
                userData: cdk.Fn.base64(cdk.Lazy.stringValue({produce: () => userData.render()})),
                metadataOptions: {
                    httpPutResponseHopLimit: 2,
                    httpEndpoint: 'enabled',
                    httpTokens: ifelse(imdsV1Disabled, 'required', 'optional'),
                },
                networkInterfaces: [{
                    deviceIndex: 0,
                    groups: [secGroup].map(s => s.securityGroupId),
                    ipv6AddressCount: 1, // <- this whole stack exists for this!
                    deleteOnTermination: true,
                    subnetId: subnetId,
                }],
            },
        });

        const asg = new autoscaling.CfnAutoScalingGroup(this, 'NodeGroup', {
            launchTemplate: {
                launchTemplateId: launchTemplate.ref,
                version: launchTemplate.attrLatestVersionNumber,
            },
            vpcZoneIdentifier: [subnetId],
            ...nodeAsgProps,
        });
        asg.cfnOptions.updatePolicy = {
            autoScalingRollingUpdate: {
                maxBatchSize: 1,
                minInstancesInService: cdk.Token.asNumber(nodeAsgProps?.minSize),
                pauseTime: cdk.Duration.minutes(5).toIsoString(),
             },
        };
        addSignalOnExitCommand(userData, asg);
        this.node.defaultChild = asg;
        this.asg = autoscaling.AutoScalingGroup.fromAutoScalingGroupName(this, 'NodeGroupASG', asg.ref);

        cdk.Tags.of(this).add(`kubernetes.io/cluster/${clusterName}`, 'owned', {
            applyToLaunchedInstances: true,
        });
    }
}

const app = new cdk.App();
new EksVpcPrivateSubnetsStack(app, 'amazon-eks-vpc-ipv6-subnets', {
    description: 'Amazon EKS Sample VPC - IPv6 subnets',
});
new EksNodegroupStack(app, 'amazon-eks-nodegroup', {
    description: 'Amazon EKS - Node Group',
});
app.synth();
