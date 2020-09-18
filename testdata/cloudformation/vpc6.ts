import * as ec2 from '@aws-cdk/aws-ec2';
import * as cdk from '@aws-cdk/core';

// IPv6-enabled VPC
//
// Alas, there is no simple 'v6enabled' bool, so we have to do
// this the long way :(
// TODO: obsolete this class by improving CDK.
export class Vpc6 extends ec2.Vpc {
    constructor(scope: cdk.Construct, id: string, props?: ec2.VpcProps) {
        super(scope, id, props);

        const ip6cidr = new ec2.CfnVPCCidrBlock(this, 'Cidr6', {
            vpcId: this.vpcId,
            amazonProvidedIpv6CidrBlock: true,
        });

        const igw6 = new ec2.CfnEgressOnlyInternetGateway(this, 'IGW6', {
            vpcId: this.vpcId,
        });

        const vpc6cidr = cdk.Fn.select(0, this.vpcIpv6CidrBlocks);
        const subnet6cidrs = cdk.Fn.cidr(vpc6cidr, 256, (128-64).toString());

        // Note the public/private/isolated distinction doesn't make
        // any sense in IPv6.  After the following they all become
        // "public" wrt IPv6.
        const allSubnets = [...this.publicSubnets, ...this.privateSubnets, ...this.isolatedSubnets];

        allSubnets.forEach((subnet, i) => {
            const cidr6 = cdk.Fn.select(i, subnet6cidrs);

            const cfnSubnet = subnet.node.defaultChild as ec2.CfnSubnet;
            cfnSubnet.ipv6CidrBlock = cidr6;
            subnet.node.addDependency(ip6cidr);

            new ec2.CfnRoute(cfnSubnet, 'DefaultRoute6', {
                destinationIpv6CidrBlock: '::/0',
                routeTableId: subnet.routeTable.routeTableId,
                egressOnlyInternetGatewayId: igw6.ref,
            })
        });
    }
}
