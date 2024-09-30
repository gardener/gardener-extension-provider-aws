package integration

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"k8s.io/utils/ptr"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

// AddRoute adds a route for the default vpc route table with myIpCidr as destination
func AddRoute(ctx context.Context, awsClient *awsclient.Client, vpcID, gatewayID, myIpCidr string) error {
	vpcIDFilter := []*ec2.Filter{
		{
			Name: awssdk.String("vpc-id"),
			Values: []*string{
				awssdk.String(vpcID),
			},
		},
	}

	routeTablesOutput, err := awsClient.EC2.DescribeRouteTablesWithContext(ctx, &ec2.DescribeRouteTablesInput{
		Filters: vpcIDFilter,
	})
	if err != nil {
		return err
	}
	if len(routeTablesOutput.RouteTables) != 1 {
		return fmt.Errorf("expected 1 route table for vpc but got %d", len(routeTablesOutput.RouteTables))
	}

	_, err = awsClient.EC2.CreateRoute(&ec2.CreateRouteInput{
		DestinationCidrBlock: ptr.To(myIpCidr),
		GatewayId:            ptr.To(gatewayID),
		RouteTableId:         routeTablesOutput.RouteTables[0].RouteTableId,
	})
	return err
}
