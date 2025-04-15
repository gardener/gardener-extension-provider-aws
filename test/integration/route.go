package integration

import (
	"context"
	"fmt"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"k8s.io/utils/ptr"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

// AddRoute adds a route for the default vpc route table with myIpCidr as destination
func AddRoute(ctx context.Context, awsClient *awsclient.Client, vpcID, gatewayID, myIpCidr string) error {
	vpcIDFilter := []ec2types.Filter{
		{
			Name: awssdk.String(awsclient.FilterVpcID),
			Values: []string{
				vpcID,
			},
		},
	}

	routeTablesOutput, err := awsClient.EC2.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{
		Filters: vpcIDFilter,
	})
	if err != nil {
		return err
	}
	if len(routeTablesOutput.RouteTables) != 1 {
		return fmt.Errorf("expected 1 route table for vpc but got %d", len(routeTablesOutput.RouteTables))
	}

	_, err = awsClient.EC2.CreateRoute(ctx, &ec2.CreateRouteInput{
		DestinationCidrBlock: ptr.To(myIpCidr),
		GatewayId:            ptr.To(gatewayID),
		RouteTableId:         routeTablesOutput.RouteTables[0].RouteTableId,
	})
	return err
}
