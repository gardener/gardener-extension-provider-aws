package helper

import (
	"fmt"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

// ZoneInternal is like aws.Zone but with an additional NameInternal field.
// this is needed to disambiguate duplicated zones with the same.
type ZoneInternal struct {
	aws.Zone
	NameInternal string
}

// HasDuplicatedZoneNames returns true if there are duplicated zone names in the given zones.
func HasDuplicatedZoneNames(zones []aws.Zone) bool {
	zoneNameCount := make(map[string]int)
	for _, zone := range zones {
		count := zoneNameCount[zone.Name]
		if count > 0 {
			return true
		}
		zoneNameCount[zone.Name] = count + 1
	}
	return false
}

// AddInternalZoneName adds the internal zone name to the given tags map under the given key,
// if the internal name is different from the public name.
func AddInternalZoneName(tags map[string]string, key string, zone ZoneInternal) {
	if zone.Name != zone.NameInternal && tags != nil {
		tags[key] = zone.NameInternal
	}
}

// CreateInternalZones creates internal zones from the given zones.
// If there are multiple zones with the same name, the internal name will be suffixed with -<index>.
// For example, if there are two zones with the name "us-west-1a", the internal names will be "us-west-1a" and "us-west-1a-2".
func CreateInternalZones(zones []aws.Zone) []ZoneInternal {
	var zonesInternal []ZoneInternal
	zoneNameCount := make(map[string]int)
	for _, zone := range zones {
		count := zoneNameCount[zone.Name]
		internalName := zone.Name
		if count > 0 {
			// TODO maybe use a hash overs CIDRs as suffix instead of a counter
			internalName = fmt.Sprintf("%s-%d", zone.Name, count+1)
		}
		zoneNameCount[zone.Name] = count + 1
		zonesInternal = append(zonesInternal, ZoneInternal{
			Zone:         zone,
			NameInternal: internalName,
		})
	}
	return zonesInternal
}
