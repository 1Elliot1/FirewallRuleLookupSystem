import logging
import ipaddress
import os
from dotenv import load_dotenv

from panos.panorama import Panorama, DeviceGroup, Template
from panos.firewall import Firewall
from panos.policies import PreRulebase, SecurityRule, NatRule, ApplicationOverride, PolicyBasedForwarding, DecryptionRule, AuthenticationRule
from panos.network import Vlan, Zone, EthernetInterface, AggregateInterface, Layer3Subinterface, Interface
from panos.device import Vsys
from panos.objects import AddressGroup, AddressObject, ServiceObject, ServiceGroup, ApplicationGroup, ApplicationObject, ApplicationContainer
from panos.predefined import Predefined


class PanoramaData:
    """
    Encapsulates retrieval and correlation of Panorama data.
    Builds lookup maps for AddressObjects, DeviceGroups, AddressGroups, VLANs, Zones, and Interfaces.
    """
    def __init__(self, pano):
        self.pano = pano
        self.addressObjects = AddressObject.refreshall(pano)
        self.addressGroups = AddressGroup.refreshall(pano)
        self.deviceGroups = DeviceGroup.refreshall(pano)
        self.templates = Template.refreshall(pano)
        self.applicationObject = ApplicationObject.refreshall(pano)
        self.applicationGroup = ApplicationGroup.refreshall(pano)
        self.applicationContainers = ApplicationContainer.refreshall(pano)
        self.serviceObjects = ServiceObject.refreshall(pano)
        self.serviceGroups = ServiceGroup.refreshall(pano)

        self.predefined = Predefined(pano)
        self.predefined.refreshall_applications()
        self.predefined.refreshall_services()
        self.predefinedApplicationObjects = self.predefined.application_objects
        self.predefinedObjectContainers = self.predefined.application_container_objects
        self.predefinedServiceObjects = self.predefined.service_objects

        self.deviceGroupRules = {}
        self.vlanData = {}

        self.collectDeviceGroupRules()
        self.collectVlanData()

    # --- Data Collection Methods ---
    def collectDeviceGroupRules(self):
        """Refresh rules for each device group."""
        for dg in self.deviceGroups:
            self.deviceGroupRules[dg.name] = self.fetchAllPrerulebaseRules(dg)

    def fetchAllPrerulebaseRules(self, deviceGroup):
        """
        Return a dictionary of rule types for the given device group.
        Some rule types (QoS, DoS, etc.) are not available.
        """
        ruleTypes = [
            SecurityRule,
            NatRule,
            ApplicationOverride,
            PolicyBasedForwarding,
            DecryptionRule,
            AuthenticationRule
        ]
        prerulebase = deviceGroup.find(PreRulebase)
        if prerulebase is None:
            prerulebase = PreRulebase()
            deviceGroup.add(prerulebase)
        allRules = {}
        for ruleType in ruleTypes:
            ruleName = ruleType.__name__
            rules = ruleType.refreshall(prerulebase)
            allRules[ruleName] = rules
        return allRules

    def collectVlanData(self):
        """
        For every template (and its vsys), grab associated zones and VLAN mappings
        using aggregate interfaces and their subinterfaces.
        """
        for template in self.templates:
            for vsys in template.findall(Vsys):
                zones = vsys.findall(Zone)
                for aggInterface in template.findall(AggregateInterface):
                    subInterfaces = self.getChildrenOfAggInterface(aggInterface)
                    vlanMap = self.getAddressForVlans(subInterfaces)
                    key = f"{template.name}-{vsys.name}"
                    if key not in self.vlanData:
                        self.vlanData[key] = {"vlanMap": vlanMap, "zones": zones}
                    else:
                        self.vlanData[key]["vlanMap"].update(vlanMap)

    @staticmethod
    def getChildrenOfAggInterface(aggInterface):
        """
        Return subinterfaces for an aggregate interface.
        Note: Currently only supports Layer3Subinterfaces.
        """
        return aggInterface.findall(Layer3Subinterface)

    @staticmethod
    def getAddressForVlans(subinterfaceList):
        """
        Create a mapping of VLAN numbers to their associated IP ranges.
        Assumes subinterface name format is: <name>.<vlan_number>
        """
        interfaceMap = {}
        for subinterface in subinterfaceList:
            try:
                vlanNum = subinterface.name.split(".")[1]
                interfaceMap[vlanNum] = subinterface.ip
            except IndexError:
                logging.error("Error parsing VLAN number from subinterface name: %s", subinterface.name)
        return interfaceMap

    @staticmethod
    def ipInCidr(ip, cidr):
        """Check if an IP address is within a given CIDR range."""
        try:
            temp = cidr.strip("'[]")
            return ipaddress.ip_address(ip) in ipaddress.ip_network(temp, strict=False)
        except ValueError:
            return False

    # --- Correlation Methods ---
    def correlateAddressToVlan(self, addressObject, vlanMap):
        """
        Given an address object and a VLAN map (vlanNum -> CIDR),
        return the VLAN number if the object's IP falls within a range.
        """
        cleanIp = addressObject.value.split("/")[0]
        for vlanNum, vlanCidr in vlanMap.items():
            if self.ipInCidr(cleanIp, str(vlanCidr)):
                return vlanNum
        return None

    @staticmethod
    def correlateVlanToZone(vlanNum, zones):
        """
        Given a VLAN number and a list of zones, return the matching zone name.
        """
        for zone in zones:
            for interface in zone.interface:
                try:
                    if "." in interface and interface.split(".")[1] == vlanNum:
                        return zone.name
                except IndexError:
                    logging.error("Error parsing VLAN number from interface name: %s", interface)
                    continue
        return None

    def resolveNestedAddressGroups(self, addressGroupName, seen=None):
        """
        Recursively resolve nested address groups.
        Returns a list of parent group names.
        """
        if seen is None:
            seen = set()
        parentGroups = set()
        for group in self.addressGroups:
            if hasattr(group, "static_value"):
                if addressGroupName in group.static_value and group.name not in seen:
                    seen.add(group.name)
                    parentGroups.add(group.name)
                    parentGroups.update(self.resolveNestedAddressGroups(group.name, seen))
        return list(parentGroups)

    def correlateAddressToAddressGroup(self, addressObject):
        """
        Given an address object, return a list of address group names it belongs to,
        including nested (parent) groups.
        """
        directGroups = []
        for group in self.addressGroups:
            if hasattr(group, "static_value"):
                if any(addressObject.name == a or addressObject.value == a for a in group.static_value):
                    directGroups.append(group.name)
        if not directGroups:
            return None
        
        #Handling IP objects that are only explicitly mentioned in a nested group
        fullGroups = set(directGroups)
        for group in directGroups:
            fullGroups.update(self.resolveNestedAddressGroups(group))
        return list(fullGroups)

    def correlateIp(self, ip):
        """
        Given an IP address (string), find its associated AddressObject,
        VLAN, Zone, and AddressGroup.
        """
        #iterate through each object in addressObjects and check if the value matches the IP
        matched = next((obj for obj in self.addressObjects if obj.value == ip), None)
        if not matched:
            #catch if nones found:
            logging.error("No AddressObject found for IP: %s", ip)
            return None

        correlation = {
            "ip": ip,
            "addressObject": [matched.name],
            "vlan": None,
            "zone": None,
            "addressGroup": None,
            "matchingRules": []
        }
        #!!! Here, the refactor changes the logic to correlate zone, addrGroups, and vlans within the correlateIP method
        for key, data in self.vlanData.items():
            vlanMap = data.get("vlanMap", {})
            zones = data.get("zones", [])
            vlanNum = self.correlateAddressToVlan(matched, vlanMap)
            if vlanNum:
                correlation["vlan"] = vlanNum
                correlation["zone"] = self.correlateVlanToZone(vlanNum, zones)
                break
        correlation["addressGroup"] = self.correlateAddressToAddressGroup(matched)
        return correlation

    def correlateAddressObjectName(self, addressObjectName):
        """
        Given an address object name (string), find its associated AddressObject,
        VLAN, Zone, and AddressGroup.
        """
        #match the name to the address object name, break early and assign to var if found
        matched = next((obj for obj in self.addressObjects if obj.name == addressObjectName), None)
        if not matched:
            logging.error("No AddressObject found for name: %s", addressObjectName)
            return None

        correlation = {
            "ip": matched.value,
            "addressObject": [addressObjectName],
            "vlan": None,
            "zone": None,
            "addressGroup": None,
            "matchingRules": []
        }
        #!!! Here, the refactor changes the logic to correlate zone, addrGroups, and vlans within the correlateAddressObjectName method
        for key, data in self.vlanData.items():
            vlanMap = data.get("vlanMap", {})
            zones = data.get("zones", [])
            vlanNum = self.correlateAddressToVlan(matched, vlanMap)
            if vlanNum:
                correlation["vlan"] = vlanNum
                correlation["zone"] = self.correlateVlanToZone(vlanNum, zones)
                break
        correlation["addressGroup"] = self.correlateAddressToAddressGroup(matched)
        return correlation

    def correlateInput(self, inputValue):
        """
        Determine the type of input and perform correlation.
        Currently assumes inputValue is an IP address.
        """
        try:
            #TODO: Implement logic to determine if inputValue is an address object name, CIDR, or other types
            # For now, assume it's an IP address
            return self.correlateIp(inputValue)
        except Exception as e:
            logging.error("Error correlating input %s: %s", inputValue, e)
            return None

    def correlateApplications(self, correlation):
        """
        Stub for correlating applications to the input.
        TODO: Implement application correlation logic.
        """
        correlation["applications"] = []
        return correlation

    def correlateServices(self, correlation):
        """
        Stub for correlating services to the input.
        TODO: Implement service correlation logic.
        """
        correlation["services"] = []
        return correlation

    # --- Rule Lookup Methods ---
    def ruleImpactsCorrelation(self, rule, correlation):
        """
        Check if a given rule impacts the input based on the correlation.
        This checks address objects, VLAN, zone, and address groups.
        """
        #For every value in either addressObject or VLAN fields, check if it exists in the rule's source or destination
        for field in ["addressObject", "vlan"]:
            #if correlation matrix contains the field's value, check if it exists in the rule's source or destination
            #if correlation[field] is a list, iterate through it, otherwise just check the value
            if correlation.get(field):
                values = correlation[field] if isinstance(correlation[field], list) else [correlation[field]]
                for item in values:
                    #check if the item's literal value exists in the rule's source or destination
                    if item in getattr(rule, "source", []) or item in getattr(rule, "destination", []):
                        return True
        #if correlation matrix contains a zone:
        if correlation.get("zone"):
            #check rule objects fromzone and tozone for the zone value
            if correlation["zone"] in getattr(rule, "fromzone", []) or correlation["zone"] in getattr(rule, "tozone", []):
                return True
        #if correlation matrix contains an address group:
        if correlation.get("addressGroup"):
            #iterate through all groups in the correlation matrix:
            for group in correlation["addressGroup"]:
                if group in getattr(rule, "source", []) or group in getattr(rule, "destination", []):
                    return True
        # TODO: Extend to applications and services if needed
        return False

    def findMatchingRules(self, correlation):
        """
        Iterate through device group rules and return a list of rules that match the correlation.
        """
        matching = []
        for dgName, ruleTypes in self.deviceGroupRules.items():
            for ruleTypeName, rules in ruleTypes.items():
                for rule in rules:
                    if self.ruleImpactsCorrelation(rule, correlation):
                        matching.append({
                            "deviceGroup": dgName,
                            "ruleType": ruleTypeName,
                            "ruleName": rule.name,
                            "source": getattr(rule, "source", []),
                            "destination": getattr(rule, "destination", []),
                            "action": getattr(rule, "action", None),
                            "service": getattr(rule, "service", []),
                            "application": getattr(rule, "application", []),
                            "fromzone": getattr(rule, "fromzone", []),
                            "tozone": getattr(rule, "tozone", [])
                        })
        return matching

    def fullCorrelationLookup(self, inputValue):
        """
        High-level method:
         1. Correlate the input to known objects.
         2. Correlate applications and services.
         3. Find and return all matching rules.
        """
        correlation = self.correlateInput(inputValue)
        if not correlation:
            return None
        correlation = self.correlateApplications(correlation)
        correlation = self.correlateServices(correlation)
        correlation["matchingRules"] = self.findMatchingRules(correlation)
        return correlation

    # --- Lookup Methods for Different Input Types ---
    def lookupRulesBySubnet(self, subnet):
        """
        Lookup rules that apply to the given subnet.
        TODO: Implement subnet overlap logic.
        """
        correlation = {
            "ip": subnet,
            "addressObject": None,
            "vlan": None,
            "zone": None,
            "addressGroup": None,
            "applications": None,
            "services": None,
            "matchingRules": []
        }
        correlation["matchingRules"] = self.findMatchingRules(correlation)
        return correlation

    def lookupRulesByApplication(self, applicationName):
        """
        Lookup rules that reference the given application.
        TODO: Implement application-based rule matching.
        """
        correlation = {
            "ip": None,
            "addressObject": None,
            "vlan": None,
            "zone": None,
            "addressGroup": None,
            "applications": [applicationName],
            "services": None,
            "matchingRules": []
        }
        correlation["matchingRules"] = self.findMatchingRules(correlation)
        return correlation

    def lookupRulesByZone(self, zone):
        """
        Lookup rules that apply to the given zone.
        """
        correlation = {
            "ip": None,
            "addressObject": None,
            "vlan": None,
            "zone": zone,
            "addressGroup": None,
            "applications": None,
            "services": None,
            "matchingRules": []
        }
        correlation["matchingRules"] = self.findMatchingRules(correlation)
        return correlation

    def lookupRulesByAddressGroup(self, addressGroupName):
        """
        Lookup rules that apply to the given address group, including nested groups.
        """
        resolved = {addressGroupName}
        #!!! Refactor changes logic here. Call update on the resolved dict with a resolveNestedAddressGroup call
        resolved.update(self.resolveNestedAddressGroups(addressGroupName))
        correlation = {
            "ip": None,
            "addressObject": None,
            "vlan": None,
            "zone": None,
            "addressGroup": list(resolved),
            "applications": None,
            "services": None,
            "matchingRules": []
        }
        correlation["matchingRules"] = self.findMatchingRules(correlation)
        return correlation

    def lookupRulesByVlan(self, vlanNum):
        """
        Lookup rules that apply to the given VLAN number.
        """
        correlation = {
            "ip": None,
            "addressObject": None,
            "vlan": vlanNum,
            "zone": None,
            "addressGroup": None,
            "applications": None,
            "services": None,
            "matchingRules": []
        }
        for key, data in self.vlanData.items():
            vlanMap = data.get("vlanMap", {})
            zones = data.get("zones", [])
            if vlanNum in vlanMap:
                correlation["zone"] = self.correlateVlanToZone(vlanNum, zones)
                break
        correlation["matchingRules"] = self.findMatchingRules(correlation)
        return correlation

    def lookupRulesByCIDR(self, CIDR):
        """
        Lookup rules that apply to the given CIDR range.
        Checks for overlaps with VLAN CIDRs and individual address objects.
        """
        network = ipaddress.ip_network(CIDR, strict=False)
        correlation = {
            "ip": CIDR,
            "addressObject": [],
            "vlan": None,
            "zone": None,
            "addressGroup": None,
            "applications": None,
            "services": None,
            "matchingRules": []
        }
        for key, data in self.vlanData.items():
            vlanMap = data.get("vlanMap", {})
            zones = data.get("zones", [])
            for vlanNum, vlanCIDR in vlanMap.items():
                vlanNetwork = ipaddress.ip_network(str(vlanCIDR).strip("'[]"), strict=False)
                if network.overlaps(vlanNetwork):
                    correlation["vlan"] = vlanNum
                    correlation["zone"] = self.correlateVlanToZone(vlanNum, zones)
                    break
            if correlation["vlan"]:
                break
        for addr in self.addressObjects:
            try:
                addrIp = addr.value.split('/')[0]
                if self.ipInCidr(addrIp, CIDR):
                    correlation["addressObject"].append(addr.name)
            except ValueError:
                logging.error("Invalid address object value: %s", addr.value)
        correlation["matchingRules"] = self.findMatchingRules(correlation)
        return correlation


# --- Test Methods ---
def testReport(panData):
    """
    Dummy test method that runs a CIDR lookup and prints a detailed report:
      - Search term
      - Zone, VLAN, and Address Groups
      - Matching IP objects (and count)
      - Summary of matching rules per type, with one example per type.
    """
    searchTerm = ""  # Adjust as needed
    result = panData.lookupRulesByCIDR(searchTerm)
    if not result:
        logging.error("No correlation result found for search term: %s", searchTerm)
        return

    reportLines = [
        "========== Detailed Report ==========",
        f"Search Term: {searchTerm}",
        f"Zone: {result.get('zone')}",
        f"VLAN: {result.get('vlan')}"
    ]

    ipObjs = result.get("addressObject")
    if isinstance(ipObjs, list):
        reportLines.append(f"Address Objects ({len(ipObjs)}): {', '.join(ipObjs)}")
    else:
        reportLines.append(f"Address Object: {ipObjs}")

    matchingRules = result.get("matchingRules", [])
    if matchingRules:
        ruleCounts = {}
        ruleExamples = {}
        for rule in matchingRules:
            rt = rule.get("ruleType")
            ruleCounts[rt] = ruleCounts.get(rt, 0) + 1
            if rt not in ruleExamples:
                ruleExamples[rt] = rule
        reportLines.append("\n--- Matching Rule Summary ---")
        for rt, count in ruleCounts.items():
            reportLines.append(f"{rt}: {count} rule(s)")
        reportLines.append("\n--- Rule Examples ---")
        for rt, rule in ruleExamples.items():
            example = (f"[{rt}] Device Group: {rule.get('deviceGroup')}, "
                       f"Rule Name: {rule.get('ruleName')}, "
                       f"Source: {', '.join(rule.get('source', []))}, "
                       f"Destination: {', '.join(rule.get('destination', []))}, "
                       f"Action: {rule.get('action')}",
                       f"From Zone: {', '.join(rule['fromzone'])}",
                       f"To Zone: {', '.join(rule['tozone'])}")
            reportLines.append(example)
    else:
        reportLines.append("No matching rules found.")

    reportLines.append("========== End of Report ==========")
    print("\n".join(reportLines))


def main():
    load_dotenv()
    apiKey = os.environ.get("API_KEY")
    panAddress = os.environ.get("PAN_ADDRESS")

    logging.basicConfig(level=logging.DEBUG)
    pano = Panorama(panAddress, api_key=apiKey)
    logging.info("Connected to Panorama at %s", pano.hostname)

    logging.info("Refreshing Managed Devices...")
    devices = pano.refresh_devices()
    logging.info("Found %d Managed Devices", len(devices))

    panData = PanoramaData(pano)
    testReport(panData)


if __name__ == "__main__":
    main()
