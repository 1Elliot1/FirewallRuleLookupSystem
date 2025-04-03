import logging
from panos.panorama import Panorama, DeviceGroup, Template
from panos.firewall import Firewall
from panos.policies import PreRulebase, SecurityRule, NatRule, ApplicationOverride, PolicyBasedForwarding, DecryptionRule, AuthenticationRule
from panos.network import Vlan, Zone, EthernetInterface, AggregateInterface, Layer3Subinterface, Interface
from panos.device import Vsys
from panos.objects import AddressGroup, AddressObject, ServiceObject, ServiceGroup, ApplicationGroup, ApplicationObject, ApplicationContainer
from panos.predefined import Predefined
from dotenv import load_dotenv
import ipaddress
import os

class PanoramaData:
    """
    Encapsulates retrieval and correlation of Panorama data. 
    Builds lookup maps for 
        AddressObjects
        DeviceGroups
        AddressGroups
        VLANs
        Zones
        Interfaces
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
        #Represents a map of application name: application object
        #'windows-azure-base': <ApplicationObject windows-azure-base 0x2c099c4c3d0>
        self.predefinedApplicationObjects = self.predefined.application_objects
        self.predefinedObjectContainers = self.predefined.application_container_objects
        #holds two objects, there are only 2 services with location set to predefined in panorama UI
        self.predefinedServiceObjects = self.predefined.service_objects
        #self.predefinedServiceGroups = self.predefined.service_groups

        self.deviceGroupRules = {}
        self.vlanData = {}

        self.collectDeviceGroupRules()
        self.collectVlanData()

    def collectDeviceGroupRules(self):
        """
        Refresh rules for each device group
        """
        for dg in self.deviceGroups:
            #logging.info(f"Retrieving Device Group '{dg.name} Rules")
            self.deviceGroupRules[dg.name] = self.fetchAllPrerulebaseRules(dg)

    def fetchAllPrerulebaseRules(self, deviceGroup):
        """
        Return a dictionary of rule types for the given device group.
        Note: Some rule types (QoS, DoS, etc.) are not available in panos.policies.
        """
        ruleTypes = [
            SecurityRule,
            NatRule,
            ApplicationOverride,
            PolicyBasedForwarding,
            DecryptionRule,
            AuthenticationRule
        ]

        #define prerulebase per device group
        prerulebase = deviceGroup.find(PreRulebase)
        if prerulebase is None:
            prerulebase = PreRulebase()
            deviceGroup.add(prerulebase)
        allRules = {}
        #for each ruletype in devices prerulebase
        for ruleType in ruleTypes:
            ruleName = ruleType.__name__
            #refresh the ruletypes prerulebase
            rules = ruleType.refreshall(prerulebase)
            #add an entry to allRules that has ruleType.name as key, with refresshed rules as values
            allRules[ruleName] = rules
        return allRules

    def collectVlanData(self):
        """
        For every template (and its vsys), grab associated zones and VLAN mappings
        Using aggregate interfaces and their subinterfaces
        """
        for template in self.templates:
            vsysList = template.findall(Vsys)
            for vsys in vsysList:
                zones = vsys.findall(Zone)
                aggInterfaces = template.findall(AggregateInterface)
                for aggInterface in aggInterfaces:
                    subInterface = self.getChildrenOfAggInterface(aggInterface)
                    vlanMap = self.getAddressForVLANS(subInterface)

                    #TODO:Better way to store them. Dont think this key will work
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
    def getAddressForVLANS(subinterfaceList):
        """
        Create a mapping of VLAN numbers to their associated IP ranges.
        Assumes the subinterface name format is: <name>.<vlan_number>
        """
        interfaceMap = {}
        for subinterface in subinterfaceList:
            try:
                vlanNum = subinterface.name.split(".")[1]
                interfaceMap[vlanNum] = subinterface.ip
            except IndexError:
                logging.error(f"Error parsing VLAN number from subinterface name: {subinterface.name}")
        return interfaceMap

    @staticmethod
    def ipInCidr(ip, cidr):
        """
        Check if an IP address is within a given CIDR range
        """
        try:
            temp = cidr.strip("'[]")
            resultIP = ipaddress.ip_address(ip) in ipaddress.ip_network(temp, strict = False)
            return resultIP
        except ValueError:
            return False

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
        Given a VLAN number and a list of zones, correlate the VLAN to a zone.
        """
        #Issue with this is that zones are not how you get the sub interfaces, templates are
        for zone in zones:
            zoneSubinterfaces = zone.interface
            for interface in zoneSubinterfaces:
                try:
                    if "." in interface:
                        interfaceVlan = interface.split(".")[1]
                        if interfaceVlan == vlanNum:
                            return zone.name
                except IndexError:
                    logging.error(f"Error parsing VLAN number from interface name: {interface}")
                    continue
        return None

    def correlateAddressToAddressGroup(self, addressObject):
        """
        Given an address object, try to correlate it to an address group
        """
        addressGroupList = []
        for addressGroup in self.addressGroups:
            #if address group is comprised of static values (as far as I can tell so far, all are)
            if hasattr(addressGroup, "static_value"):
                #if name or value of any address object in the group matches the address object
                if any(addressObject.name == a or addressObject.value == a for a in addressGroup.static_value):
                    addressGroupList.append(addressGroup.name)
        if len(addressGroupList) != 0:
            return addressGroupList
        return None

    def correlateIP(self, ip):
        """
        Given an IP address (string), find its associated AddressObject,
        VLAN, Zone, and AddressGroup.
        """
        #find matching addressObject for the given IP
        matchedObject = None
        for obj in self.addressObjects:
            if obj.value == ip:
                matchedObject = obj
                break
        #matchedObject = next((obj for obj in self.addressObjects if obj.value == ip), None)
        if not matchedObject:
            logging.error(f"No AddressObject found for IP: {ip}")
            return None
        
        correlationResult = {
            "ip": ip,
            "addressObject": matchedObject.name,
            "vlan": None,
            "zone": None,
            "addressGroup": None,
            "matchingRules": []
            #"applications": None,
            #"services": None
        }


    def correlateAddressObjectName(self, addressObjectName):
        """
        Given an address object name (string), find its associated AddressObject,
        VLAN, Zone, and AddressGroup.
        """
        #find matching addressObject for the given IP
        matchedObject = None
        for obj in self.addressObjects:
            if obj.name == addressObjectName:
                matchedObject = obj
                break
        if not matchedObject:
            logging.error(f"No AddressObject found for name: {addressObjectName}")
            return None
        
        correlationResult = {
            "ip": matchedObject.value,
            "addressObject": addressObjectName,
            "vlan": None,
            "zone": None,
            "addressGroup": None,
            "matchingRules": []
            #"applications": None,
            #"services": None
        }
        #check each vlanData bucket until a matching VLAN is found
        for key, data in self.vlanData.items():
            vlanMap = data.get("vlanMap", {})
            zones = data.get("zones", [])
            vlanNum = self.correlateAddressToVlan(matchedObject, vlanMap)
            if vlanNum:
                correlationResult["vlan"] = vlanNum
                zoneName = self.correlateVlanToZone(vlanNum, zones)
                correlationResult["zone"] = zoneName
                break #stop searching once a match is found

        #Correlate the AddressObject to an AddressGroup
        correlationResult["addressGroup"] = self.correlateAddressToAddressGroup(matchedObject)

        return correlationResult

    # --- Correlating Objects Logic Ends Here ---
    # --- !!! Rule Lookup Methods Start Here !!! ---

    def correlateInput(self, inputValue):
        """
        Determine the type of input and perform correlation.
        Currently, assumes inputValue is an IP address.
        TODO: This is where you will parse the users query and figure out what to search by (IP, name, range, group, vlan, zone, etc. )
        """
        #use regex to parse which input is most likely?
        try:
            correlationResult = self.correlateAddressObjectName(inputValue)
        except ValueError:
            logging.error("Input value is not a valid IP address: %s", inputValue)
            return None
        return correlationResult

    def correlateApplications(self, correlationResult):
        """
        Correlate applications to the input.
        TODO: Implement application correlation logic (e.g., based on UDP/TCP ports).
        """
        correlationResult["applications"] = [] 
        return correlationResult

    def correlateServices(self, correlationResult):
        """
        Correlate services to the input.
        TODO: Implement service correlation logic (e.g., based on UDP/TCP ports).
        """
        correlationResult["services"] = []  # Placeholder for matched services.
        return correlationResult

    def ruleImpactsCorrelation(self, rule, correlationResult):
        """
        Check if a given rule impacts the input based on the correlation result.
        This example checks if the address object or address group appears in the rule's source or destination.
        Extend with VLAN, zone, application, or service checks as needed.
        """

        #Feels like a very clunky method... any improvements?
        if correlationResult["addressObject"]:
            if correlationResult["addressObject"] in getattr(rule, "source", []):
                return True
            if correlationResult["addressObject"] in getattr(rule, "destination", []):
                return True
        if correlationResult["vlan"]:
            if correlationResult["vlan"] in getattr(rule, "source", []):
                return True
            if correlationResult["vlan"] in getattr(rule, "destination", []):
                return True
        if correlationResult["zone"]:
            if correlationResult["zone"] in getattr(rule, "fromzone", []):
                return True
            if correlationResult["zone"] in getattr(rule, "tozone", []):
                return True
        if correlationResult["addressGroup"]:
            #can be apart of multiple groups, so check if any of the address groups match
            for addressGroup in correlationResult["addressGroup"]:
                if addressGroup in getattr(rule, "source", []):
                    return True
                if addressGroup in getattr(rule, "destination", []):
                    return True
        # TODO: Add additional checks for applications, and services.
        return False

    def findMatchingRules(self, correlationResult):
        """
        Iterate through device group rules and return a list of rules
        that match the correlation result.
        """
        matchingRules = []
        for dgName, ruleTypes in self.deviceGroupRules.items():
            for ruleTypeName, rules in ruleTypes.items():
                for rule in rules:
                    #iterates through all rules, checks if they impact the query or any object the 
                    #query is associated with
                    if self.ruleImpactsCorrelation(rule, correlationResult):
                        matchingRules.append({
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
        return matchingRules

    def fullCorrelationLookup(self, inputValue):
        """
        High-level method:
         1. Correlate the input to known objects.
         2. (Optionally) correlate applications and services.
         3. Find and return all matching rules.
        """
        correlationResult = self.correlateInput(inputValue)
        if not correlationResult:
            return None
        correlationResult = self.correlateApplications(correlationResult)
        correlationResult = self.correlateServices(correlationResult)
        correlationResult["matchingRules"] = self.findMatchingRules(correlationResult)
        return correlationResult

    # --- Basic Rule Lookup Methods End Here ---
    # --- !!! Lookup Methods Based on Different Input Types Start Here !!! ---

    def lookupRulesBySubnet(self, subnet):
        """
        Lookup rules that apply to the given subnet.
        TODO: Implement logic to match rules based on subnet overlap.
        """
        correlationResult = {
            "ip": subnet,
            "addressObject": None,
            "vlan": None,
            "zone": None,
            "addressGroup": None,
            "applications": None,
            "services": None,
            "matchingRules": []
        }
        # Extend this by checking if the subnet overlaps with any address object.
        correlationResult["matchingRules"] = self.findMatchingRules(correlationResult)
        return correlationResult

    def lookupRulesByApplication(self, applicationName):
        """
        Lookup rules that reference the given application.
        TODO: Implement logic to match rules by application.
        """
        correlationResult = {
            "ip": None,
            "addressObject": None,
            "vlan": None,
            "zone": None,
            "addressGroup": None,
            "applications": [applicationName],
            "services": None,
            "matchingRules": []
        }
        correlationResult["matchingRules"] = self.findMatchingRules(correlationResult)
        return correlationResult

    def lookupRulesByZone(self, zone):
        """
        Lookup rules that apply to the given zone.
        """
        #Since zones do not have a parent "bucket" aside from maybe a template, could I just return the 
        #rules that impact that zone?
        #Tested 04.01.2025. Seems to return nearly all rules applied to a zone. Counted a difference of 10 
        #when manually checking. Have a feeling it has to do with predefined rules? Try to validate 
        #where the descrepancy is coming from.
        correlationResult = {
            "ip": None,
            "addressObject": None,
            "vlan": None,
            "zone": zone,
            "addressGroup": None,
            "applications": None,
            "services": None,
            "matchingRules": []
        }
        correlationResult["matchingRules"] = self.findMatchingRules(correlationResult)
        return correlationResult
    
    def lookupRulesByAddressGroup(self, addressGroupName):
        """
        Lookup rules that apply to the given address group.
        TODO: Return objects encapsulated by the group. 
        TODO: Handle nested groups. If a group is part of a parent group, the parent groups rules impact it as well 
        """
        correlationResult = {
            "ip": None,
            "addressObject": None,
            "vlan": None,
            "zone": None,
            "addressGroup": addressGroupName,
            "applications": None,
            "services": None,
            "matchingRules": []
        }
        correlationResult["matchingRules"] = self.findMatchingRules(correlationResult)
        return correlationResult

    # --- Lookup Methods Based on Different Input Types End Here ---

def testMethods(panData):
    """
    Test function to verify limited API calls and functionality.
    Example: Correlate a known IP and lookup matching rules.
    """
    testIP = "CSHOST-alpine"  # Replace with a valid IP for testing.
    result = panData.fullCorrelationLookup(testIP)
    if result:
        logging.info("Test correlation result for IP %s: %s", testIP, result)
    else:
        logging.error("No correlation result found for IP: %s", testIP)

def testZoneLookup(panData):
    """
    Test function to verify zone lookup functionality.
    Example: Lookup rules based on a known zone.
    """
    testZone = "" 
    result = panData.lookupRulesByZone(testZone)
    if result:
        logging.info("Test correlation result for zone %s: %s", testZone, result)
        print(f"Rules Found: {len(result['matchingRules'])}")
    else:
        logging.error("No correlation result found for zone: %s", testZone)

def main():
    #Address Objects are missing 11 total objects, because they are held in a different location
    #than the rest of them. A couple in IC-Perimeter and the rest in IC-Datacenter.
    #TODO: Find out how to access the objects in these non-default locations

    load_dotenv()
    apiKey = os.environ.get('API_KEY')
    panAddress = os.environ.get('PAN_ADDRESS')

    logging.basicConfig(level=logging.DEBUG)

    pano = Panorama(panAddress, api_key=apiKey)
    logging.info("Connected to Panorama at %s", pano.hostname)
    
    #Get managed devices
    logging.info("Refreshing Managed Devices...")
    devices = pano.refresh_devices()    
    logging.info("Found %d Managed Devices", len(devices))

    #build PanoramaData object
    panData = PanoramaData(pano)

    testMethods(panData)

if __name__ == "__main__":
    main()