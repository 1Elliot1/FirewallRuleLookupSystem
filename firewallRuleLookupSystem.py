import logging
from panos.panorama import Panorama, DeviceGroup, Template
from panos.firewall import Firewall
from panos.policies import PreRulebase, SecurityRule, NatRule, ApplicationOverride, PolicyBasedForwarding, DecryptionRule, AuthenticationRule
from panos.network import Vlan, Zone, EthernetInterface, AggregateInterface, Layer3Subinterface, Interface
from panos.device import Vsys
from panos.objects import AddressGroup, AddressObject, ServiceObject, ServiceGroup, ApplicationGroup, ApplicationObject, ApplicationContainer
from panos.predefined import Predefined
from dotenv import load_dotenv
import json
import pprint
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

        #self.correlationMatrix = self.buildCorrelationMatrix()
        self.ruleMatrix = self.buildRuleMatrix()
        temp = self.serviceObjects[0]
        print(f"Service Object: {temp.name}, {temp.protocol}, {temp.source_port}, {temp.destination_port}")
        #temp2 = self.predefinedServiceObjects[0]
        #print(f"Predefined Service Object: {temp2.name}, {temp2.protocol}, {temp2.source_port}, {temp2.destination_port}")
        # print("\n1:\n")
        # print(self.predefinedServiceObjects)
        # print("\n2:\n ***")
        # print("\n3:\n ****")
        # print(self.predefinedObjectContainers)
        # print("\n4:\n")
        # print(self.serviceGroups)
        # print("\n5:\n")
        # print(self.applicationContainers)
        # print("\n6:\n")
        # print(self.applicationGroup )
        # print("\n7:\n")
        # print(self.applicationObject)
        print(f"{self.predefinedApplicationObjects['oracle'].name}: {self.predefinedApplicationObjects['oracle'].default_port}, {self.predefinedApplicationObjects['oracle'].default_ip_protocol}, {self.predefinedApplicationObjects['oracle'].category}, {self.predefinedApplicationObjects['oracle'].subcategory}, {self.predefinedApplicationObjects['oracle'].technology}")
        print(f"{self.predefinedApplicationObjects['active-directory-base'].name}: {self.predefinedApplicationObjects['active-directory-base'].default_port}, {self.predefinedApplicationObjects['active-directory-base'].default_ip_protocol}, {self.predefinedApplicationObjects['active-directory-base'].category}, {self.predefinedApplicationObjects['active-directory-base'].subcategory}, {self.predefinedApplicationObjects['active-directory-base'].technology}")

        
        #TODO: When you come back, find out how to access the correct attributes for services, predef services, service groups, apps, predef apps, app groups, etc. to fill in the entries "protocol", "port", "app name", "service name", and maybe "default port" for each item in any of those objects

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
        Check if an IP address or a smaller CIDR range is within a given CIDR range
or equivalent to it.
        """
        try:
            # Clean the CIDR input
            cidrCleaned = cidr.strip("'[]")
            network = ipaddress.ip_network(cidrCleaned, strict=False)

            #catch for networks that are 0.0.0.0/0
            if network.prefixlen == 0:
                return False
            # Check if the input is a single IP or a CIDR range
            #Treat /32 as a subnet still due to how ipaddress library works
            if '/' in ip:
                # Input is a CIDR range
                inputNetwork = ipaddress.ip_network(ip, strict=False)
                if inputNetwork.version != network.version:
                    return False
                # Check if the input network is a subnet of the given CIDR

                return inputNetwork.subnet_of(network)
            else:
                # Input is a single IP
                ipObj = ipaddress.ip_address(ip)   
                #Catch if IP versions of the two inputs are differt, as IpAddress library   
                if ipObj.version != network.version:
                    return False       
            # Check if the IP is within the CIDR or equivalent to the network address
            isWithin = ipObj in network
            isEquivalent = ipObj == network.network_address
            return isWithin or isEquivalent
        except ValueError as e:
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
        directGroups = []
        for addressGroup in self.addressGroups:
            #if address group is comprised of static values (as far as I can tell so far, all are)
            if hasattr(addressGroup, "static_value"):
                #if name or value of any address object in the group matches the address object
                if any(addressObject.name == a or addressObject.value == a for a in addressGroup.static_value):
                    directGroups.append(addressGroup.name)
        if not directGroups:
            return None
        
        #Handling IP objects that are only explicitly mentioned in a nested group:
        fullGroupList = set(directGroups)
        for group in directGroups:
            parentGroups = self.resolveNestedAddressGroups(group)
            fullGroupList.update(parentGroups)

        return list(fullGroupList)

    def correlateIP(self, ip):
        """
        Given an IP address (string), find its associated AddressObject,
        VLAN, Zone, and AddressGroup.
        """
        matchedObjects = self.correlateAddressObjects(ip)
        if not matchedObjects:
            logging.error(f"No AddressObject found for IP: {ip}")
            return None
        
        correlationResult = {
            "ip": ip,
            "addressObject": [obj.name for obj in matchedObjects],
            "vlan": None,
            "zone": None,
            "addressGroup": None,
            "matchingRules": []
            #"applications": None,
            #"services": None
        }
        #MAD INNEFICIENT WOWIEEEE
        for obj in matchedObjects:
            for key, data in self.vlanData.items():
                vlanMap = data.get("vlanMap", {})
                zones = data.get("zones", [])
                vlanNum = self.correlateAddressToVlan(obj, vlanMap)
                if vlanNum:
                    correlationResult["vlan"] = vlanNum
                    correlationResult["zone"] = self.correlateVlanToZone(vlanNum, zones)
                    break
            if correlationResult["vlan"]:
                break
        
        addressGroups = set()
        for obj in matchedObjects:
            groups = self.correlateAddressToAddressGroup(obj)
            if groups:
                addressGroups.update(groups)    

        correlationResult["addressGroup"] = list(addressGroups) if addressGroups else None
        return correlationResult

    def correlateAddressObjectName(self, addressObjectName):
        """
        Given an address object name (string), find its associated AddressObject,
        VLAN, Zone, and AddressGroup.
        """
        #find matching addressObject for the given IP
        matchedObject = None
        for obj in self.addressObjects:
            #Find exact match on address object name
            if obj.name == addressObjectName:
                matchedObject = obj
                break
        if not matchedObject:
            logging.error(f"No AddressObject found for name: {addressObjectName}")
            return None
        #How to check all nested objects for a match when not based off ip? Take the IP of the found object and run the correlateIP type functions?
        
        correlationResult = {
            #Check for nested address objects once an IP is matched
            "ip": self.correlateAddressObjects(matchedObject.value),
            "addressObject": [addressObjectName],
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
            correlationResult = self.correlateIP(inputValue)
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
            for addr in correlationResult["addressObject"]:
                if addr in getattr(rule, "source", []):
                    return True
                if addr in getattr(rule, "destination", []):
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

    def correlateAddressObjects(self, ip):
        """
        Return all address objects that contain the inut IP
        This includes any exact matches and broader CIDR ranges
        """
    
        matchingObjects = []
        for addr in self.addressObjects:
            if addr.value == ip or self.ipInCidr(ip, addr.value):
                matchingObjects.append(addr)
        if not matchingObjects:
            logging.error(f"No AddressObject found for IP: {ip}")
            return None

        
        return matchingObjects

    def fullCorrelationLookup(self, inputValue):
        #TODO: (First double check if the case:) Remove-- Un-needed, searches happen once data is exported, eventually
        #All correlation should now occur in the exported files. 
        """
        High-level method:
         1. Correlate the input to known objects.
         2. (Optionally) correlate applications and services.
         3. Find and return all matching rules.
        """
        correlationResult = self.correlateInput(inputValue)
        if not correlationResult:
            return None
        # correlationResult = self.correlateApplications(correlationResult)
        # correlationResult = self.correlateServices(correlationResult)
        correlationResult["matchingRules"] = self.findMatchingRules(correlationResult)
        return correlationResult

    # --- Basic Rule Lookup Methods End Here ---
    # --- !!! Lookup Methods Based on Different Input Types Start Here !!! ---

    def lookupRulesBySubnet(self, subnet):
        #TODO: (First double check if the case:) Remove-- Un-needed, searches happen once data is exported, eventually
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
        #TODO: (First double check if the case:) Remove-- Un-needed, searches happen once data is exported, eventually
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
        #TODO: (First double check if the case:) Remove-- Un-needed, searches happen once data is exported, eventually
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
    
    def resolveNestedAddressGroups(self, addressGroupName, seen = None):
        """
        Recursively resolve nested address groups.
        """
        if seen is None:
            seen = set()
        parentGroups = set()
        for group in self.addressGroups:
            if hasattr(group, "static_value"):
                if addressGroupName in group.static_value and group.name not in seen:
                    seen.add(group.name)
                    parentGroups.add(group.name)
                    # Recursively resolve nested groups
                    parentGroups.update(self.resolveNestedAddressGroups(group.name, seen))
        return list(parentGroups)

    def lookupRulesByAddressGroup(self, addressGroupName):
        #TODO: (First double check if the case:) Remove-- Un-needed, searches happen once data is exported, eventually

        """
        Lookup rules that apply to the given address group.
        """
        resolvedGroups = {addressGroupName}
        parentGroups = self.resolveNestedAddressGroups(addressGroupName)
        resolvedGroups.update(parentGroups)

        correlationResult = {
            "ip": None,
            "addressObject": None,
            "vlan": None,
            "zone": None,
            "addressGroup": list(resolvedGroups),
            "applications": None,
            "services": None,
            "matchingRules": []
        }
        correlationResult["matchingRules"] = self.findMatchingRules(correlationResult)
        return correlationResult

    def lookupRulesByVlan(self, vlanNum):
        #TODO: (First double check if the case:) Remove-- Un-needed, searches happen once data is exported, eventually
        """
        Lookup rules that apply to the given VLAN number
        Method uses the vlanData mapping to correlate VLAN to its CIDR range and associated zones,
        then builds a correlation result for the rule matching. 
        """
        correlationResult = {
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
                correlationResult["zone"] = self.correlateVlanToZone(vlanNum, zones)
                #break to avoid unnecessary iterations once a match is found
                break
        correlationResult["matchingRules"] = self.findMatchingRules(correlationResult)
        return correlationResult

    def lookupRulesByCIDR(self, CIDR):
        #TODO: (First double check if the case:) Remove-- Un-needed, searches happen once data is exported, eventually
        """
        Lookup rules that apply to the given CIDR range.
        This method checks if provided CIDR overlaps with any of the VLAN CIDR ranges or address objects
        then builds a correlation result accordingly
        """
        network = ipaddress.ip_network(CIDR, strict=False)
        correlationResult = {
            "ip": CIDR,
            "addressObject": [],
            "vlan": None,
            "zone": None,
            "addressGroup": None,
            "applications": None,
            "services": None,
            "matchingRules": []
        }
        #Alter to return rules for any address object that overlaps with the CIDR range
        for key, data in self.vlanData.items():
            vlanMap = data.get("vlanMap", {})
            zones = data.get("zones", [])
            for vlanNum, vlanCIDR in vlanMap.items():
                vlanNetwork = ipaddress.ip_network(str(vlanCIDR), strict=False)
                if network.overlaps(vlanNetwork):
                    correlationResult["vlan"] = vlanNum
                    correlationResult["zone"] = self.correlateVlanToZone(vlanNum, zones)
                    break
            if correlationResult["vlan"]:
                break
        
        #Check individual address objects for overlap with the CIDR range
        for addr in self.addressObjects:
            try:
                addrIP = ipaddress.ip_network(addr.value.split('/')[0])
                if addrIP in network:
                    correlationResult["addressObject"].append(addr.name)
            except ValueError:
                logging.error(f"Invalid address object value: {addr.value}")
        correlationResult["matchingRules"] = self.findMatchingRules(correlationResult)
        return correlationResult
    
    def buildApplicationPortMap(self):
        #TODO: Want to implement a function that takes app and service data, parses through it correctly, so we can 
        #eventually build a correlation matrix of all apps and services to their ports, and vice versa-- or some 
        #kind of solution that will allow us to search for a port and find all apps and services that apply to it
        #so that can be used to search for rules that apply to those protocols/ports/apps/services

        from collections import defaultdict

        applicationToPorts = {}
        portToApplications = defaultdict(list)

        allApps = self.applicationObject + list(self.predefinedApplicationObjects.values())
        #Not the correct implementation, just keeping it here so you can see some of how the 
        #api data is formatted. 
        for app in allApps:
            appName = app.name
            ports = {'tcp': [], 'udp': []}
            if app.default_port:
                for port in app.default_port:
                #TODO: Handle port ranges (denoted with a dash)
                    if "/" in port:
                        subCollection = []
                        proto = port.split("/")[0]
                        portNum = port.split("/")[1]
                        if "," in port:
                            subCollection = portNum.split(",")

                    if proto == "tcp":
                        if subCollection:
                            ports['tcp'].extend(subCollection)
                        else:
                            ports['tcp'].append(portNum)
                    elif proto == "udp":
                        if subCollection:
                            ports['udp'].extend(subCollection)
                        else:
                            ports['udp'].append(portNum)
                
                applicationToPorts[appName] = ports


        self.applicationToPorts = applicationToPorts
        self.portToApplications = dict(portToApplications)

    def buildCorrelationMatrix(self):
        """
        Build a comprehensive mapping of all objects (address objects, VLANs, zones, etc.) 
        to their related objects, for visualization or export purposes.
        Returns a list of dicts, each dict representing on object and its relationships
        """
        correlationMatrix = []

        vlanCache = {}
        # --- Address Objects --- 
        for addr in self.addressObjects:
            entry = {
                "type": "AddressObject",
                "name": addr.name,
                "value": addr.value,
                "zone": None,
                "vlan": None,
                "parentGroups": self.correlateAddressToAddressGroup(addr) or [],
                "parentAddressObjects": self.correlateAddressObjects(addr.value) or [],
            }
            #change parentAddressObjects to simply their names for json output:
            entry["parentAddressObjects"] = [obj.name for obj in entry["parentAddressObjects"]]
            #get VLAN/Zone from correlation
            for key, data in self.vlanData.items():
                vlanMap = data.get("vlanMap", {})
                zones = data.get("zones", [])
                vlanNum = self.correlateAddressToVlan(addr, vlanMap)
                if vlanNum:
                    vlanCache.setdefault(vlanNum, []).append(addr.name)
                    entry["vlan"] = vlanNum
                    entry["zone"] = self.correlateVlanToZone(vlanNum, zones)
                    break
            
            correlationMatrix.append(entry)

        # --- Address Groups --- 
        for group in self.addressGroups:
            entry = {
                "type": "AddressGroup",
                "name": group.name,
                "members": group.static_value if hasattr(group, "static_value") else [],
                "parentGroups": self.resolveNestedAddressGroups(group.name),
            }
            correlationMatrix.append(entry)

        # --- VLANs ---
        for templateKey, data in self.vlanData.items():
            vlanMap = data.get("vlanMap", {})
            zones = data.get("zones", [])
            for vlanNum, cidr in vlanMap.items():
                entry = {
                    "type": "VLAN",
                    "name": vlanNum,
                    "cidr": cidr,
                    "zone": self.correlateVlanToZone(vlanNum, zones),
                    "template": templateKey,
                    "childAddressObjects": vlanCache.get(vlanNum, []),
                }
                correlationMatrix.append(entry)

        # --- Zones ---
        zoneSet = set()
        for data in self.vlanData.values():
            for zone in data.get("zones", []):
                zoneSet.add(zone.name)
        
        for zoneName in zoneSet:
            entry = {
                "type": "Zone",
                "name": zoneName
            }
            correlationMatrix.append(entry)

        return correlationMatrix
    
    def buildRuleMatrix(self):
        ruleMatrix = []
        for dg in self.deviceGroupRules:
            print(dg)
            for ruleType in self.deviceGroupRules[dg]:
                print(ruleType)
                for rule in self.deviceGroupRules[dg][ruleType]:
                    entry = {
                        "type": ruleType,
                        "name": getattr(rule, "name", None),
                        "deviceGroup": dg,
                        "source": getattr(rule, "source", None),
                        "destination": getattr(rule, "destination", None),
                        "action": getattr(rule, "action", None),
                        "service": getattr(rule, "service", None),
                        "application": getattr(rule, "application", None),
                        "fromzone": getattr(rule, "fromzone", None),
                        "tozone": getattr(rule, "tozone", None),
                        "sourceDevices": getattr(rule, "source_devices", None),
                        "destinationDevices": getattr(rule, "destination_devices", None),
                        "description": getattr(rule, "description", None),
                    }
                    ruleMatrix.append(entry)

        return ruleMatrix
    
    # --- Export Utility Methods --- 
    def exportAllAppServiceObjectsToFile(self):
        #TODO: implement a solution that eventually will allow user to search for a specific protocol/port and return all apps and services that apply to it (so the rules that apply to those services and apps can then be correlated to that)
        #TODO: Once implemented, implement this method to export the data to a similarly formatted file as the others 
        pass

    def exportAllVlansToFile(self):
        #TODO: Take the current vlanData collection and format it with a build function, then export it to a file here similarlly formatted as the others below
        pass
    
    def exportAllRulesToFile(self):
        jsonObj = json.dumps(self.ruleMatrix, indent=4)
        with open("deviceGroupRules.json", "w") as outfile:
            outfile.write(jsonObj)

    
    def exportCorrelationMatrixToFile(self, filename="correlationMatrix.json"):
        jsonObj = json.dumps(self.correlationMatrix, indent=4)
        with open(filename, "w") as outfile:
            outfile.write(jsonObj)

    # --- Lookup Methods Based on Different Input Types End Here ---

def testMethods(panData):
    """
    Test function to verify limited API calls and functionality.
    Example: Correlate a known IP and lookup matching rules.
    """
    testIP = ""
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
    result = panData.lookupRulesByVlan(testZone)
    if result:
        logging.info("Test correlation result for VLAN %s: %s", testZone, result)
        print(f"Rules Found: {len(result['matchingRules'])}")
    else:
        logging.error("No correlation result found for zone: %s", testZone)

def testApplicationPortMapping(panData):
    panData.buildApplicationPortMap()

    print("Ports for 'web-browsing':")
    print(panData.applicationToPorts.get('web-browsing', "Not Found"))

    print("Applications for port 'tcp/443':")
    print(panData.portToApplications.get('tcp/443', "Not Found"))

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
    panData.exportAllRulesToFile()

if __name__ == "__main__":
    main()