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
        self.predefinedServiceGroups = self.predefined.service_groups

        testCont = self.predefined.application_container_objects.get("cisco-spark")
        print("Container Print Out: ", testCont)
        print("Applications Print Out From Container ", str(testCont.applications))

        self.deviceGroupRules = {}
        self.vlanData = {}

        self.collectDeviceGroupRules()
        self.collectVlanData()
        
        self.buildApplicationServicePortMap()
        self.correlationMatrix = self.buildCorrelationMatrix()
        self.ruleMatrix = self.buildRuleMatrix()
        
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

    # --- Correlating Objects Logic Ends Here ---

    def enrichRuleWithPorts(self, apps, services, serviceFieldRaw):
        """
        Resolve all ports a rule allows and annotate with reasoning
        apps and services must be fully resolved (i.e., no groups by calling resolveAppAndServiceGroups)
        serviceFieldRaw is the raw service field is the original rule.service list
        """
        resolvedPorts = set()
        portReasoning = {}

        #handle applicationDefault logic:
        if serviceFieldRaw and len(serviceFieldRaw) == 1 and serviceFieldRaw[0] == "application-default":
            for app in apps:
                #because nested groups are not resolved, they search the applicationToPorts mapping for the parent
                #name-- finding nothing (Since groups are stored as their members)
                #So, need to resolve the group to its members first before this point.
                portMap = self.applicationToPorts.get(app, {})
                if not portMap:
                    print(f"Warning: No port mapping found for application '{app}'")
                for proto, ports in portMap.items():
                    for port in ports:
                        key = f"{proto}/{port}"
                        resolvedPorts.add(key)
                        portReasoning.setdefault(key, []).append(f"{app} (application-default)")

        for service in services:
            if service == "application-default":
                # Skip application-default as it is handled above
                continue

            servicePorts = self.serviceToPorts.get(service, {})
            for proto, ports in servicePorts.items():
                for port in ports:
                    key = f"{proto}/{port}"
                    resolvedPorts.add(key)
                    portReasoning.setdefault(key, []).append(f"{service} (service object)")

        return {
            "resolvedPorts": list(resolvedPorts),
            "portReasoning": portReasoning
        }

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
    
    def resolveApplicationGroup(self, groupName: str, seen: set[str] | None = None) -> list[str]:
        """
        Recursively returns all leaf application names contained in an
        Application Group (handles groups inside groups and containers).
        Cycles are detected by the `seen` set.
        """
        if seen is None:
            seen = set()
        if groupName in seen:
            logging.warning("Cycle detected while expanding application group %s", groupName)
            return []

        # memoisation pays off when thousands of rules reference the same group
        cached = self.expandedAppGroupCache.get(groupName)
        if cached is not None:
            return cached

        grp = self.appGroupByName.get(groupName)
        if not grp:
            # Not a group – treat it as a leaf application name
            return [groupName]

        seen.add(groupName)
        leaves: list[str] = []

        for member in getattr(grp, "value", []):
            # 1.  Another Application Group?
            if member in self.appGroupByName:
                leaves.extend(self.resolveApplicationGroup(member, seen))
            # 2.  Application Container defined by the admin?
            elif member in self.appContainerByName:
                leaves.extend(self.resolveApplicationContainer(member, seen))
            # 3.  Pre-defined container (from Palo Alto content DB)?
            elif member in self.predefContainerByName:
                leaves.extend(self.resolvePredefinedContainer(member))
            else:
                # 4.  Plain application leaf
                leaves.append(member)

        # Cache the fully-expanded list (duplicates removed, order preserved)
        deduped = list(dict.fromkeys(leaves))
        self.expandedAppGroupCache[groupName] = deduped
        return deduped
    
    def resolveServiceGroup(self, groupName, seen=None):
        """
        Recursively resolves service groups to get all service names.
        """
        if seen is None:
            seen = set()
        if groupName in seen:
            return []
        seen.add(groupName)

        for group in self.serviceGroups:
            if group.name == groupName:
                values = getattr(group, "value", [])
                result = []
                for val in values:
                    if val in [g.name for g in self.serviceGroups]:
                        result.extend(self.resolveServiceGroup(val, seen))
                    else:
                        result.append(val)
                return result
        return []

    def resolveApplicationContainer(self, containerName: str,
                                    seen: set[str] | None = None) -> list[str]:
        container = self.appContainerByName.get(containerName)
        if not container:
            return []

        # handle nested containers or groups
        leaves: list[str] = []
        for val in getattr(container, "value", []):
            if val in self.appGroupByName:
                leaves.extend(self.resolveApplicationGroup(val, seen))
            elif val in self.appContainerByName:
                leaves.extend(self.resolveApplicationContainer(val, seen))
            elif val in self.predefContainerByName:
                leaves.extend(self.resolvePredefinedContainer(val))
            else:
                leaves.append(val)
        return leaves
    
    def resolvePredefinedContainer(self, name: str) -> list[str]:
        container = self.predefinedObjectContainers.get(name)
        if container:
            first = getattr(container, "value", None)
            if first:
                return first 

            second = self.containerMembersViaParams(container)
            if second:
                return second

        return self._container_members.get(name, [])
    
    def resolveAppAndServiceGroups(
        self,
        apps: list[str] | None,
        services: list[str] | None,
    ) -> tuple[list[str], list[str]]:
        """
        Flatten *all* application and service references.

        • If an item is an Application Group → expand recursively.
        • If it is an Application Container (admin-defined or predefined) →
        expand to its leaves.
        • Otherwise treat it as an application leaf.
        ('application-default' is kept unchanged because it is not a real
        application name.)

        Returns  (allApps, allServices)  as **deduplicated lists**.
        """

        resolvedApps: set[str] = set()
        resolvedSvcs: set[str] = set()

        # ── Applications ────────────────────────────────────────────────────
        for app in apps or []:
            if app == "application-default":
                # keep sentinel so the caller can detect it later
                resolvedApps.add(app)
                continue
            
            if app in self.leafAppNames:
                resolvedApps.add(app)
            elif app in self.appGroupByName:
                resolvedApps.update(self.resolveApplicationGroup(app))
            elif app in self.appContainerByName:
                resolvedApps.update(self.resolveApplicationContainer(app))
            elif app in self.predefContainerByName:
                resolvedApps.update(self.resolveApplicationContainer(app))
            else:
                resolvedApps.add(app)

        # ── Services ────────────────────────────────────────────────────────
        for svc in services or []:
            if svc in self.serviceGroupByName:
                resolvedSvcs.update(self.resolveServiceGroup(svc))
            else:
                resolvedSvcs.add(svc)

        # Return deterministic order (helps diff / tests)
        return (
            list(dict.fromkeys(resolvedApps)),     # preserves first-seen order
            list(dict.fromkeys(resolvedSvcs)),
        )
    
    def buildApplicationServicePortMap(self):
        """
        Build mappings of: 
        - Applications to their default ports (tcp/udp)
        - Services to their defined ports (tcp/udp)
        - Reverse: protocol/port to all applications/services that use it
        """
        #TODO: Want to implement a function that takes app and service data, parses through it correctly, so we can 
        #eventually build a correlation matrix of all apps and services to their ports, and vice versa-- or some 
        #kind of solution that will allow us to search for a port and find all apps and services that apply to it
        #so that can be used to search for rules that apply to those protocols/ports/apps/services

        from collections import defaultdict

        self.applicationToPorts = {}
        self.serviceToPorts = {}
        portToEntities = defaultdict(lambda: {"applications": [], "services": []})

        # --- Application Objects ---
        allApps = self.applicationObject + list(self.predefinedApplicationObjects.values())
        for app in allApps:
            appName = app.name
            ports = {"tcp": [], "udp": []}

            if hasattr(app, "default_port") and app.default_port:
                for entry in app.default_port:
                    try:
                        proto, portBlob = entry.split("/")
                        proto = proto.lower()
                        for part in portBlob.split(","):
                            ports[proto].append(part.strip())
                            portToEntities[f"{proto}/{part.strip()}"]["applications"].append(appName)
                    except Exception as e:
                        logging.warning(f"Error parsing application port: {entry}, {e}")

            self.applicationToPorts[appName] = ports

        # --- Service Objects ---
        allServices = self.serviceObjects + list(self.predefinedServiceObjects.values())

        for service in allServices:
            #Only handles destination ports for now-- is that correct?
            serviceName = service.name
            protocol = service.protocol.lower() if service.protocol else None
            destPort = service.destination_port if service.destination_port else None

            if protocol and destPort:
                self.serviceToPorts[serviceName] = {protocol: [destPort]}
                portToEntities[f"{protocol}/{destPort}"]["services"].append(serviceName)
        
        self.portToEntities = dict(portToEntities)

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
        """
        Builds a matrix of all rules with consolidated data, including apps/services/ports correlation
        """
        ruleMatrix = []
        for dg in self.deviceGroupRules:
            for ruleType in self.deviceGroupRules[dg]:
                for rule in self.deviceGroupRules[dg][ruleType]:
                    rawApps = getattr(rule, "application", []) or []
                    rawServices = getattr(rule, "service", []) or []

                    #expand all service and application groups into their members: 
                    allApps, allServices = self.resolveAppAndServiceGroups(rawApps, rawServices)

                    enriched = self.enrichRuleWithPorts(allApps, allServices, rawServices)
                    
                    entry = {
                        "type": ruleType,
                        "name": getattr(rule, "name", None),
                        "deviceGroup": dg,
                        "source": getattr(rule, "source", None),
                        "destination": getattr(rule, "destination", None),
                        "fromzone": getattr(rule, "fromzone", None),
                        "tozone": getattr(rule, "tozone", None),
                        "sourceDevices": getattr(rule, "source_devices", None),
                        "destinationDevices": getattr(rule, "destination_devices", None),
                        "action": getattr(rule, "action", None),
                        "service": rawServices,
                        "application": rawApps,
                        "expandedApplications": allApps,
                        "expandedServices": allServices,
                        "resolvedPorts": enriched["resolvedPorts"],
                        "portReasoning": enriched["portReasoning"],
                        "description": getattr(rule, "description", None),
                    }

                    ruleMatrix.append(entry)

        return ruleMatrix
    
    # --- Export Utility Methods --- 
    def exportAllAppServiceObjectsToFile(self):
        #TODO: implement a solution that eventually will allow user to search for a specific protocol/port and return all apps and services that apply to it (so the rules that apply to those services and apps can then be correlated to that)
        #TODO: Once implemented, implement this method to export the data to a similarly formatted file as the others 
        mapping = {
            "applications": self.applicationToPorts,
            "services": self.serviceToPorts,
            "ports": self.portToEntities
        }

        with open("appServiceMapping0.json", "w") as outfile:
            json.dump(mapping, outfile, indent=4)
        logging.info("Exported application/service mapping to appServiceMapping.json")
            

    def exportAllVlansToFile(self):
        #TODO: Take the current vlanData collection and format it with a build function, then export it to a file here similarlly formatted as the others below
        pass
    
    def exportAllRulesToFile(self):
        jsonObj = json.dumps(self.ruleMatrix, indent=4)
        with open("deviceGroupRules0.json", "w") as outfile:
            outfile.write(jsonObj)

    
    def exportCorrelationMatrixToFile(self, filename="correlationMatrix0.json"):
        jsonObj = json.dumps(self.correlationMatrix, indent=4)
        with open(filename, "w") as outfile:
            outfile.write(jsonObj)

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
    panData.exportAllAppServiceObjectsToFile()
    panData.exportCorrelationMatrixToFile()


if __name__ == "__main__":
    main()