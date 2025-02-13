import logging
from panos.panorama import Panorama, DeviceGroup, Template
from panos.firewall import Firewall
from panos.policies import PreRulebase, SecurityRule, NatRule, ApplicationOverride, PolicyBasedForwarding, DecryptionRule, AuthenticationRule
from panos.network import Vlan, Zone, EthernetInterface, AggregateInterface, Layer3Subinterface, Interface
from panos.device import Vsys
from panos.objects import AddressGroup, AddressObject
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
        Return a dictionary of rule types for the given device group
        """
        #Still cannot get QoS, DoS, NetworkPacketBroker, -TunnelInspection, or -SD-WAN rules (not in panos.policies)
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
        TODO: currently only supporting Layer3Subinterfaces
        """
        return aggInterface.findall(Layer3Subinterface)

    @staticmethod
    def getAddressForVLANS(subinterfaceList):
        """
        Create mapping of VLAN numbers ot their associated IP ranges
        Assumes that the second half of subinterface name, preceeded by a period is vlan num
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
        Check if an IP address is within a CIDR range
        """
        try:
            temp = cidr.split("'")[1]
            resultIP = ipaddress.ip_address(ip) in ipaddress.ip_network(temp, strict = False)
            return resultIP
        except ValueError:
            return False

    def correlateAddressToVlan(self, addressObject, vlanMap):
        """
        Given an address object and VLAN map (VlanNum -> cidr), return the VLAN number if found
        """
        cleanIp = addressObject.value.split("/")[0]
        for vlanNum, vlanCidr in vlanMap.items():
            if self.ipInCidr(cleanIp, str(vlanCidr)):
                return vlanNum
        return None
    
    @staticmethod
    def correlateVlanToZone(vlanNum, zones):
        """
        Given a VLAN number and a list of zones, try to correlate VLAN to a zone
        TODO: GRAB VLAN NAMES AND INTERFACES CORRECTLY 
        """
        #Issue with this is that zones are not how you get the sub interfaces, templates are
        for zone in zones:
            zoneSubinterfaces = zone.interface
            for interface in zoneSubinterfaces:
                try:
                    interfaceVlan = interface.split(".")[1]
                    if interfaceVlan == vlanNum:
                        return zone.name
                except IndexError:
                    logging.error(f"Error parsing VLAN number from interface name: {interface.name}")
                    continue 
        return None

    def correlateAddressToAddressGroup(self, addressObject):
        """
        Given an address object, try to correlate it to an address group
        """
        for addressGroup in self.addressGroups:
            if hasattr(addressGroup, "static_value"):
                if any(addressObject.name == a or addressObject.value == a for a in addressGroup.static_value):
                    return addressGroup.name
        return None

    def correlateIP(self, ip):
        #TODO: Doesn't seem to be correlating IP Objects together correctly yet. Match on value or name? 
        """
        given an IP address (String), find its associated AddressObject, VLAN, Zone, AddressGroup, and DeviceGroup rules
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
            "addressGroup": None
            #"deviceGroupRules": {} #can be further filtered based on context
        }
#application and application groups
#services and service groups
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
        addressGroup = self.correlateAddressToAddressGroup(matchedObject)
        if addressGroup:
            correlationResult["addressGroup"] = addressGroup
        
        #Device group rules can be refined further
        #For now,including all device group rules as starting point
        #TODO: Figure out what you need to do with that
        #correlationResult["deviceGroupRules"] = self.deviceGroupRules

        return correlationResult


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

    #Test Example:
    testIP = ""
    result = panData.correlateIP(testIP)
    if result:
       logging.info(f"Correlation Result for IP: {testIP}\n{result}")
    else:
       logging.error(f"No correlation result found for IP: {testIP}")

if __name__ == "__main__":
    main()
