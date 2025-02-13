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

def main():
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
    #get all address objects
    addressObject = AddressObject.refreshall(pano)
    #get all address groups
    addressGroup = AddressGroup.refreshall(pano)
    fetchDeviceGroupInfo(pano)

    #Address Objects are missing 11 total objects, because they are held in a different location
    #than the rest of them. A couple in IC-Perimeter and the rest in IC-Datacenter.
    #TODO: Find out how to access the objects in these non-default locations



def fetchDeviceGroupInfo(pano):
    #Find and refresh all dev groups
    logging.info("Retrieving and Refreshing Device Groups...")
    deviceGroups = DeviceGroup.refreshall(pano)
    ruleMap = {}
    for dg in deviceGroups: 
        logging.info(f"Retrieving Device Group '{dg.name}' Rules")
        ruleMap[dg.name] = fetchAllPreRulebaseRules(dg)
    


def fetchTemplateInfo(pano):
    logging.info("Retrieving and Refreshing Templates")
    #get all templates
    templates = Template.refreshall(pano)
    print(templates)

    for template in templates:
        #Get all vsys' per template
        vsysList = template.findall(Vsys)
        zones = []
        for vsys in vsysList:
            #Find all zones per vsys
            zones = vsys.findall(Zone)
            if zones:
                logging.info(f"     {len(zones)} Zones Found For Template '{template}, Vsys '{vsys}'")
            else:
                logging.info(f"No Zones found for template '{template}', Vsys '{vsys}'")

        #Find all interfaces. Currently aggInterfaces show up as the parent agg
        ethInterfaces = template.findall(EthernetInterface)
        aggInterfaces = template.findall(AggregateInterface)
        if ethInterfaces:
            logging.info(f"     {len(ethInterfaces)} Ethernet Interfaces Found for Template '{template}', Vsys '{vsys}'")
        else:
            logging.info(f"No Ethernet Interfaces Found for Template {template}, Vsys '{vsys}'")
        if aggInterfaces:
            logging.info(f"     {len(aggInterfaces)} Aggregate Interfaces Found for Template '{template}', Vsys '{vsys}'")
        else:
            logging.info(f"No Aggregate Interfaces Found for Template '{template}', Vsys '{vsys}'")
        for aggInterface in aggInterfaces:
            subInterfaces = getChildrenOfAggInterface(aggInterface)
            vlanMap = getAddressForVLANS(subInterfaces)
        #Do this for every addressObject 
            addressObjectVlanNum = correlateAddressToVLAN(addressObject, vlanMap)
            addressObjectZone = correlateVLANToZone(zones, addressObjectVlanNum)
            addressObjectAddressGroup = correlateAddressToAddressGroup(addressObject, addressGroups)
            print(f"Address Object: {addressObject.name} is in VLAN {addressObjectVlanNum}, Zone {addressObjectZone}, and Address Group {addressObjectAddressGroup}")

def fetchAllPreRulebaseRules(deviceGroup):
    #Still cannot get QoS, DoS, NetworkPacketBroker, TunnelInspection, or SD-WAN rules (not in panos.policies)
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

#TODO: Logic for correlating rules to their respective zones, interfaces, and address objects
#now have a dictionary of all rules per device group, need to correlate them next

#TODO get the VLAN, AddressGroup, Zone, and Interface for each addressObject
#Correlating methods below
def ipInCidr(ip, cidr):
    return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)

def correlateVLANToZone(zoneList, addressVlan):
    for zone in zoneList:
        zoneVlans = zone.findall(Interface)
        for zoneVlan in zoneVlans:
            zoneVlanNum = zoneVlan.name.split(".")[1]
            if zoneVlanNum == addressVlan:
                return zone.name
    return "NA"

def correlateAddressToVLAN(addressObject, vlanDict):
    #check if ip is within cidr range of the VLAN IP. (Returned by the getAddressForVLANS method)
    for vlanNum, vlanIP in vlanDict.items():
        if ipInCidr(addressObject.value, vlanIP):
            return vlanNum
    return "NA"

def correlateAddressToAddressGroup(addressObject, addressGroups):
    #Unsure if the addressGroup ip is a name or ip
    for addressGroup in addressGroups:
        for address in addressGroup.static_value:
            if addressObject.name == address or addressObject.value == address:
                return addressGroup.name
    return "NA"

def getChildrenOfAggInterface(aggInterface):
    #TODO:Be sure to eventually account for other interface types (Layer2, virtual-wire, tap, ha)
    subInterfaces = aggInterface.findall(Layer3Subinterface)
    return subInterfaces

def getAddressForVLANS(subinterfaceList):
    interfaceMap = {}
    for subinterface in subinterfaceList:
        #grab the second half of the interface name, which is the VLANs number
        vlanNum = subinterface.name.split(".")[1]
        vlanIP = subinterface.ip
        interfaceMap[vlanNum] = vlanIP
    return interfaceMap

main()
