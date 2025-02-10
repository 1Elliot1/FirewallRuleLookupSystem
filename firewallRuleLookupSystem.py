import logging
from panos.panorama import Panorama, DeviceGroup, Template
from panos.firewall import Firewall
from panos.policies import PreRulebase, SecurityRule, NatRule, ApplicationOverride, PolicyBasedForwarding, DecryptionRule, AuthenticationRule
from panos.network import Vlan, Zone, EthernetInterface, AggregateInterface
from panos.device import Vsys
from panos.objects import AddressGroup, AddressObject
from dotenv import load_dotenv
import os

def main():
    #TODO: Place API key and IP into secure location later
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



#TODO: Finish implementation and figure out how to get missing rule types included
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
    

main()
