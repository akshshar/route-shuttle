#! /usr/bin/python

import subprocess, ipaddress
from functools import partial
from pyroute2 import IPDB, NetNS
from pyroute2.netlink.rtnl import rt_proto
from socket import AF_INET, AF_INET6
from base import BasePlugin
from rshuttle import logger

RT_TABLE_LOCAL = 255
ROUTE_OIF = 0x10
ROUTE_SINGLEPATH = 0x11
ROUTE_MULTIPATH = 0x12

ROUTE_EVENTS = {'RTM_NEWROUTE': 'add',
                'RTM_DELROUTE' : 'delete',
                'add' : 'RTM_NEWROUTE',
                'delete' : 'RTM_DELROUTE'}

DEFAULT_ROUTE_POLICY = {'proto': {
                                     'bird': {
                                         'allowed': False
                                      },
                                     'boot': {
                                         'allowed': False
                                      },
                                     'dhcp': {
                                         'allowed': False
                                      },
                                     'dnrouted': {
                                         'allowed': False
                                      },
                                     'gated': {
                                         'allowed': False
                                      },
                                     'kernel': {
                                         'allowed': False
                                      },
                                     'mrt': {
                                         'allowed': False
                                      },
                                     'ntk': {
                                         'allowed': False
                                      },
                                     'ra': {
                                         'allowed': False
                                      },
                                     'redirect': {
                                         'allowed': False
                                      },
                                     'static': {
                                         'allowed': False
                                      },
                                     'unspec': {
                                         'allowed': False
                                      },
                                     'xorp': {
                                         'allowed': False
                                      },
                                     'zebra': {
                                         'allowed': False
                                     }
                                 }
                       }

class NetlinkPlugin(BasePlugin):

    def __init__(self, routePolicy=None, netns=None):
        if routePolicy is None:
            self.routePolicy = DEFAULT_ROUTE_POLICY
        else:
            self.routePolicy = routePolicy

        if netns is None:
            netns = 'global-vrf'
        self.ipdb = IPDB(nl=NetNS(netns))
        self.route_events = ROUTE_EVENTS

    def get_route_attrs(self, route):
        try:
            if route['attrs']:
                return dict(route['attrs'])
        except Exception as e:
            logger.debug('Unable to fetch route attributes')
            logger.debug('Error is '+str(e))
            return None

    def get_route_prefix(self, route):
        route_attrs = self.get_route_attrs(route)
        try:
            if route_attrs is not None:
                if 'RTA_DST' in route_attrs:
                    return route_attrs['RTA_DST']
                else:
                    return None
        except Exception as e:
            logger.debug('Unable to fetch route prefix')
            logger.debug('Error is '+str(e))
            return None


    def get_route_prefixlen(self, route):
        try:
            if 'dst_len' in route:
                return route['dst_len']
            else:
                return None
        except Exception as e:
            logger.debug('Unable to fetch route prefix length')
            logger.debug('Error is '+str(e))
            return None


    def get_route_gateway(self, route):
        route_attrs = self.get_route_attrs(route)
        try:
            if route_attrs is not None:
                if 'RTA_GATEWAY' in route_attrs:
                    return route_attrs['RTA_GATEWAY']
                else:
                    return None
        except Exception as e:
            logger.debug('Unable to fetch route gateway')
            logger.debug('Error is '+str(e))
            return None

    def get_route_oif(self, route):
        route_attrs = self.get_route_attrs(route)
        try:
            if route_attrs is not None:
                if 'RTA_OIF' in route_attrs:
                    return route_attrs['RTA_OIF']
                else:
                    return None
        except Exception as e:
            logger.debug('Unable to fetch route outgoing interface index')
            logger.debug('Error is '+str(e))
            return None

    def linux_to_xr_ifname(self, interface):

        if interface in ["fwdintf","fwd_ew"]:
            return interface

        cmd = ("echo "+str(interface)+" | sed -e 's/\//_/g' "
                                " -e 's/^Gi/GigabitEthernet/g'"
                                " -e 's/^Tg/TenGigE/g'"
                                " -e 's/^Fg/FortyGigE/g'"
                                " -e 's/^Tf/TwentyFiveGigE/g'"\
                                " -e 's/^Hg/HundredGigE/g'"
                                " -e 's/^Mg/MgmtEth/g'")

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        out, err = process.communicate()
        _name =  out.rstrip()
        return _name.replace('_', '/')

    def get_route_ifname(self, route):
        oif = self.get_route_oif(route)
        if oif is not None:
            try:
                if oif in self.ipdb.interfaces:
                    return self.ipdb.interfaces[oif]['ifname']
                else:
                    logger.debug("Outgoing interface not present in IPDB")
                    return None
            except Exception as e:
                logger.debug("Failed to get interfaces from IPDB")
                logger.debug("Error is "+str(e))
                return None


    def get_route_xrifname(self, route):
        ifname = self.get_route_ifname(route)
        if ifname is not None:
            xr_ifname = self.linux_to_xr_ifname(ifname)
            if xr_ifname not in ['fwdintf', 'fwd_ew']:
                return {'status': 'success', 'ifname' : xr_ifname}
            else:
                logger.debug("Skipping fwdintf and fwd_ew as outgoing interfaces")
                return {'status': 'success', 'ifname' : ''}
        else:
            return {'status': 'error', 'ifname' : ''}


    def get_admin_distance(self, route):
        route_proto = self.get_route_proto(route)
        if route_proto is not None:
            if int(route_proto) in rt_proto:
                proto = str(rt_proto[int(route_proto)])
                if proto in self.routePolicy['proto']:
                    if 'admin_distance' in self.routePolicy['proto'][proto]:
                        return self.routePolicy['proto'][proto]['admin_distance']
                    else:
                        logger.debug("User hasn't specified any custom admin distance for route, return admin distance for \"default\" proto if set")
                        if "default" in self.routePolicy['proto']:
                            return self.routePolicy['proto']['default']['admin_distance']
                        else:
                            logger.debug("No default admin distance specified")
                            return None


    def get_route_family(self, route):
        try:
            if 'family' in route:
                return route['family']
            else:
                return None
        except Exception as e:
            logger.debug('Unable to fetch route family')
            logger.debug('Error is '+str(e))
            return None

    def get_route_proto(self, route):
        try:
            if 'proto' in route:
                return route['proto']
            else:
                return None
        except Exception as e:
            logger.debug('Unable to fetch route proto')
            logger.debug('Error is '+str(e))
            return None

    def is_valid_route(self, route):
        route_attrs = self.get_route_attrs(route)
        try:

            if self.get_route_proto(route) is None:
                logger.debug("Missing proto type in route")
                return {'type' : '' , 'valid' : False}

            if self.get_route_prefix(route) is None:
                logger.debug("Missing prefix in route")
                return {'type' : '' , 'valid' : False}

            if self.get_route_prefixlen(route) is None:
                logger.debug("Missing prefix length in route")
                return {'type' : '' , 'valid' : False}

            if route_attrs is not None:
                if ('RTA_MULTIPATH' in route_attrs):
                    # Multiple Next Hop Route
                    return {'type' : ROUTE_MULTIPATH , 'valid' : True}
                else:
                    # Handle just the single hop routes here
                    if ('RTA_DST' in route_attrs and
                        'RTA_GATEWAY' in route_attrs):

                        # Single Next Hop Route
                        return {'type' : ROUTE_SINGLEPATH , 'valid' : True}

                    elif ('RTA_DST' in route_attrs and
                          'RTA_OIF' in route_attrs):

                        # Outgoing interface Only route (no next hop IP)
                        return {'type' : ROUTE_OIF , 'valid' : True}

                    elif ('RTA_GATEWAY' not in route_attrs and
                          'RTA_OIF' not in route_attrs):
                        logger.debug("No next hop in route")
                        return {'type' : '' , 'valid' : False}
                    else:
                        logger.debug("Invalid Netlink route")
                        return {'type' : '' , 'valid' : False}

        except Exception as e:
            logger.debug('Unable to determine route validity')
            logger.debug('Error is '+str(e))
            return {'type' : '' , 'valid' : False}


    def is_allowed_route(self, route):
        route_attrs = self.get_route_attrs(route)

        try:
            if route_attrs is not None:
            # Ignore local routes
                if route_attrs['RTA_TABLE'] == RT_TABLE_LOCAL:
                    return False
        except Exception as e:
            logger.debug('Unable to fetch route attributes, skipping route')
            return False 

        if self.routePolicy is not None:
            route_proto = self.get_route_proto(route)
            route_prefix = self.get_route_prefix(route)

            if route_proto is not None:
                if int(route_proto) in rt_proto:
                    proto = str(rt_proto[int(route_proto)])
                else:
                    logger.debug("route protocol type = " +str(proto)+ " not known")
                    logger.debug("Not allowing route")
                    return False
            else:
                logger.debug("Unable to fetch route protocol type")
                logger.debug("Not allowing route")
                return False


            if proto in self.routePolicy["proto"]:
                if "allowed" in self.routePolicy["proto"][proto]:
                    if self.routePolicy["proto"][proto]["allowed"]:
                        if "filter" in self.routePolicy["proto"][proto]:
                            subnets = self.routePolicy["proto"][proto]["filter"]["subnets"]
                            for subnet in subnets:
                                if ipaddress.ip_address(route_prefix) in ipaddress.ip_network(subnet):
                                    logger.debug("Prefix part of filtered subnets")
                                    logger.debug("Not allowing route")
                                    return False
                        else:
                            logger.debug("No filtering logic for protocol type="+str(proto))
                            logger.debug("Allowing route")
                            return True 
                    else:
                        logger.debug("User did not allow routes from this protocol type = "+str(proto))
                        logger.debug("Not allowing route")
                        return False
                else:
                    logger.debug("No allowed field specified in user defined route policy")
                    logger.debug("Not allowing route")
                    return False
            elif proto in DEFAULT_ROUTE_POLICY["proto"]:
                logger.debug("User did not create a policy for this protocol type = "+str(proto))
                logger.debug("Falling over to DEFAULT ROUTE POLICY")
                return DEFAULT_ROUTE_POLICY["proto"][proto]["allowed"]
            else:
                logger.debug("Protocol type="+str(proto)+" not in user or defined route policy")
                logger.debug("Not allowing route")
                return False


        # Ignore Kernel routes
        route_proto = self.get_route_proto(route)
        if route_proto is not None:
            if route_proto == rt_proto['kernel']:
                return False
        return True
