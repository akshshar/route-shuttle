#! /usr/bin/python

import subprocess, ipaddress
from functools import partial
from base import BasePlugin
from routeshuttle.rshuttle import logger

ROUTE_OIF = 0x10
ROUTE_SINGLEPATH = 0x11
ROUTE_MULTIPATH = 0x12

ROUTE_EVENTS = {'add': 'add',
                'del' : 'delete',
                'delete' : 'del'}


class OpenBMPPlugin(BasePlugin):

    def __init__(self):
        self.route_events = ROUTE_EVENTS

    def get_route_paths(self, route):
        try:
            if route['paths']:
                return dict(route['paths'])
        except Exception as e:
            logger.debug('Unable to fetch route paths')
            logger.debug('Error is '+str(e))
            return None

    def get_route_prefix(self, route):
        try:
            if 'network' in route:
                return route['network']
            else:
                return None
        except Exception as e:
            logger.debug('Unable to fetch route prefix')
            logger.debug('Error is '+str(e))
            return None


    def get_route_prefixlen(self, route):
        try:
            if 'prefix_len' in route:
                return route['prefix_len']
            else:
                return None
        except Exception as e:
            logger.debug('Unable to fetch route prefix length')
            logger.debug('Error is '+str(e))
            return None


    def get_route_gateway(self, route):
        route_paths = self.get_route_paths(route)
        try:
            if route_paths is not None:
                if 'nexthop' in route_paths:
                    return route_paths['nexthop']
                else:
                    return None
        except Exception as e:
            logger.debug('Unable to fetch route gateway')
            logger.debug('Error is '+str(e))
            return None

    def get_route_event(self, route):
        route_paths = self.get_route_paths(route)
        try:
            if route_paths is not None:
                if 'event' in route_paths:
                    return route_paths['event']
                else:
                    return None
        except Exception as e:
            logger.debug('Unable to fetch route event')
            logger.debug('Error is '+str(e))
            return None

    def get_route_oif(self, route):
        route_paths = self.get_route_paths(route)
        try:
            if route_paths is not None:
                if 'nexthop_interface' in route_paths:
                    return route_paths['nexthop_interface']
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
            return {'status': 'success', 'ifname' : ''}


    def get_admin_distance(self, route):
        route_paths = self.get_route_paths(route)
        try:
            if route_paths is not None:
                if 'admin_distance' in route_paths:
                    return route_paths['admin_distance']
                else:
                    return None
        except Exception as e:
            logger.debug('Unable to fetch route gateway')
            logger.debug('Error is '+str(e))
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
        return 'openbmp'

    def is_valid_route(self, route):
        route_paths = self.get_route_paths(route)
        print route_paths
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

            if route_paths is not None:
                    # Assume single hop routes for now 
                    if ('network' in route and
                        'nexthop' in route_paths):

                        # Single Next Hop Route
                        return {'type' : ROUTE_SINGLEPATH , 'valid' : True}

                    elif ('network' in route and
                          'nexthop_interface' in route_paths):

                        # Outgoing interface Only route (no next hop IP)
                        return {'type' : ROUTE_OIF , 'valid' : True}

                    elif ('nexthop' not in route_paths and
                          'nexthop_interface' not in route_paths):
                        logger.debug("No next hop in route")
                        return {'type' : '' , 'valid' : False}
                    else:
                        logger.debug("Invalid route")
                        return {'type' : '' , 'valid' : False}

            else:
                return {'type' : '' , 'valid' : False}
        except Exception as e:
            logger.debug('Unable to determine route validity')
            logger.debug('Error is '+str(e))
            return {'type' : '' , 'valid' : False}


    def is_allowed_route(self, route):
        return True
        route_paths = self.get_route_paths(route)

        try:
            if route_paths is not None:
            # Ignore local routes
                if route_paths['RTA_TABLE'] == RT_TABLE_LOCAL:
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
