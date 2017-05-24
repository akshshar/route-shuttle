#! /usr/bin/python

from abc import ABCMeta, abstractmethod

class BasePlugin():
    __metaclass__ = ABCMeta

    @abstractmethod
    def get_route_prefix(self):
        """Method to return prefix from
           route pushed to queue"""
        pass

    @abstractmethod
    def get_route_prefixlen(self):
        """Method to get prefix length
           from route pushed to queue"""
        pass

    @abstractmethod
    def get_route_gateway(self):
        """Method to return gateway (next hop IP)
           from route pushed to queue"""
        pass

    @abstractmethod
    def get_route_xrifname(self):
        """Method to next hop interface (if present)
           as a valid interface name for IOS-XR platforms
           from route pushed to queue"""
        pass

    @abstractmethod
    def get_admin_distance(self):
        """Method to fetch the user-defined admin distance
           for the route"""
        pass

    @abstractmethod
    def get_route_family(route):
        """Method to get route family from route. The expected
        values are:
        AF_NET = ipv4
        AF_INET6 = ipv6.
        These are defined in the python socket module"""
        pass


    @abstractmethod
    def is_valid_route(route):
        """
        Method to return a dictionary based on
        route analysis:

        {'type' : '' , 'valid' : False}

        'type' is expected to be one of the following values:

         ROUTE_SINGLEPATH
         ROUTE_MULTIPATH
         ROUTE_OIF
         or ''  (empty)

         """
        pass


    @abstractmethod
    def is_allowed_route(route):
        """Method to return a boolean if a valid route
           (see is_valid_route) is chosen to be disallowed
           by the user/plugin """
        pass
