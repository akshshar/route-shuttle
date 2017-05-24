import signal, yaml
import time, os, sys, ipaddress, pdb, argparse
from functools import partial
import logging, logging.handlers
from rshuttle import RouteShuttle, logger
from plugins.netlink import NetlinkPlugin, ROUTE_EVENTS

EXIT_FLAG = False

# POSIX signal handler to ensure we shutdown cleanly
def handler(shuttler, ntlnk, signum, frame):
    global EXIT_FLAG

    if not EXIT_FLAG:
        EXIT_FLAG = True
        logger.info("Cleaning up...")
        shuttler.slcleanup()
        logger.info("Releasing IPDB")    
        ntlnk.ipdb.release()
        sys.exit(0)

# Called by the IPDB Netlink listener thread for _every_ message (route, neigh, etc,...)
def callback(ipdb, msg, action):
    if msg['event'] in [ROUTE_EVENTS['add'], ROUTE_EVENTS['delete']]:
            shuttler.rtQueue.put(msg)


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', action='store', dest='route_policy',
                    help='Specify the YAML file describing user defined rules for netlink route import')
    parser.add_argument('-i', '--server-ip', action='store', dest='server_ip',
                    help='Specify the IOS-XR GRPC server IP address', required=True)
    parser.add_argument('-p', '--server-port', action='store', dest='server_port',
                    help='Specify the IOS-XR GRPC server port', required=True)
    parser.add_argument('-v', '--verbose', action='store_true',
                    help='Enable verbose logging')


    results = parser.parse_args()
    if results.verbose:
        logger.info("Starting verbose debugging")
        logging.basicConfig()
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)


    if results.server_ip and results.server_port:
        server_ip = results.server_ip
        server_port = int(results.server_port)


    if results.route_policy:
        # Load up the user defined routePolicy
        with open(results.route_policy, 'r') as stream:
            route_policy = yaml.load(stream)
    else:
        route_policy = None

    # Instantiate the NetlinkPlugin Class
    ntlnk = NetlinkPlugin(routePolicy = route_policy, netns = 'global-vrf')

    # Create the RouteShuttle Object to start internal threads to process incoming routes
    # Also load the NetlinkPlugin class

    shuttler = RouteShuttle(plugin=ntlnk, vrf='default', server_port=server_port, server_ip=server_ip)

    # Register against the vrf that is expected to be programmed by the incoming routes.
    shuttler.register_vrf()


    # Register our handler for keyboard interrupt and termination signals
    signal.signal(signal.SIGINT, partial(handler, shuttler, ntlnk))
    signal.signal(signal.SIGTERM, partial(handler, shuttler, ntlnk))

    ## Before we listen to Netlink events, sync the current routing table

    # Fetch the routes
    routes = ntlnk.ipdb.nl.get_routes()

    # Feed the route queue
    for route in routes:
        shuttler.rtQueue.put(route)

    # Register our callback to the Netlink IPDB to listen to Netlink messages
    ntlnk.ipdb.register_callback(callback)

    # The process main thread does nothing but wait for signals
    signal.pause()
