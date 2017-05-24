#! /usr/bin/python

import Queue, threading
import os, sys, ipaddress, pdb
from socket import AF_INET, AF_INET6

import logging, logging.handlers
logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Add the generated python bindings directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
# gRPC generated python bindings
from genpy import sl_route_ipv4_pb2
from genpy import sl_route_common_pb2
from genpy import sl_common_types_pb2
from genpy import sl_global_pb2
from genpy import sl_version_pb2

# gRPC libs
from grpc.beta import implementations

ROUTE_OIF = 0x10
ROUTE_SINGLEPATH = 0x11
ROUTE_MULTIPATH = 0x12

class RouteShuttle(object):

    def __init__(self, plugin, vrf, server_ip, server_port):

        self.server_ip = server_ip
        self.server_port = server_port
        self.vrf = vrf
        self.v4routeList = []
        self.plugin = plugin   #The client will load the correct plugin object
        self.rtQueue= Queue.Queue(maxsize=100000)
        self.poisonpillq = Queue.Queue()
        self.threadList = []

        self.channel = self.setup_grpc_channel()
        for fn in [self.route_batch]:
            thread = threading.Thread(target=fn, args=())
            self.threadList.append(thread)
            thread.daemon = True                            # Daemonize thread
            thread.start()                                  # Start the execution



    def slcleanup(self):
      logger.info("Cleaning up, exiting the active threads")
      self.unregister_vrf()
      self.poisonpillq.put("quit")
      self.rtQueue.put("quit")
      for thread in self.threadList:
          logger.info("Waiting for %s to finish..." %(thread.name))
          thread.join()
      return

    def setup_grpc_channel(self):

        logger.info("Using GRPC Server IP(%s) Port(%s)" %(self.server_ip, self.server_port))
        # Create the channel for gRPC.
        channel = implementations.insecure_channel(self.server_ip, self.server_port)
        # Spawn a thread to Initialize the client and listen on notifications
        # The thread will run in the background
        self.global_init(channel)
        # Create another channel for gRPC requests.
        channel = implementations.insecure_channel(self.server_ip, self.server_port)
        return channel


    def client_init(self, stub, event):
        #
        # Create SLInitMsg to handshake the version number with the server.
        # The Server will allow/deny access based on the version number.
        # The same RPC is used to setup a notification channel for global
        # events coming from the server.
        #
        # # Set the client version number based on the current proto files' version
        pill = ''
        init_msg = sl_global_pb2.SLInitMsg()
        init_msg.MajorVer = sl_version_pb2.SL_MAJOR_VERSION
        init_msg.MinorVer = sl_version_pb2.SL_MINOR_VERSION
        init_msg.SubVer = sl_version_pb2.SL_SUB_VERSION

        # Set a very large timeout, as we will "for ever" loop listening on
        # notifications from the server
        Timeout = 365*24*60*60 # Seconds

        # This for loop will never end unless the server closes the session
        for response in stub.SLGlobalInitNotif(init_msg, Timeout):
            logger.debug("Received event from GRPC server")
            if response.EventType == sl_global_pb2.SL_GLOBAL_EVENT_TYPE_VERSION:
                if (sl_common_types_pb2.SLErrorStatus.SL_SUCCESS ==
                        response.ErrStatus.Status) or \
                    (sl_common_types_pb2.SLErrorStatus.SL_INIT_STATE_CLEAR ==
                        response.ErrStatus.Status) or \
                    (sl_common_types_pb2.SLErrorStatus.SL_INIT_STATE_READY ==
                        response.ErrStatus.Status):
                    logger.debug("Server Returned 0x%x, Version %d.%d.%d" %(
                        response.ErrStatus.Status,
                        response.InitRspMsg.MajorVer,
                        response.InitRspMsg.MinorVer,
                        response.InitRspMsg.SubVer))
                    logger.debug("Successfully Initialized, connection established!")
                    # Any thread waiting on this event can proceed
                    event.set()
                else:
                    logger.debug("client init error code 0x%x", response.ErrStatus.Status)

            elif response.EventType == sl_global_pb2.SL_GLOBAL_EVENT_TYPE_HEARTBEAT:
                logger.debug("Received HeartBeat")
                try:
                    pill = self.poisonpillq.get_nowait()
                except Queue.Empty:
                    pass

                if isinstance(pill, str) and pill == "quit":
                    logger.debug("Received a poison pill, killing the global thread")
                    return

            elif response.EventType == sl_global_pb2.SL_GLOBAL_EVENT_TYPE_ERROR:
                if (sl_common_types_pb2.SLErrorStatus.SL_NOTIF_TERM ==
                    response.ErrStatus.Status):
                    logger.debug("Received notice to terminate. Client Takeover?")
                else:
                    logger.debug("Error not handled:", response)
            else:
                logger.debug("client init unrecognized response %d", response.EventType)


    def global_thread(self, stub, event):
        logger.debug("Global thread spawned")

        # Initialize the GRPC session. This function should never return
        self.client_init(stub, event)

        logger.debug("global_thread: exiting unexpectedly")
        # If this session is lost, then most likely the server restarted
        # Typically this is handled by reconnecting to the server. For now, exit()
        

    def global_init(self, channel):
        # Create the gRPC stub.
        stub = sl_global_pb2.beta_create_SLGlobal_stub(channel)

        # Create a thread sync event. This will be used to order thread execution
        event = threading.Event()

        # The main reason we spawn a thread here, is that we dedicate a GRPC
        # channel to listen on Global asynchronous events/notifications.
        # This thread will be handling these event notifications.
        t = threading.Thread(target = self.global_thread, args=(stub, event))
        self.threadList.append(t)
        t.start()

        # Wait for the spawned thread before proceeding
        event.wait()

        # Get the globals. Create a SLGlobalsGetMsg
        global_get = sl_global_pb2.SLGlobalsGetMsg()

        #
        # Make an RPC call to get global attributes
        #
        Timeout = 10 # Seconds
        response = stub.SLGlobalsGet(global_get, Timeout)

        # Check the received result from the Server
        if (response.ErrStatus.Status ==
            sl_common_types_pb2.SLErrorStatus.SL_SUCCESS):
            logger.debug("Max VRF Name Len     : %d" %(response.MaxVrfNameLength))
            logger.debug("Max Iface Name Len   : %d" %(response.MaxInterfaceNameLength))
            logger.debug("Max Paths per Entry  : %d" %(response.MaxPathsPerEntry))
            logger.debug("Max Prim per Entry   : %d" %(response.MaxPrimaryPathPerEntry))
            logger.debug("Max Bckup per Entry  : %d" %(response.MaxBackupPathPerEntry))
            logger.debug("Max Labels per Entry : %d" %(response.MaxMplsLabelsPerPath))
            logger.debug("Min Prim Path-id     : %d" %(response.MinPrimaryPathIdNum))
            logger.debug("Max Prim Path-id     : %d" %(response.MaxPrimaryPathIdNum))
            logger.debug("Min Bckup Path-id    : %d" %(response.MinBackupPathIdNum))
            logger.debug("Max Bckup Path-id    : %d" %(response.MaxBackupPathIdNum))
            logger.debug("Max Remote Bckup Addr: %d" %(response.MaxRemoteAddressNum))
        else:
            logger.debug("Globals response Error 0x%x" %(response.ErrStatus.Status))


    def vrf_operation(self, oper):
        # Create the gRPC stub.
        stub = sl_route_ipv4_pb2.beta_create_SLRoutev4Oper_stub(self.channel)

        # Create the SLVrfRegMsg message used for VRF registrations
        vrfMsg = sl_route_common_pb2.SLVrfRegMsg()

        # Create a list to maintain the SLVrfReg objects (in case of batch VRF
        # registrations)
        # In this example, we fill in only a single SLVrfReg object
        vrfList = []

        # Create an SLVrfReg object and set its attributes
        vrfObj = sl_route_common_pb2.SLVrfReg()
        # Set VRF name.
        vrfObj.VrfName = self.vrf
        # Set Administrative distance
        vrfObj.AdminDistance = 1
        # Set VRF purge interval
        vrfObj.VrfPurgeIntervalSeconds = 500

        #
        # Add the registration message to the list
        # In case of bulk, we can append other VRF objects to the list
        vrfList.append(vrfObj)

        # Now that the list is completed, assign it to the SLVrfRegMsg
        vrfMsg.VrfRegMsgs.extend(vrfList)

        # Set the Operation
        vrfMsg.Oper = oper

        #
        # Make an RPC call
        #
        Timeout = 10 # Seconds
        response = stub.SLRoutev4VrfRegOp(vrfMsg, Timeout)

        #
        # Check the received result from the Server
        # 
        if (response.StatusSummary.Status ==
                sl_common_types_pb2.SLErrorStatus.SL_SUCCESS):
            logger.debug("VRF %s Success!" %(
                sl_common_types_pb2.SLRegOp.keys()[oper]))
        else:
            logger.debug("Error code for VRF %s is 0x%x! Response:" % (
                sl_common_types_pb2.SLRegOp.keys()[oper],
                response.StatusSummary.Status))
            logger.debug(response)

        # If we have partial failures within the batch, let's print them
        if (response.StatusSummary.Status == 
            sl_common_types_pb2.SLErrorStatus.SL_SOME_ERR):
            for result in response.Results:
                logger.debug("Error code for %s is 0x%x" %(result.VrfName,
                    result.ErrStatus.Status))



    def register_vrf(self):
        # Send an RPC for VRF registrations
        self.vrf_operation(sl_common_types_pb2.SL_REGOP_REGISTER)
        # RPC EOF to cleanup any previous stale routes
        self.vrf_operation(sl_common_types_pb2.SL_REGOP_EOF)

    def unregister_vrf(self):
        # When done with the VRFs, RPC Delete Registration
        logger.debug("Unregistering the vrf")
        self.vrf_operation(sl_common_types_pb2.SL_REGOP_UNREGISTER)


    def setup_v4routelist(self, route, route_event, route_type):
        #
        # Create an SLRoute object and set its attributes
        #

        routev4 = sl_route_ipv4_pb2.SLRoutev4()

        # Ignore routes that are not allowed
        if not self.plugin.is_allowed_route(route):
            return

        # IP Prefix
        routev4.Prefix = int(ipaddress.ip_address(self.plugin.get_route_prefix(route)))

        # Prefix Length
        routev4.PrefixLen = self.plugin.get_route_prefixlen(route)

        # Administrative distance Loaded based on User defined proto weight
        admin_distance = self.plugin.get_admin_distance(route)

        if admin_distance is not None:
            routev4.RouteCommon.AdminDistance =  admin_distance
        else:
            logger.debug("No Admin Distance specified by User, skipping route")
            return

        # Create an SLRoutePath path object.
        path = sl_route_common_pb2.SLRoutePath()
        # Fill in the path attributes.
        # Path next hop address

        if route_event != 'delete':
            if route_type == ROUTE_SINGLEPATH:
                path.NexthopAddress.V4Address = int(ipaddress.ip_address(self.plugin.get_route_gateway(route)))
                nh_interface = self.plugin.get_route_xrifname(route)
                if nh_interface['status'] == 'success':
                    if nh_interface['ifname'] != '':
                        path.NexthopInterface.Name = nh_interface['ifname']
                    else:
                        logger.debug("OIF not allowed, skipping next hop interface setting")
                else:
                    logger.debug("Error while fetching the next hop interface, skip route")
                    return
            elif route_type == ROUTE_OIF:
                # For now, we ignore OIF only routes, SL-API expects a gateway to be specified
                logger.debug("Gateway is not specified, skipping this route")
                return

            routev4.PathList.extend([path])


        #
        # Append the route to the route list (bulk routes)
        #
        self.v4routeList.append(routev4)



    def prefix_in_rib(self, route):

        # Set up the stub to query Routes
        stub = sl_route_ipv4_pb2.beta_create_SLRoutev4Oper_stub(self.channel)

        # Create the container to be used in the query message
        serializer = sl_route_ipv4_pb2.SLRoutev4GetMsg()

        # IP Prefix
        prefix = int(ipaddress.ip_address(self.plugin.get_route_prefix(route)))
        # Prefix Length
        prefixLen = self.plugin.get_route_prefixlen(route)

        serializer.Prefix = int(ipaddress.ip_address(prefix))
        serializer.PrefixLen = int(prefixLen)
        serializer.EntriesCount = 1
        serializer.GetNext = False
        serializer.VrfName = self.vrf

        Timeout = 10

        response = stub.SLRoutev4Get(serializer, Timeout)

        if not response.ErrStatus.Status:
            # Check if route is present in the response
            for elem in response.Entries:
                if self.plugin.get_route_family(route) == AF_INET:
                    addr = int(ipaddress.ip_address(elem.Prefix))
                    if prefix == addr:
                        logger.debug("Route present in application RIB already")
                        return response, True
                    else:
                        return response, False
        else:
            logger.error("Error fetching route from RIB: 0x%x" % (
                response.ErrStatus.Status
            ))
            # If we have partial failures within the batch, let's print them
            if (response.StatusSummary.Status ==
                sl_common_types_pb2.SLErrorStatus.SL_SOME_ERR):
                for result in response.Results:
                    logger.debug("Error code for %s/%d is 0x%x" %(
                       str(ipaddress.ip_address(result.Prefix)),
                        result.PrefixLen,
                        result.ErrStatus.Status
                    ))

        return response, False


    def route_batch(self, batch_size=100000):

        route_batch_v4 = []
        rt_last_event = 'add'  # Possible values include add, update, delete
        batch_prefixset_v4 = set()
        commit_batch = False
        route = None


        while True:
            try:
                route = self.rtQueue.get_nowait()
            except Queue.Empty:
                # Used to initiate a batch commit when queue become empty
                commit_batch = True
                if self.v4routeList:
                    route_batch_v4 = self.v4routeList[:]
                    self.v4routeList = []
                    batch_action = rt_last_event
            else:
                logger.debug("Got a Route Message!")
                logger.debug(route)

                if isinstance(route, str) and route == "quit":
                    logger.debug("Quitting the route worker thread")
                    break

                try:
                    logger.debug(self.plugin.get_route_prefix(route))
                except:
                    logger.debug("No prefix in route")

                route_event = ''

                if self.plugin.get_route_family(route) == AF_INET:
                    try:
                        # The following checks are necessary to differentiate between
                        # route add and update

                        route_check = self.plugin.is_valid_route(route)
                        if route_check['valid'] :
                            route_tuple = (self.plugin.get_route_prefix(route),self.plugin.get_route_prefixlen(route))
                            response, verdict = self.prefix_in_rib(route)

                            # Check if the route is already present in application RIB
                            # or if the route is present in the current batch itself
                            if (verdict or
                                route_tuple in batch_prefixset_v4):
                                if self.plugin.route_events[route['event']] == 'add':
                                    route_event = 'update'
                                else:
                                    route_event = self.plugin.route_events[route['event']]
                            else:
                                route_event = self.plugin.route_events[route['event']]

                            batch_prefixset_v4.add((self.plugin.get_route_prefix(route), self.plugin.get_route_prefixlen(route)))

                        else:
                            commit_batch = False
                            continue
                    except Exception as e:
                        logger.debug("Failed to check if the route already exists, skip this route")
                        logger.debug("Error is " +str(e))
                        commit_batch = False
                        continue


                    # If the latest event type is different from the last event type, then
                    # create a route batch from the previous set of routes and send to RIB

                    if route_event != rt_last_event:
                        # Prepare to commit the route batch now
                        route_batch_v4 = self.v4routeList[:]
                        commit_batch = True
                        batch_action = rt_last_event

                        # Cleanup for the next round of updates
                        self.v4routeList = []
                        batch_prefixset_v4.clear()

                        # Save the update that triggered batch creation
                        self.setup_v4routelist(route, route_event, route_check['type'])
                    else:
                        self.setup_v4routelist(route, route_event, route_check['type'])

                    rt_last_event = route_event
                self.rtQueue.task_done()
            finally:
                if route_batch_v4:
                    logger.debug("Current commit batch: " +str(commit_batch))
                    if commit_batch:
                        logger.debug("Current route batch:")
                        logger.debug(route_batch_v4)
                        self.slv4_rtbatch_send(route_batch_v4, batch_action)
                        route_batch_v4= []
                        commit_batch = False
                        route = None

    def slv4_rtbatch_send(self, route_batch, event):

        logger.info("Got a Route List!")
        # Create the gRPC stub for v4 routemsg
        stub = sl_route_ipv4_pb2.beta_create_SLRoutev4Oper_stub(self.channel)

        # Create the SLRoutev4Msg message holding the SLRoutev4 object list
        rtMsg = sl_route_ipv4_pb2.SLRoutev4Msg()

        rtMsg.VrfName = self.vrf

        if event == 'add':
            oper = sl_common_types_pb2.SL_OBJOP_ADD
        elif event == 'delete':
            oper = sl_common_types_pb2.SL_OBJOP_DELETE
        elif event == 'update':
            oper = sl_common_types_pb2.SL_OBJOP_UPDATE
        else:
            return
        rtMsg.Routes.extend(route_batch)

        logger.debug(rtMsg)
        #
        # Make an RPC call
        #
        Timeout = 10 # Seconds
        rtMsg.Oper = oper # Desired ADD, UPDATE, DELETE operation
        response = stub.SLRoutev4Op(rtMsg, Timeout)
        #
        # Check the received result from the Server
        #

        if (sl_common_types_pb2.SLErrorStatus.SL_SUCCESS ==
               response.StatusSummary.Status):
            logger.debug("Route %s Success!" %(
                sl_common_types_pb2.SLObjectOp.keys()[oper]))
        else:
            logger.error("Error code for route %s is 0x%x" % (
                sl_common_types_pb2.SLObjectOp.keys()[oper],
                response.StatusSummary.Status
            ))
            # If we have partial failures within the batch, let's print them
            if (response.StatusSummary.Status ==
                sl_common_types_pb2.SLErrorStatus.SL_SOME_ERR):
                for result in response.Results:
                    logger.debug("Error code for %s/%d is 0x%x" %(
                       str(ipaddress.ip_address(result.Prefix)),
                        result.PrefixLen,
                        result.ErrStatus.Status
                    ))
