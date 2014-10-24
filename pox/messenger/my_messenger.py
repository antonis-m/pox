from pox.core import core
from pox.lib.revent import Event
from pox.lib.revent.revent import *
from pox.messenger import *
import random
log = core.getLogger()


class MessengerEvent (Event):
    def __init__(self, router, mac, mac_prefix, ip, subnet, net_id,
                 port, gateway_ip, join=False, leave=False):
        super(MessengerEvent, self).__init__()
        self.router = router
        self.ip = ip
        self.gateway_ip = gateway_ip
        self.mac = mac
        self.mac_prefix = mac_prefix
        self.subnet = subnet
        self.net_id = net_id
        self.port = port
        self.join = join
        self.leave = leave

        assert sum(1 for x in [join, leave] if x) == 1


class CycladesService (EventMixin):

    _eventMixin_events = set([MessengerEvent])

    def __init__(self, parent, con, event):
        EventMixin.__init__(self)
        self._forwarding = set()
        self.parent = parent
        self.con = con
        self.count = 0
        self.listeners = con.addListeners(self)
        core.openflow.addListeners(self)
        #First message - handle manually
        self._handle_MessageReceived(event, event.msg)

    def _handle_ConnectionClosed(self, event):
        self.con.removeListeners(self.listeners)
        self.parent.clients.pop(self.con, None)

    def _handle_MessageReceived(self, event, msg):
        if self.count == 0:
            self.con.send(reply(msg,msg="send next message with router info "))
            self.count += 1
        else:
            print "received message with new NIC_params. Updating router"
            port = self._pick_forwarding_port()
            entry = MessengerEvent("yes","aa:vv:vv", "aa:vv:bb:","83.0.0.0",
                                   "10.0.0.0/24", 42, port, "10.0.0.1",
                                    True)
            self.raiseEventNoErrors(entry)
            self.con.send(reply(msg,msg="OK"))

    def _pick_forwarding_port(self):
        port = random.randint(49152, 65534)
        cycle = 0
        while (cycle < 5):
            if port not in self._forwarding:
                self._forwarding.add(port)
                print port
                return port
            port += 1
            if port > 65534:
                port = 49152
                cycle += 1
        log.warn("No ports to give")
        return None


class CycladesBot (ChannelBot):
    def _init(self, extra):
        self.clients = {}

    def _unhandled(self, event):
        connection = event.con
        if connection not in self.clients:
            self.clients[connection] = CycladesService(self, connection, event)
            core.register("messenger", self.clients[connection])


class MyMessenger (object):
    def __init__(self):
        core.listen_to_dependencies(self)

    def _all_dependencies_met(self):
        CycladesBot(core.MessengerNexus.get_channel("cyclades"))


def launch():
    MyMessenger()
