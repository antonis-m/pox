from pox.core import core
from pox.lib.revent import Event
from pox.lib.revent.revent import *
from pox.messenger import *
import random
log = core.getLogger()


class MessengerEvent (Event):
    def __init__(self, router, router_nics, user_nics, rem_nics={},
                 join=False, leave=False):
        super(MessengerEvent, self).__init__()
        self.router = router
        self.router_nics = router_nics
        self.user_nics = user_nics
        self.rem_nics = rem_nics
        self.join = join
        self.leave = leave


class CycladesService (EventMixin):

    _eventMixin_events = set([MessengerEvent])

    def __init__(self, parent, con, event):
        EventMixin.__init__(self)
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
            #self.con.send(reply(msg,msg="send next message with router info "))
            self.count += 1
        else:
            print "received message with new NIC_params. Updating router"
            print event.msg["msg"]
            entry = MessengerEvent(event.msg["msg"]["router"],
                                   event.msg["msg"]["router_nics"],
                                   event.msg["msg"]["user_nics"],
                                   event.msg["msg"]["rem_nics"])
            self.raiseEventNoErrors(entry)
            print core.components["NAT"]._forwarding
            self.con.send(reply(msg,msg="OK"))


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
