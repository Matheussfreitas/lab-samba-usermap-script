#!/usr/bin/python
#=======================================================================
# topo_samba.py — Topologia Containernet para o lab CVE-2007-2447
# (Samba usermap_script). Switch ligando Alice (alvo) e Chuck (atacante)
#=======================================================================
import os
from containernet.net import Containernet
from containernet.cli import CLI
from containernet.term import makeTerm
from mininet.log import info, setLogLevel


ALICE_IMAGE = "mgsoutodelira/samba-vuln:latest"
CHUCK_IMAGE = "mgsoutodelira/msf-attacker:latest"


def topology():
    "Topologia: switch ligando Alice (alvo) e Chuck (atacante)."
    DISPLAY_ID = 0
    net = Containernet(ipBase='10.200.0.0/24')

    os.system('sudo xhost +local:docker')
    os.system('export DISPLAY=:{}'.format(DISPLAY_ID))

    info("*** Creating nodes\n")
    s1 = net.addSwitch('s1', failMode="standalone")
    alice1 = net.addDocker('alice', dimage=ALICE_IMAGE, cpu_shares=20,
                            volumes=['/tmp/.X11-unix:/tmp/.X11-unix:rw'],
                            environment={'DISPLAY': ":{}".format(DISPLAY_ID)},
                            mac='00:00:00:00:00:01')
    chuck1 = net.addDocker('chuck', dimage=CHUCK_IMAGE, cpu_shares=20,
                            volumes=['/tmp/.X11-unix:/tmp/.X11-unix:rw'],
                            environment={'DISPLAY': ":{}".format(DISPLAY_ID)},
                            mac='00:00:00:00:00:02')

    info("*** Creating Links\n")
    net.addLink(s1, alice1)
    net.addLink(s1, chuck1)

    info("*** Starting network\n")
    net.build()
    s1.start([])

    alice1.cmd("echo '10.200.0.1 alice' > /etc/hosts")
    alice1.cmd("/usr/local/samba/start.sh > /tmp/samba.log 2>&1 &")

    makeTerm(chuck1, cmd="bash")

    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
