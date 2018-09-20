""""
    pyScanner is a program to scan TCP/UDP ports for Network Security purpose.
    Copyright (C) 2018 Matheus Marotzke - matheus.marotzke@gmail.com

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
import argparse
import socket
import sys
from multiprocessing.dummy import Pool as ThreadPool 
import itertools
import errno
import progressbar

version = "1.0.0"

parser = argparse.ArgumentParser(prog='pyScanner', description='Scan ports on from a given address.', 
                                 epilog='''This application should be used for personal security analysis only.
                                           This can be used to commit cyber-crimes, developers are not responsible for improper usage.''')
parser.add_argument('address', metavar='ADDRESS', type=str, nargs=1, help='destination host/network to be scanned')
parser.add_argument('--verbose', '-v', action='count', default=0, help='print closed ports as well')
parser.add_argument('--version', action='version', version='%(prog)s {0}'.format(version))
parser.add_argument('--ports', '-p', dest='ports', nargs=2, metavar=('INIT_PORT','END_PORT'), type=int, choices=range(1, 64999), required=True, help='ports to be analysed')
parser.add_argument('--tcp', '-t', dest='TCP', default=False, action='store_true', help='analyse TCP ports')
parser.add_argument('--udp', '-u', dest='UDP', default=False, action='store_true', help='analyse UDP ports')


args = parser.parse_args()

#socket gethostbyaddr(ip_address)
#socket getservbyport(port, protocol)
timeout = 2
socket.setdefaulttimeout(timeout)

def scan_ports(args, port):
    bar.update(port - args.ports[0])
    try:
        if not args.TCP and not args.UDP:
            args.TCP = True
            args.UDP = True
        if args.TCP:
            type = "tcp"
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((args.address[0], port))
            service = socket.getservbyport(port, type)
            if result == 0:
                status = "Open  "
            else:
                status = "Closed"
            return (port, service, status, type)
            sock.close()
        if args.UDP:#UDP
            type = "udp"
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            result = sock.connect_ex((args.address[0], port))
            service = socket.getservbyport(port, type)
            if result == 0:
                status = "Open  "
            else:
                status = "Closed"
            return (port, service, status, type)
            sock.close()

    except KeyboardInterrupt:
        print("Program interrupted by user.")
        sys.exit()

    except socket.gaierror:
        print('Hostname could not be resolved. Exiting')
        sys.exit()

    except socket.error as error:
        # print("Couldn't connect to server - {0}\n".format(error.errno))
        pass
        # sys.exit()


ports = list(range(args.ports[0],args.ports[1]))

print('\n{3}Analysing HOST: {0} PORTS: {1} to {2} {4}'.format(args.address[0],args.ports[0],args.ports[1], bcolors.HEADER, bcolors.ENDC))
bar = progressbar.ProgressBar(maxval=(args.ports[1]-args.ports[0]), \
    widgets=[progressbar.Bar('=', '[', ']'), ' ', progressbar.Percentage()])

bar.start()

pool = ThreadPool(4) 
result = pool.starmap(scan_ports, zip(itertools.repeat(args),list(range(args.ports[0],args.ports[1]))))
pool.close() 
pool.join() 

bar.finish()
print()
result = [x for x in result if x is not None]
for port, service, status, type in result:
    if args.verbose > 0 or status == "Open  ":
        color =  bcolors.OKGREEN if status == "Open  " else ''
        endcolor = bcolors.ENDC if status == "Open  " else ''
        print( "{4}Port {0}:      Status:{2}      Protocol:{3}    Service:[{1}]{5}".format(port, service, status.upper(), type.upper(), color, endcolor))

# for port in range(args.ports[0],args.ports[1]):
    # scan_ports([args.address, args.TCP, args.UDP, args.verbose],port)
