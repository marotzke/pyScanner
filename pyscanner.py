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

import argparse
version = "0.1"

parser = argparse.ArgumentParser(prog='pyScanner', description='Scan ports on from a given address.', 
                                 epilog='''This application should be used for personal security analysis only.
                                           This can be used to commit cyber-crimes, developers are not responsible for improper usage.''')
parser.add_argument('address', metavar='ADDRESS', type=str, nargs=1,help='destination host/network to be scanned')
parser.add_argument('--verbose', '-v', action='count', default=0, help='print closed ports as well')
parser.add_argument('--version', action='version', version='%(prog)s {0}'.format(version))
parser.add_argument('--ports', '-p', dest='ports', nargs=2, metavar=('INIT_PORT','END_PORT'), type=int, choices=range(1, 64999), required=True, help='ports to be analysed')
parser.add_argument('--tcp', '-t', dest='TCP', default=False, action='store_true', help='analyse TCP ports')
parser.add_argument('--udp', '-u', dest='UDP', default=False, action='store_true', help='analyse UDP ports')


args = parser.parse_args()
print(args)

#socket gethostbyaddr(ip_address)
#socket getservbyport(port, protocol)


