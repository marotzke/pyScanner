import argparse
version = "0.1"

"""
PROJECT
Ser em linguagem Python;
[OKAY]• Permitir o escaneamento de um host ou uma rede;
[    ]• Permitir selecionar o Protocolo TCP ou UDP;
[HALF]• Permitir inserir o range (intervalo) de portas a serem escaneadas;
[    ]• Além da função de escaneamento, espera-se que seu código relacione as
portas Well-Know Ports e seus serviços, e apresente em sua saída (imprimir)
o número da porta e o nome do serviço associado.  (#socket getservbyport(port, protocol))


"""


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


