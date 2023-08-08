from argparse import ArgumentParser
from ctypes import windll
from datetime import datetime
from os import system as RunCommand
from socketserver import BaseRequestHandler, TCPServer
from ssl import Purpose, create_default_context
from subprocess import CalledProcessError, check_output
from sys import exit as _exit
from time import sleep as timeSleep
from time import time as nowTime

from requests import get as request_get

adminPrivilleges: bool = windll.shell32.IsUserAnAdmin()
parser = ArgumentParser(
    description="An automate address blocker for Growtopia Private Server",
    add_help=False,
)

parser.add_argument(
    "-h",
    "--host",
    help="Specify the host address for the server_data.php",
    default=None,
)
parser.add_argument("-p", "--port", help="Specify the port number", default=443)
args_result = parser.parse_args()


class pprint:
    def __init__(self, loc: str, text: str, *args, **kwargs) -> None:
        self.nowDate: datetime.now = datetime.now()
        print(
            self.nowDate.strftime("%Y-%m-%dT%H:%M:%S.")
            + str(self.nowDate.microsecond)
            + f" server[{loc}]: {text}",
            *args,
            **kwargs,
        )


if args_result.host is None:
    try:
        ip_add: str = request_get("https://api.ipify.org/").text
        pprint("MissingArgument", "Host address automatically set to: " + ip_add)

    except Exception:
        pprint(
            "NetworkError",
            "Failed to get the vps ip address.. please type manually by using the `-h` flag",
        )
        _exit(1)

else:
    ip_add = args_result.host

if not str(args_result.port).isdigit():
    pprint("TypeError", "Port supposed to be an integer, not a string.")
    _exit(1)

UbiServices: list = [
    "UbiServices_SDK_2019.Release.27_PC32_unicode_static",
    "UbiServices_SDK_2019.Release.27_PC64_unicode_static",
    "UbiServices_SDK_2017.Final.21_ANDROID64_static",
    "UbiServices_SDK_2017.Final.21_ANDROID32_static",
]

if not adminPrivilleges:
    pprint(
        "permissionError",
        "This program has to be executed as Administrator in order to change netsh firewall settings.",
    )
    pprint("timeout", "Closing in 3 second.")
    timeSleep(3)
    _exit(1)

try:
    blockedAddress = (
        check_output(
            'netsh advfirewall firewall show rule name="BlockedAddress', shell=True
        )
        .decode()
        .splitlines()
    )
    blockedAddress = [
        line.replace(" ", "")[9:]
        for line in blockedAddress
        if line.startswith("RemoteIP")
    ][0].split(",")
    blockedAddress = [address.split("/")[0] for address in blockedAddress]

except CalledProcessError:
    pprint(
        "netsh.firewall",
        "Failed to load blacklist address, automatically reset to dafult.",
    )
    blockedAddress = []


class GrowtopiaRequestHandler(BaseRequestHandler):
    def handle(self) -> None:
        global blockedAddress
        clientData: list = self.request.recv(256).decode().splitlines()
        if not clientData:
            return

        if len(clientData) == 7 and self.client_address[0] not in blockedAddress:
            if (
                clientData[0] == "POST /growtopia/server_data.php HTTP/1.1"
                and clientData[1].startswith("Host: www.growtopia")
                and clientData[2].split(": ")[1] in UbiServices
                and clientData[3] == "Accept: */*"
                and clientData[4].split(": ")[1] == "application/x-www-form-urlencoded"
                and clientData[5].split(": ")[1] == "36"
            ):
                self.request.sendall(
                    f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nserver|{ip_add}\nport|17091\ntype|1\n#maint\nbeta_server|127.0.0.1\nbeta_port|10000\nbeta_type|1\nmeta|localhost\nRTENDMARKERBS1001".encode()
                )
                return

        if self.client_address[0] not in blockedAddress:
            pprint(
                "GrowtopiaRequestHandler",
                f"New malicious requests captured, automatically blocked => {self.client_address[0]}",
            )
            blockedAddress.append(self.client_address[0])

            exitCode: int = RunCommand(
                f'netsh advfirewall firewall set rule name="blockedAddress" dir=in new remoteip={",".join(blockedAddress)} > nul'
            )

            if exitCode == 1:
                RunCommand(
                    f'netsh advfirewall firewall add rule name=blockedAddress action=block dir=in remoteip={",".join(blockedAddress)} > nul'
                )


if __name__ == "__main__":
    context = create_default_context(Purpose.CLIENT_AUTH)
    context.load_cert_chain("domain.cert", "domain.key")

    with TCPServer(
        ("0.0.0.0", int(args_result.port)), GrowtopiaRequestHandler
    ) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)

        pprint(
            "GrowtopiaRequestHandler",
            "Server is running at 0.0.0.0:" + str(args_result.port),
        )

        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pprint("KeyboardInterrupt", "Server closed.")
            _exit(0)
