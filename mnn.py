# /usr/bin/python
# TODO:
# get multiprocressing working correctly
# add reporting to file
# integrate web enumeration

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
from time import sleep
import yaml,os,argparse,subprocess,multiprocessing




parser = argparse.ArgumentParser()
parser.add_argument('-host', "--hosts", help="IP or Range you wish to scan")
args = parser.parse_args()

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

hosts = "192.168.2.0/24"
# ports = "1-3389"
commands = "-Pn -A -n -T5"
f0 = open(__location__ + '/config.yaml')
config = yaml.safe_load(f0)
f0.close()
f1 = open(__location__ + '/services-dict.yaml')
config_services = yaml.safe_load(f1)
f1.close()

def reporting(config, host, service):
    for key, value in config.items():
        print(key + value)



# checks results sent to it against a yaml dict
def service_check(host, service):
    for key, value in config_services.items():
        if service.service.startswith(key):
            if service.state == "open":
                # if the yaml dict has nmap for the matched service it will send that info to a second nmap scan with the
                nmap_script = value['nmap']
                nmap_service_scan(host, service, nmap_script)
                #scan then checks to see if there is a subprocessing value to run non-nmap tools
                if value['subproc'] is not None:
                    for command in value['subproc']:
                        subproc_command = command
                        non_nmap_cmd(subproc_command, host, service)
                else:
                    print("No Shell command for:" + service.service)



# main nmap scan function, not to be used for secondary processing
def nmap_scan(hosts, commands):
    nm = NmapProcess(hosts, commands)
    #change to sudo_run(run_as='root') to run syn scans
    nm.run_background()
    command = nm.get_command_line()
    print(command)
    while nm.is_running():
        print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nm.etc, nm.progress))
        sleep(1)
    nmap_report = NmapParser.parse(nm.stdout)
    for host in nmap_report.hosts:

        if host.status == 'up':
            for serv in host.services:
                # if serv.port == 'open':
                service_check(host, serv)
    print("Primary Scan Completed \n")

# information should be passed to this function from the original nmap_scan.
def nmap_service_scan(host, service, command):
    port = service.port
    nm = NmapProcess(host.address, options=command + " -p " + str(port))
    # change to sudo_run(run_as='root') to run syn scans
    nm.run_background()
    command = nm.get_command_line()
    print(command)
    while nm.is_running():
        print("Nmap Service Scan running:" + host.address + " : " + str(service.port) + " ETC: {0} DONE: {1}%".format(nm.etc, nm.progress))
        sleep(10)
    nmap_report = NmapParser.parse(nm.stdout)
    for host_service in nmap_report.hosts:
        for serv in host_service.services:
            pserv = "{0:>5s}/{1:3s}  {2:12s}  {3} ".format(str(serv.port),host.address, serv.protocol, serv.state, serv.service)
            print(pserv)
            for result in serv.scripts_results:
                print(result["output"])
            print("\n")


#runs shell commmands based on subproc in services-dict
def non_nmap_cmd(command, host, service):
    subproc = (str(command).format(host.address, service.port))
    print("Running:" + subproc)
    # jobs = []
    # p = multiprocessing.Process(target=subprocess.call(subproc, shell=True))
    # jobs.append(p)
    # p.start()
    # return



if __name__ == "__main__":
    nmap_scan(hosts, commands)
