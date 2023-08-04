# certificate-scanner
Tool to scan servers/networks for [soon to be] expired certificates and TLS/SSL config


Getting started
---------------

The following packages need to be installed directly via pip (or in a virtualenv):

    pip install -r requirements.txt


Running
-------

    ./certificate_scanner.py -f ip_list.txt scan



IP List Format
--------------
The list of IP addreses are IP,port definitions.

The IP address may be IPs, hostname, or network/CIDR combinations.

The ports are optional.  If not specified, ports 443, 8443, and 9443 are scanned.


Example:

    1.1.1.1,80,443,444
    2.2.2.0/24,5432
    yahoo.com


Generating reports
-------

    ./certificate_scanner.py -f ip_list.txt cert_report
    
    ./certificate_scanner.py -f ip_list.txt cert_fullreport
    
    ./certificate_scanner.py -f ip_list.txt ssl_report


Restarting
----------
The state of the scanner and entries is stored in SQLite database, therefore it is safe to stop and restart the scanner.  The scan will pick up where it left off.

