# expired-certificate-scanner
Tool to scan servers/networks for [soon to be] expired certificates


Getting started
---------------

The following packages need to be installed directly via pip (or in a virtualenv):

    pip install --upgrade setuptools
    pip install --upgrade sslyze
    pip install --upgrade sqlalchemy


Running
-------

	./expired_certificate_scanner.py hostlist.csv
    ./expired_certificate_scanner.py ip_list.txt



IP List Format
--------------
The list of IP addreses are IP,port definitions.

The IP address may be IPs, hostname, or network/CIDR combinations.

The ports are optional.  If not specified only port 443 is scanned.


Example:

    1.1.1.1,80,443,444
    2.2.2.0/24,5432
    yahoo.com


Restarting
----------
The state of the scanner and entries is stored in SQLite database, therefore it is safe to stop and restart the scanner.  The scan will pick up where it left off.

