#!/usr/bin/env python3
# Tool to scan servers/networks for [soon to be] expired certificates and TLS/SSL configuration
# Author:  Aaron W Morris <aaron@aarmor.net>


import sys
import io
import csv
import logging
import re
import time
import datetime
import ipaddress
import argparse
import enum
from pprint import pformat  # noqa: F401

from sslyze import Scanner
from sslyze import ServerNetworkLocation
from sslyze import ServerNetworkConfiguration
from sslyze import ServerScanRequest
from sslyze import ScanCommand
from sslyze import ServerScanStatusEnum
from sslyze import ScanCommandAttemptStatusEnum

import binascii
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import NameOID

from sqlalchemy.engine import Engine
from sqlalchemy import event
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy import DateTime
from sqlalchemy import Boolean
from sqlalchemy import Enum
from sqlalchemy import UniqueConstraint
from sqlalchemy import PickleType
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql.expression import false as sa_false


DEFAULT_PORT_LIST = [
    '443',
    '8443',
    '9443',
]
WARN_DAYS = 90

WORKER_POOL = 15


logging.basicConfig(level=logging.INFO)
logger = logging


logging.getLogger('sqlalchemy').setLevel(logging.WARN)

Base = declarative_base()


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    dbapi_connection.execute("PRAGMA synchronous=OFF")
    dbapi_connection.execute("PRAGMA journal_mode=MEMORY")
#    dbapi_connection.execute("PRAGMA temp_store=MEMORY")
#    dbapi_connection.execute("PRAGMA cache_size=500000")




class certificate_scanner(object):

    def __init__(self, filename):

        self.filename = filename
        self.sqlite_db = '{0:s}.sqlite'.format(filename)

        self.session = self._getDbConn()

        self.start_time = time.time()


    def __del__(self):
        elapsed = time.time() - self.start_time

        logger.warning('Runtime %0.2fs', elapsed)


    def _getDbConn(self):

        engine = create_engine('sqlite:///{0:s}'.format(self.sqlite_db), echo=False)
        #engine = create_engine('mysql+mysqldb://sslscan:sslscan@localhost/sslscan', echo=False)
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)

        return Session()


    def get_connections(self):
        file_o = open(self.filename, 'r')

        entry_count = 0
        for line in file_o:
            if re.search(r'^#', line):
                continue

            if re.search(r'^$', line):
                continue

            host_info = line.rstrip().split(',')

            address = host_info[0]
            port_list = host_info[1:]


            # if no ports specified, use default list
            if not port_list:
                port_list = DEFAULT_PORT_LIST


            # This coule be an ip address or ip/cidr
            if re.search(r'^\d+\.\d+\.\d+\.\d+', address):
                logger.info('IPv4 address detected')
                network = ipaddress.ip_network(address, strict=False)

                address_list = network

            elif re.search(r'^[0-9abcdef]*:[0-9abcdef]*:[0-9abcdef]*', address, re.IGNORECASE):
                logger.info('IPv6 address detected')
                network = ipaddress.ip_network(address, strict=False)

                # A large ipv6 subnet may never finish
                if network.prefixlen < 122:
                    logger.warning('Only scanning first 100 IPv6 addresses for %s', address)
                    address_list = [network[x] for x in range(100)]
                else:
                    address_list = network

            else:
                address_list = [address]


            # Loop through hosts and ports
            for host in address_list:
                for port in port_list:
                    # Add entries to DB
                    entry = {
                        'host' : str(host),
                        'port' : int(port),
                    }

                    try:
                        self.session.bulk_insert_mappings(ScanEntry, [entry])
                        self.session.commit()
                        entry_count = entry_count + 1
                    except IntegrityError:
                        logger.info('Duplicate entry: %s:%s', host, port)
                        self.session.rollback()
                        continue



        logger.warning('%d services added to queue', entry_count)

        file_o.close()


    def sslyzeScan(self):
        scanner = Scanner(concurrent_server_scans_limit=WORKER_POOL)

        # Get entries from DB
        open_query = self.session.query(ScanEntry).filter(ScanEntry.state == ScanState.INITIAL)

        logger.warning('Scanning %d open ports', open_query.count())


        scan_list = list()
        for entry in open_query:
            #logger.info('Creating location')
            server_location = ServerNetworkLocation(entry.host, ip_address=entry.host, port=entry.port)
            network_configuration = ServerNetworkConfiguration(entry.host, network_timeout=2)

            scan_req = ServerScanRequest(
                server_location=server_location,
                network_configuration=network_configuration,
                scan_commands=[
                    ScanCommand.CERTIFICATE_INFO,
                    ScanCommand.SSL_2_0_CIPHER_SUITES,
                    ScanCommand.SSL_3_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_1_CIPHER_SUITES,
                    ScanCommand.TLS_1_2_CIPHER_SUITES,
                    ScanCommand.TLS_1_3_CIPHER_SUITES,
                ]
            )


            scan_list.append(scan_req)


        if len(scan_list) == 0:
            logger.error('All scans complete')
            sys.exit(1)

        logger.info('Queuing scans')
        scanner.queue_scans(scan_list)



        for scan_result in scanner.get_results():
            #logger.info('Scan result: %s', pformat(scan_result))

            hostname = scan_result.server_location.hostname
            port = scan_result.server_location.port

            # fetch scan entry from DB
            scan_entry = self.session.query(ScanEntry)\
                .filter(ScanEntry.host == hostname)\
                .filter(ScanEntry.port == port)\
                .first()


            logger.info('Updating scan entry: %d', scan_entry.id)

            if scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
                logger.error('Error at %s:%d', scan_entry.host, scan_entry.port)
                #logger.error('Error: %d', scan_result)

                scan_entry.error = 'no connectivity'
                scan_entry.state = ScanState.NOTOPEN
                self.session.commit()

                continue


            ### Certificate info ###
            certificate_info = scan_result.scan_result.certificate_info
            if certificate_info.status == ScanCommandAttemptStatusEnum.ERROR:
                logger.error('Error at %s:%d', scan_entry.host, scan_entry.port)
                #logger.error('Error: %d', scan_result)

                scan_entry.error = 'unknown error'
                scan_entry.state = ScanState.ERROR
                self.session.commit()

                continue


            self.getCertificateInfo(scan_entry, scan_result)
            self.getSslInfo(scan_entry, scan_result)

            scan_entry.state = ScanState.COMPLETE
            self.session.commit()


    def getCertificateInfo(self, scan_entry, scan_result):
        certificate_info = scan_result.scan_result.certificate_info

        # Print the Common Names within the certificate chain
        cert_deployment_0 = certificate_info.result.certificate_deployments[0]

        #configured_certificate_chain = [cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        #                                for cert in cert_deployment_0.received_certificate_chain]
        #logger.info('Configured Chain: %s', configured_certificate_chain)

        fingerprint = binascii.hexlify(cert_deployment_0.received_certificate_chain[0].fingerprint(hashes.SHA1())).decode('ascii')
        #logger.info('Fingerprint: %s', fingerprint)


        try:
            cn = cert_deployment_0.received_certificate_chain[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            logger.error('Certificate CN error')
            cn = 'CN ERROR'

        try:
            issuer = cert_deployment_0.received_certificate_chain[0].issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            logger.error('Certificate issuer error')
            issuer = 'ISSUER ERROR'

        expire = cert_deployment_0.received_certificate_chain[0].not_valid_after

        scan_entry.cn = cn
        scan_entry.issuer = issuer
        scan_entry.expire = expire
        scan_entry.fingerprint = fingerprint

        if cn == issuer:
            scan_entry.selfsigned = True

        self.session.commit()


    def getSslInfo(self, scan_entry, scan_result):
        ### SSL info ###

        ssl_2_0 = scan_result.scan_result.ssl_2_0_cipher_suites
        if not isinstance(ssl_2_0.result, type(None)):
            if len(ssl_2_0.result.accepted_cipher_suites) > 0:
                ssl_2_0_cipher_list = [x.cipher_suite.name for x in ssl_2_0.result.accepted_cipher_suites]
                #logger.info('SSL 2: %s', pformat(ssl_2_0_cipher_list))
                scan_entry.sslv2_0 = ','.join(ssl_2_0_cipher_list)
            else:
                #logger.info('SSLv2 disabled')
                scan_entry.sslv2_0 = 'disabled'
        else:
            scan_entry.sslv2_0 = 'no_scan'


        ssl_3_0 = scan_result.scan_result.ssl_3_0_cipher_suites
        if not isinstance(ssl_3_0.result, type(None)):
            if len(ssl_3_0.result.accepted_cipher_suites) > 0:
                ssl_3_0_cipher_list = [x.cipher_suite.name for x in ssl_3_0.result.accepted_cipher_suites]
                #logger.info('SSL 3: %s', pformat(ssl_3_0_cipher_list))
                scan_entry.sslv3_0 = ','.join(ssl_3_0_cipher_list)
            else:
                #logger.info('SSLv3 disabled')
                scan_entry.sslv3_0 = 'disabled'
        else:
            scan_entry.sslv3_0 = 'no_scan'


        tls_1_0 = scan_result.scan_result.tls_1_0_cipher_suites
        if not isinstance(tls_1_0.result, type(None)):
            if len(tls_1_0.result.accepted_cipher_suites) > 0:
                tls_1_0_cipher_list = [x.cipher_suite.name for x in tls_1_0.result.accepted_cipher_suites]
                #logger.info('TLS 1: %s', pformat(tls_1_0_cipher_list))
                scan_entry.tlsv1_0 = ','.join(tls_1_0_cipher_list)
            else:
                #logger.info('TLSv1.0 disabled')
                scan_entry.tlsv1_0 = 'disabled'
        else:
            scan_entry.tlsv1_0 = 'no_scan'


        tls_1_1 = scan_result.scan_result.tls_1_1_cipher_suites
        if not isinstance(tls_1_1.result, type(None)):
            if len(tls_1_1.result.accepted_cipher_suites) > 0:
                tls_1_1_cipher_list = [x.cipher_suite.name for x in tls_1_1.result.accepted_cipher_suites]
                #logger.info('TLS 1.1: %s', pformat(tls_1_1_cipher_list))
                scan_entry.tlsv1_1 = ','.join(tls_1_1_cipher_list)
            else:
                #logger.info('TLSv1.1 disabled')
                scan_entry.tlsv1_1 = 'disabled'
        else:
            scan_entry.tlsv1_1 = 'no_scan'


        tls_1_2 = scan_result.scan_result.tls_1_2_cipher_suites
        if not isinstance(tls_1_2.result, type(None)):
            if len(tls_1_2.result.accepted_cipher_suites) > 0:
                tls_1_2_cipher_list = [x.cipher_suite.name for x in tls_1_2.result.accepted_cipher_suites]
                #logger.info('TLS 1.2: %s', pformat(tls_1_2_cipher_list))
                scan_entry.tlsv1_2 = ','.join(tls_1_2_cipher_list)
            else:
                #logger.info('TLSv1.2 disabled')
                scan_entry.tlsv1_2 = 'disabled'
        else:
            scan_entry.tlsv1_2 = 'no_scan'


        tls_1_3 = scan_result.scan_result.tls_1_3_cipher_suites
        if not isinstance(tls_1_3.result, type(None)):
            if len(tls_1_3.result.accepted_cipher_suites) > 0:
                tls_1_3_cipher_list = [x.cipher_suite.name for x in tls_1_3.result.accepted_cipher_suites]
                #logger.info('TLS 1.3: %s', pformat(tls_1_3_cipher_list))
                scan_entry.tlsv1_3 = ','.join(tls_1_3_cipher_list)
            else:
                #logger.info('TLSv1.3 disabled')
                scan_entry.tlsv1_3 = 'disabled'
        else:
            scan_entry.tlsv1_3 = 'no_scan'


        self.session.commit()


    def scan(self, days):
        # Bypass loading entries if already populated
        all_query = self.session.query(ScanEntry)
        if all_query.count() == 0:
            logger.warning('Loading data into DB')
            self.get_connections()


        # Run the sslyze scans against open ports
        self.sslyzeScan()


    def cert_report(self, days):
        now = datetime.datetime.now()
        warn_date = now + datetime.timedelta(days=days)

        query = self.session.query(ScanEntry)\
            .filter(ScanEntry.expire <= warn_date)\
            .filter(ScanEntry.selfsigned == sa_false())\
            .order_by(ScanEntry.expire)


        now_str = now.strftime('%y%m%d_%H%M%S')
        with io.open('results_cert_{0:s}_{1:s}.csv'.format(self.filename, now_str), 'w') as output_o:
            csvwriter = csv.writer(output_o)

            csvwriter.writerow(['#host:port', 'cn', 'expire', 'days', 'issuer'])

            for entry in query:
                time_remaining = entry.expire - now

                csvwriter.writerow([
                    '{0:s}:{1:d}'.format(entry.host, entry.port),
                    entry.cn,
                    entry.expire,
                    time_remaining.days,
                    entry.issuer,
                ])


            logger.warning('Report: %s', output_o.name)


    def cert_fullreport(self, days):
        now = datetime.datetime.now()

        query = self.session.query(ScanEntry)\
            .filter(ScanEntry.state == ScanState.COMPLETE)\
            .order_by(ScanEntry.expire)


        now_str = now.strftime('%y%m%d_%H%M%S')
        with io.open('results_cert_{0:s}_{1:s}.csv'.format(self.filename, now_str), 'w') as output_o:
            csvwriter = csv.writer(output_o)

            csvwriter.writerow(['#host:port', 'cn', 'fingerprint', 'selfsigned', 'expire', 'days', 'issuer'])


            for entry in query:
                time_remaining = entry.expire - now
                if entry.selfsigned:
                    selfsigned = 'True'
                else:
                    selfsigned = ''

                csvwriter.writerow([
                    '{0:s}:{1:d}'.format(entry.host, entry.port),
                    entry.cn,
                    entry.fingerprint,
                    selfsigned,
                    entry.expire,
                    time_remaining.days,
                    entry.issuer,
                ])


            logger.warning('Report: %s', output_o.name)


    def ssl_report(self, days):
        self.tls_report(days)


    def tls_report(self, days):
        now = datetime.datetime.now()

        query = self.session.query(ScanEntry)\
            .filter(ScanEntry.state == ScanState.COMPLETE)


        now_str = now.strftime('%y%m%d_%H%M%S')
        with io.open('results_tls_{0:s}_{1:s}.csv'.format(self.filename, now_str), 'w') as output_o:
            csvwriter = csv.writer(output_o)

            csvwriter.writerow(['#host:port', 'cn', 'tlsv1_3', 'tlsv1_2', 'tlsv1_1', 'tlsv1_0', 'sslv3_0', 'sslv2_0'])


            for entry in query:
                if not entry.tlsv1_3:
                    tlsv1_3 = 'no_data'
                elif entry.tlsv1_3 == 'no_scan':
                    tlsv1_3 = 'no_scan'
                elif entry.tlsv1_3 == 'disabled':
                    tlsv1_3 = 'disabled'
                else:
                    tlsv1_3 = 'x'


                if not entry.tlsv1_2:
                    tlsv1_2 = 'no_data'
                elif entry.tlsv1_2 == 'no_scan':
                    tlsv1_2 = 'no_scan'
                elif entry.tlsv1_2 == 'disabled':
                    tlsv1_2 = ''
                else:
                    tlsv1_2 = 'x'


                if not entry.tlsv1_1:
                    tlsv1_1 = 'no_data'
                elif entry.tlsv1_1 == 'no_scan':
                    tlsv1_1 = 'no_scan'
                elif entry.tlsv1_1 == 'disabled':
                    tlsv1_1 = ''
                else:
                    tlsv1_1 = 'x'


                if not entry.tlsv1_0:
                    tlsv1_0 = 'no_data'
                elif entry.tlsv1_0 == 'no_scan':
                    tlsv1_0 = 'no_scan'
                elif entry.tlsv1_0 == 'disabled':
                    tlsv1_0 = ''
                else:
                    tlsv1_0 = 'x'


                if not entry.sslv3_0:
                    sslv3_0 = 'no_data'
                elif entry.sslv3_0 == 'no_scan':
                    sslv3_0 = 'no_scan'
                elif entry.sslv3_0 == 'disabled':
                    sslv3_0 = ''
                else:
                    sslv3_0 = 'x'


                if not entry.sslv2_0:
                    sslv2_0 = 'no_data'
                elif entry.sslv2_0 == 'no_scan':
                    sslv2_0 = 'no_scan'
                elif entry.sslv2_0 == 'disabled':
                    sslv2_0 = ''
                else:
                    sslv2_0 = 'x'


                csvwriter.writerow([
                    '{0:s}:{1:d}'.format(entry.host, entry.port),
                    entry.cn,
                    tlsv1_3,
                    tlsv1_2,
                    tlsv1_1,
                    tlsv1_0,
                    sslv3_0,
                    sslv2_0,
                ])


            logger.warning('Report: %s', output_o.name)



class ScanState(enum.Enum):
    INITIAL  = 'initial'
    COMPLETE = 'complete'
    ERROR    = 'error'
    NOTOPEN  = 'notopen'


class ScanEntry(Base):
    __tablename__ = 'scanentry'

    id            = Column(Integer, primary_key=True)
    state         = Column(Enum(ScanState, length=20, native_enum=False), default=ScanState.INITIAL, index=True)
    host          = Column(String(length=100), nullable=False, index=True)
    port          = Column(Integer, nullable=False, index=True)
    selfsigned    = Column(Boolean, default=False, index=True)
    cn            = Column(String(length=100), index=True)
    issuer        = Column(String(length=100), index=True)
    expire        = Column(DateTime, index=True)
    #test_result   = Column(Text)
    test_result   = Column(PickleType)
    fingerprint   = Column(String(length=41))
    sslv2_0       = Column(Text)
    sslv3_0       = Column(Text)
    tlsv1_0       = Column(Text)
    tlsv1_1       = Column(Text)
    tlsv1_2       = Column(Text)
    tlsv1_3       = Column(Text)
    error         = Column(Text)

    __table_args__ = (UniqueConstraint('host', 'port', name='_hostport_uc'),)



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        help="action",
        choices=[
            'scan',
            'cert_report',
            'cert_fullreport',
            'ssl_report',
            'tls_report',
        ],
    )
    parser.add_argument(
        "--file",
        "-f",
        help="file",
        required=True,
        type=str,
    )
    parser.add_argument(
        "--days",
        "-d",
        help="days",
        required=False,
        type=int,
        default=WARN_DAYS,
    )

    args = parser.parse_args()

    cs = certificate_scanner(
        args.file,
    )

    action_function = getattr(cs, args.action)
    action_function(
        days=args.days
    )

