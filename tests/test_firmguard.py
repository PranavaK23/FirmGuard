import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import sqlite3
import stat
import struct
import sys
import tarfile
import tempfile
import threading
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT)]
from fastapi.testclient import TestClient
from pypdf import PdfReader
import history
import jobs
import main
from analysis import analyse
from binwalk_adapter import extract
from elfcheck import analyse_elf
from integrity import check_integrity
from inventory import check_versions, inventory
from scanner import scan_configuration, scan_credentials
from settings import AnalysisError
from scripts.make_samples import elf_fixture
from unpack import Unpacker, safe_name

def zip_bytes(entries):
    output=io.BytesIO()
    with zipfile.ZipFile(output,"w",zipfile.ZIP_DEFLATED) as z:
        for path,data in entries: z.writestr(path,data)
    return output.getvalue()

def tar_bytes(entries, special=None):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode="w") as t:
        for path,data in entries:
            member=tarfile.TarInfo(path);member.size=len(data);member.mode=0o644
            t.addfile(member,io.BytesIO(data))
        if special:
            member=tarfile.TarInfo("bad");member.type=special;member.linkname="../../outside";t.addfile(member)
    return output.getvalue()

class ExtractionTests(unittest.TestCase):
    def test_real_archives_not_just_extensions(self):
        archive=zip_bytes([("etc/a.conf",b"password=dummy"),("bin/a",elf_fixture())])
        result=analyse(archive,"firmware.bin")
        self.assertEqual(result["extraction"]["input_format"],"zip")
        self.assertEqual(result["files_scanned"],2)
        self.assertEqual(len(result["elf"]),1)

    def test_all_native_compression_formats(self):
        archive=tar_bytes([("etc/a.conf",b"password=dummy")])
        for compress in [lambda b:b,gzip.compress,bz2.compress,lzma.compress]:
            with self.subTest(compress=compress):
                items=Unpacker().unpack(compress(archive),"release.bin")
                self.assertEqual(items[0].path,"etc/a.conf")
                self.assertEqual(items[0].data,b"password=dummy")

    def test_nested_zip_paths(self):
        archive=zip_bytes([("root/nested.zip",zip_bytes([("etc/a",b"setting=1")]))])
        self.assertEqual(Unpacker().unpack(archive,"top.zip")[0].path,"root/nested.zip!/etc/a")

    def test_traversal_and_windows_paths(self):
        for path in ["../outside","/outside","C:\\outside","a/../x","a\\..\\x","NUL.txt","a:stream","a//x","a/./x","a. ","a\x00x","a!/x"]:
            with self.subTest(path=path), self.assertRaises(AnalysisError): safe_name(path)

    def test_links_and_special_tar_files(self):
        for special in [tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.FIFOTYPE,tarfile.CHRTYPE,tarfile.BLKTYPE]:
            with self.subTest(special=special), self.assertRaises(AnalysisError):
                Unpacker().unpack(tar_bytes([],special),"a.tar")

    def test_zip_symlink(self):
        output=io.BytesIO()
        with zipfile.ZipFile(output,"w") as z:
            entry=zipfile.ZipInfo("link");entry.create_system=3;entry.external_attr=(stat.S_IFLNK|0o777)<<16
            z.writestr(entry,"../../outside")
        with self.assertRaises(AnalysisError):Unpacker().unpack(output.getvalue(),"a.zip")

    def test_encrypted_zip(self):
        data=bytearray(zip_bytes([("a",b"hello")]))
        for signature,offset in [(b"PK\x03\x04",6),(b"PK\x01\x02",8)]:
            start=data.index(signature);flags=struct.unpack_from("<H",data,start+offset)[0]
            struct.pack_into("<H",data,start+offset,flags|1)
        with self.assertRaises(AnalysisError):Unpacker().unpack(bytes(data),"a.zip")

    def test_duplicates_case_collisions_and_decompression_collisions(self):
        for data in [zip_bytes([("a",b"1"),("A",b"2")]),zip_bytes([("a",b"1"),("a.gz",gzip.compress(b"2"))])]:
            with self.subTest(data_size=len(data)),self.assertRaises(AnalysisError):analyse(data,"a.zip")

    def test_empty_and_damaged_archive(self):
        for data,name in [(zip_bytes([]),"a.zip"),(b"bad zip","a.zip"),(b"\x1f\x8btruncated","a.gz")]:
            with self.subTest(name=name),self.assertRaises(AnalysisError):analyse(data,name)

    def test_expansion_budget(self):
        data=zip_bytes([("bomb",b"x"*200)])
        with patch("unpack.MAX_EXPANDED",100),self.assertRaises(AnalysisError) as caught:Unpacker().unpack(data,"a.zip")
        self.assertEqual(caught.exception.status,413)

    def test_single_file_budget(self):
        with patch("unpack.MAX_FILE",100),self.assertRaises(AnalysisError):Unpacker().unpack(zip_bytes([("a",b"x"*101)]),"a.zip")

    def test_stream_decompression_budget(self):
        with patch("unpack.MAX_EXPANDED",100),self.assertRaises(AnalysisError):Unpacker().unpack(gzip.compress(b"x"*101),"a.gz")

    def test_entry_and_nesting_limits(self):
        with patch("unpack.MAX_ENTRIES",2),self.assertRaises(AnalysisError):Unpacker().unpack(zip_bytes([(str(i),b"x") for i in range(3)]),"a.zip")
        data=b"payload"
        for _ in range(5):data=zip_bytes([("nested",data)])
        with self.assertRaises(AnalysisError):Unpacker().unpack(data,"a.zip")

    def test_tar_conventional_dot_prefix(self):
        self.assertEqual(Unpacker().unpack(tar_bytes([("./etc/a",b"x")]),"a.tar")[0].path,"etc/a")

    def test_raw_binary_partial_coverage(self):
        r=analyse(b"\x00\xffpassword=PRIVATE_123\x00OpenSSL 1.0.1f\x00","router.bin")
        self.assertEqual(r["coverage"],"partial")
        self.assertNotIn("PRIVATE_123",json.dumps(r))
        self.assertIsNone(r["findings"][0]["line"])
        self.assertIn("offset",r["findings"][0])

    def test_large_file_text_coverage_is_explicit(self):
        with patch("analysis.MAX_TEXT",10): r=analyse(b"a"*20,"a.bin")
        self.assertEqual(r["coverage"],"partial")
        self.assertEqual(r["manifest"][0]["sha256"],hashlib.sha256(b"a"*20).hexdigest())

class RuleTests(unittest.TestCase):
    def test_sample_credentials(self):
        r=analyse((ROOT/"samples/unsafe_config.txt").read_bytes(),"unsafe.txt")
        self.assertEqual(r["finding_count"],3)
        self.assertTrue(all(f["masked_value"]=="********" for f in r["findings"]))
        self.assertEqual(analyse((ROOT/"samples/safe_config.txt").read_bytes(),"safe.txt")["finding_count"],0)

    def test_comment_quotes_and_placeholders(self):
        text='# password=ignored\nPASSWORD="literal value"\n{"api_key":"secret"}\nwifi_password: value\npassword=""\npassword=${PASSWORD}\npassword=null\nnot_password=abc\n'
        found=scan_credentials(text,"a")
        self.assertEqual([f["line"] for f in found],[2,3,4])
        self.assertNotIn("literal value",json.dumps(found))

    def test_private_key(self):
        found=scan_credentials("-----BEGIN RSA PRIVATE KEY-----\nSENSITIVE_KEY_MATERIAL", "key.pem")
        self.assertEqual(found[0]["rule_id"],"CRED-002")
        self.assertNotIn("SENSITIVE_KEY_MATERIAL",json.dumps(found))

    def test_configuration_rules_and_scope(self):
        text="PermitRootLogin yes\nPermitEmptyPasswords yes\nPasswordAuthentication yes\nProtocol 1\n"
        self.assertEqual(len(scan_configuration(text,"etc/ssh/sshd_config")),4)
        self.assertEqual(scan_configuration(text,"notes.txt"),[])
        self.assertEqual(scan_configuration("# telnet_enabled=true\n","config"),[])

    def test_configuration_miscellaneous_and_permissions(self):
        text="telnet_enabled=true\nssl_verify=false\ndebug=true\nrocommunity public\nnet.ipv4.ip_forward=1"
        self.assertEqual(len(scan_configuration(text,"config",0o666)),6)
        self.assertEqual(scan_configuration("", "bin/a",0o4755)[0]["rule_id"],"CONF-PRIVILEGED")

    def test_conditional_ssh_is_marked(self):
        r=scan_configuration("Match User root\nPermitRootLogin yes", "sshd_config")
        self.assertIn("conditional",r[0]["explanation"])

    def test_account_fields_are_not_exposed(self):
        r=scan_configuration("PRIVATE_NAME::0:0:root:/root:/bin/sh", "etc/shadow")
        self.assertEqual(r[0]["rule_id"],"CONF-ACCOUNT-EMPTY")
        self.assertNotIn("PRIVATE_NAME",json.dumps(r))
        self.assertEqual(scan_configuration("root:!:0:0", "shadow"),[])
        self.assertEqual(scan_configuration("root:$6$SENSITIVE:0:0", "passwd")[0]["rule_id"],"CONF-PASSWD-HASH")

    def test_inventory_package_metadata_and_eight_families(self):
        c=inventory("Package: openssl\nVersion: 1.0.1f\n\nPackage: unrecognized\nVersion: 1.2.3\n", "var/lib/opkg/status")
        self.assertEqual(len(c),1);self.assertEqual(c[0]["source"],"package")
        text="OpenSSL 1.0.1f BusyBox v1.36.1 dropbear_2022.83 dnsmasq-2.77 OpenSSH_8.9p1 curl/7.88.1 zlib 1.2.13 uClibc 0.9.33"
        self.assertEqual(len(inventory(text,"versions")),8)

    def test_advisory_boundaries_and_vendor_suffix(self):
        cases={"1.0.0":False,"1.0.1":True,"1.0.1f":True,"1.0.1g":False,"1.0.2":False,"1.0.1f-vendor":False}
        for version,expected in cases.items():
            c=[{"product":"OpenSSL","version":version,"filename":"x"}]
            findings,_=check_versions(c)
            self.assertEqual(bool(findings),expected,version)
            if "vendor" in version:self.assertEqual(c[0]["check_status"],"unmapped_version")
        for version,expected in [("2.77",True),("2.78",False)]:
            self.assertEqual(bool(check_versions([{"product":"dnsmasq","version":version,"filename":"x"}])[0]),expected)

    def test_finding_limit_fails_instead_of_silent_truncation(self):
        with patch("analysis.MAX_FINDINGS",1),self.assertRaises(AnalysisError):analyse(b"password=a\npassword=b", "a.conf")

    def test_sha256_exact_bytes_and_reference(self):
        source=b"a\r\n";digest=hashlib.sha256(source).hexdigest()
        self.assertEqual(check_integrity(source,digest.upper())["status"],"match")
        self.assertEqual(check_integrity(source,b"".hex().zfill(64))["status"],"mismatch")
        self.assertEqual(check_integrity(source)["status"],"not_compared")
        with self.assertRaises(ValueError):check_integrity(source,"not a hash")

class ELFTests(unittest.TestCase):
    def test_canary_and_fortify_symbol_evidence(self):
        # Undefined dynamic symbols are normal imported functions in an ELF executable.
        data=bytearray(elf_fixture())
        strings=b"\x00__stack_chk_fail\x00__memcpy_chk\x00"
        str_offset=len(data);data.extend(strings)
        sym_offset=len(data)
        data.extend(bytes(24))
        for name_offset in [1,18]:data.extend(struct.pack("<IBBHQQ",name_offset,0x12,0,0,0,0))
        names=b"\x00.dynstr\x00.dynsym\x00.shstrtab\x00"
        names_offset=len(data);data.extend(names)
        section_offset=len(data)
        sections=[(0,0,0,0,0,0,0,0,0,0),(1,3,2,0,str_offset,len(strings),0,0,1,0),
            (9,11,2,0,sym_offset,72,1,1,8,24),(17,3,0,0,names_offset,len(names),0,0,1,0)]
        for section in sections:data.extend(struct.pack("<IIQQQQIIQQ",*section))
        struct.pack_into("<Q",data,40,section_offset);struct.pack_into("<HH",data,60,4,3)
        result,_=analyse_elf(bytes(data),"bin/symbols")
        self.assertEqual(result["stack_canary"],"detected")
        self.assertEqual(result["fortify"],"detected")

    def test_unhardened_executable(self):
        r,f=analyse_elf(elf_fixture(),"bin/test")
        self.assertEqual((r["nx"],r["pie"],r["relro"]),("disabled","disabled","none"))
        self.assertEqual({i["rule_id"] for i in f},{"ELF-NX","ELF-PIE","ELF-RELRO"})
        self.assertEqual(r["stack_canary"],"unknown")

    def test_hardened_32_64_little_big(self):
        for bits in [32,64]:
            for endian in ["little","big"]:
                with self.subTest(bits=bits,endian=endian):
                    r,f=analyse_elf(elf_fixture(True,bits,endian),"bin/test")
                    self.assertEqual((r["class"],r["endian"]),(bits,endian))
                    self.assertEqual((r["nx"],r["pie"],r["relro"]),("enabled","enabled","full"))
                    self.assertEqual(f,[])

    def test_shared_library_not_reported_as_no_pie(self):
        r,f=analyse_elf(elf_fixture(shared=True),"lib/a.so")
        self.assertEqual(r["pie"],"not_applicable")
        self.assertNotIn("ELF-PIE",[i["rule_id"] for i in f])

    def test_missing_stack_header_unknown(self):
        data=bytearray(elf_fixture());struct.pack_into("<H",data,56,0)
        self.assertEqual(analyse_elf(bytes(data),"bin/a")[0]["nx"],"unknown")

    def test_malformed_elf_explicitly_partial(self):
        result=analyse(b"\x7fELFbroken", "bad.elf")
        self.assertEqual(result["coverage"],"partial")
        self.assertEqual(result["elf"][0]["status"],"unreadable")

class APITests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.db_patch=patch.object(history,"DB_PATH",Path(self.tmp.name)/"scans.db");self.db_patch.start()
        self.client=TestClient(main.app);self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None,None,None);self.db_patch.stop();self.tmp.cleanup()

    def upload(self,data=b"password=UNIQUE_TEST_SECRET",name="config.conf",**fields):
        return self.client.post("/api/scans",files={"file":(name,data)},data={"device":"Lab router","version":"v1",**fields})

    def saved(self,**options):
        response=self.upload(**options);self.assertEqual(response.status_code,202,response.text)
        scan=self.client.get(f'/api/scans/{response.json()["id"]}').json()
        self.assertEqual(scan["status"],"completed",scan)
        return scan

    def test_health_version(self):
        r=self.client.get("/api/health")
        self.assertEqual(r.status_code,200);self.assertEqual(r.json()["version"],"1.0.0")
        self.assertIn("binwalk",r.json())

    def test_saved_record_privacy_and_exports(self):
        record=self.saved()
        self.assertEqual(record["progress"],100)
        self.assertNotIn("UNIQUE_TEST_SECRET",json.dumps(record))
        self.assertNotIn(b"UNIQUE_TEST_SECRET",history.DB_PATH.read_bytes())
        export=self.client.get(f'/api/scans/{record["id"]}/export')
        self.assertEqual(export.status_code,200);self.assertNotIn("UNIQUE_TEST_SECRET",export.text)
        pdf=self.client.get(f'/api/scans/{record["id"]}/report.pdf')
        self.assertTrue(pdf.content.startswith(b"%PDF"))
        text="\n".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf.content)).pages)
        self.assertIn("Hardcoded password",text);self.assertNotIn("UNIQUE_TEST_SECRET",text)
        self.assertIn(record["result"]["integrity"]["sha256"],text.replace("\n",""))

    def test_revision_is_immutable_and_not_reused_after_delete(self):
        a,b=self.saved(),self.saved(data=b"password=different")
        self.assertEqual((a["revision"],b["revision"]),(1,2))
        self.assertEqual(self.client.get(f'/api/scans/{a["id"]}').json()["result"],a["result"])
        self.assertEqual(self.client.delete(f'/api/scans/{b["id"]}').status_code,204)
        self.assertEqual(self.saved()["revision"],3)

    def test_comparison_findings_and_secret_rotation(self):
        a=self.saved(data=b"password=one\nwifi_password=two")
        b=self.saved(data=b"# moved\nwifi_password=rotated\napi_key=three",version="v2")
        r=self.client.get(f'/api/compare?baseline={a["id"]}&candidate={b["id"]}').json()
        self.assertEqual(r["counts"],{"new":1,"still_present":1,"no_longer_detected":1})
        self.assertEqual(r["file_counts"]["changed"],1)

    def test_full_firmware_comparison_and_pdf(self):
        a=self.saved(data=(ROOT/"samples/firmware_v1.zip").read_bytes(),name="v1.zip")
        b=self.saved(data=(ROOT/"samples/firmware_v2.tar.gz").read_bytes(),name="v2.tar.gz",version="v2")
        query=f'baseline={a["id"]}&candidate={b["id"]}'
        response=self.client.get('/api/compare?'+query);self.assertEqual(response.status_code,200,response.text)
        result=response.json();self.assertEqual(result["file_counts"],{"added":1,"removed":1,"changed":5,"unchanged":0})
        self.assertEqual(len(result["software_changes"]),3)
        pdf=self.client.get('/api/compare/report.pdf?'+query)
        self.assertGreater(len(PdfReader(io.BytesIO(pdf.content)).pages),1)

    def test_different_scope_device_rules_and_same_id_rejected(self):
        a=self.saved();b=self.saved(device="Other")
        for left,right in [(a,b),(a,a)]:
            self.assertEqual(self.client.get(f'/api/compare?baseline={left["id"]}&candidate={right["id"]}').status_code,400)
        c=self.saved(data=zip_bytes([("config",b"password=x")]),name="a.zip")
        self.assertEqual(self.client.get(f'/api/compare?baseline={a["id"]}&candidate={c["id"]}').status_code,400)
        d=self.saved();d["result"]["scanner_version"]="old"
        history.update_scan(d["id"],"completed","Completed",100,d["result"])
        self.assertEqual(self.client.get(f'/api/compare?baseline={a["id"]}&candidate={d["id"]}').status_code,400)

    def test_failed_extraction_is_visible_and_cannot_export(self):
        accepted=self.upload(data=zip_bytes([("../outside",b"private")]),name="bad.zip")
        self.assertEqual(accepted.status_code,202)
        scan_id=accepted.json()["id"];record=self.client.get(f'/api/scans/{scan_id}').json()
        self.assertEqual(record["status"],"failed");self.assertIn("unsafe",record["error"])
        self.assertEqual(self.client.get(f'/api/scans/{scan_id}/report.pdf').status_code,409)

    def test_validation_does_not_echo_input(self):
        for fields in [{"device":" "},{"version":"x"*41},{"expected_sha256":"SECRET_BAD_HASH"},{"use_binwalk":"SECRET_NOT_BOOL"}]:
            with self.subTest(fields=fields):
                r=self.upload(**fields);self.assertIn(r.status_code,[400,422]);self.assertNotIn("SECRET_",r.text)
        self.assertEqual(self.client.post("/api/scans",data={"device":"SECRET_VALUE"}).status_code,422)
        self.assertEqual(self.client.get("/api/scans?limit=-1").status_code,422)
        self.assertEqual(self.client.get("/api/compare?baseline=0&candidate=1").status_code,422)
        self.assertEqual(self.client.get("/api/scans").json()["total"],0)

    def test_empty_oversize_and_unsafe_upload_name(self):
        for data,name,status_code in [(b"","a",400),(b"a","CON",400)]:
            self.assertEqual(self.upload(data=data,name=name).status_code,status_code)
        with patch.object(main,"MAX_UPLOAD",10):self.assertEqual(self.upload(data=b"x"*11).status_code,413)

    def test_request_body_limit_without_content_length(self):
        with patch.object(main,"MAX_UPLOAD",10):
            r=self.client.post("/api/scan",content=(b"x"*65536 for _ in range(18)),headers={"Content-Type":"multipart/form-data; boundary=test"})
        self.assertEqual(r.status_code,413)

    def test_local_origin_and_host_restrictions(self):
        self.assertEqual(self.client.post("/api/scan",headers={"origin":"https://foreign.example"}).status_code,403)
        self.assertEqual(self.client.get("/api/health",headers={"host":"foreign.example"}).status_code,400)
        self.assertEqual(self.client.post("/api/scan",headers={"host":"127.0.0.1:8765","origin":"http://127.0.0.1:8765"},files={"file":("a.txt",b"setting=1")}).status_code,200)

    def test_pagination_and_exact_device_filter(self):
        self.saved(device="A");self.saved(device="B")
        result=self.client.get("/api/scans?limit=1&offset=1").json()
        self.assertEqual((len(result["items"]),result["total"]),(1,2))
        self.assertEqual(self.client.get("/api/scans?device=A").json()["total"],1)

    def test_interrupted_records_and_active_deletion(self):
        scan_id=history.create_scan("Lab","v1",{"filename":"a"})
        self.assertEqual(self.client.delete(f'/api/scans/{scan_id}').status_code,409)
        history.interrupt_unfinished()
        self.assertEqual(self.client.get(f'/api/scans/{scan_id}').json()["status"],"interrupted")
        self.assertEqual(self.client.delete(f'/api/scans/{scan_id}').status_code,204)

    def test_missing_records(self):
        self.assertEqual(self.client.get("/api/scans/999").status_code,404)
        self.assertEqual(self.client.delete("/api/scans/999").status_code,404)

    def test_worker_failure_is_sanitized(self):
        response=self.client.post("/api/scan",files={"file":("bad.gz",b"\x1f\x8bprivate_invalid")})
        self.assertEqual(response.status_code,400)
        self.assertNotIn("private_invalid",response.text)

    def test_job_capacity_rejects_cleanly(self):
        with patch.object(main,"SLOTS") as slots:
            slots.acquire.return_value=False
            self.assertEqual(self.upload().status_code,429)
        self.assertEqual(self.client.get("/api/scans").json()["total"],0)

    def test_status_remains_readable_while_worker_runs(self):
        entered,release=threading.Event(),threading.Event()
        actual=jobs.execute
        def controlled(*args,**kwargs):
            entered.set()
            if not release.wait(10):raise RuntimeError("test gate")
            return actual(*args,**kwargs)
        with patch.object(jobs,"execute",controlled),ThreadPoolExecutor() as pool:
            future=pool.submit(self.upload)
            try:
                self.assertTrue(entered.wait(10))
                scan_id=self.client.get("/api/scans").json()["items"][0]["id"]
                self.assertEqual(self.client.get(f'/api/scans/{scan_id}').json()["status"],"running")
            finally:release.set()
            self.assertEqual(future.result(timeout=20).status_code,202)

class BinwalkTests(unittest.TestCase):
    def test_unavailable_does_not_silently_claim_extraction(self):
        with patch.dict(os.environ,{"FIRMGUARD_BINWALK_IMAGE":""}),self.assertRaises(AnalysisError) as caught:extract(b"raw")
        self.assertEqual(caught.exception.status,503)

    def test_container_command_and_output_revalidation(self):
        tar=tar_bytes([("firmguard-metadata.json",json.dumps({"notice":"Excluded links","tool":"binwalk 3.1.0"}).encode()),("binwalk/etc/a",b"password=dummy")])
        commands=[]
        class Process:
            returncode=0
            def __init__(self,args,stdout,stderr):commands.append(args);stdout.write(tar);stdout.flush()
            def poll(self):return 0
            def wait(self,**kwargs):return 0
        with patch.dict(os.environ,{"FIRMGUARD_BINWALK_IMAGE":"local-test:3"}),patch("binwalk_adapter.shutil.which",return_value="docker"),patch("binwalk_adapter.subprocess.Popen",Process),patch("binwalk_adapter.subprocess.run"):
            items,info=extract(b"raw")
        self.assertEqual(items[0].path,"binwalk/etc/a")
        for flag in ["--network=none","--read-only","--cap-drop=ALL","--security-opt=no-new-privileges","--user=65534:65534","--pull=never","--rm"]:
            self.assertIn(flag,commands[0])
        self.assertNotIn("--privileged",commands[0])

    def test_timeout_kills_client_and_removes_container(self):
        process=unittest.mock.Mock()
        process.poll.return_value=None
        with patch.dict(os.environ,{"FIRMGUARD_BINWALK_IMAGE":"local:3"}),patch("binwalk_adapter.shutil.which",return_value="docker"),patch("binwalk_adapter.subprocess.Popen",return_value=process),patch("binwalk_adapter.subprocess.run") as cleanup,patch("binwalk_adapter.BINWALK_TIMEOUT",-1),self.assertRaises(AnalysisError):
            extract(b"raw")
        process.kill.assert_called_once();cleanup.assert_called_once()
        self.assertEqual(cleanup.call_args.args[0][:3],["docker","rm","-f"])

class WorkerAndHistoryTests(unittest.TestCase):
    def test_worker_timeout_kills_process(self):
        process=unittest.mock.Mock();process.poll.return_value=None
        with patch.object(jobs.subprocess,"Popen",return_value=process),patch.object(jobs,"JOB_TIMEOUT",-1),self.assertRaises(AnalysisError) as caught:
            jobs.execute(b"data",{"filename":"file"})
        self.assertIn("time limit",caught.exception.message)
        process.kill.assert_called_once();process.wait.assert_called_once()

    def test_revision_allocation_is_transactional(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(history,"DB_PATH",Path(directory)/"db.sqlite"):
            with history.connection():pass
            with ThreadPoolExecutor(max_workers=4) as pool:
                ids=list(pool.map(lambda _:history.create_scan("Device","v1",{"filename":"file"}),range(8)))
            self.assertEqual(sorted(history.get_scan(i)["revision"] for i in ids),list(range(1,9)))

    def test_database_migration_preserves_existing_record(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(history,"DB_PATH",Path(directory)/"db.sqlite"):
            with closing(sqlite3.connect(history.DB_PATH)) as db, db:
                db.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY,device TEXT,version TEXT,created_at TEXT,status TEXT,stage TEXT,progress INTEGER,result_json TEXT,events_json TEXT,error TEXT)")
                db.execute("INSERT INTO scans VALUES (1,'A','v1','2024','completed','Completed',100,'{}','[]',NULL)")
            self.assertEqual(history.get_scan(1)["status"],"completed")
            new=history.create_scan("A","v1",{})
            self.assertEqual(history.get_scan(new)["revision"],2)

if __name__ == "__main__":unittest.main()
