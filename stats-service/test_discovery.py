import struct
import unittest
from discovery import question, ptr_answers, clean_name

class DiscoveryTests(unittest.TestCase):
    def test_compressed_ptr_and_truncated_packet(self):
        owner,q=question('192.168.50.6')
        name=b'\x07MacBook\x05local\0'
        packet=struct.pack('!6H',42,0x8400,1,1,0,0)+q+b'\xc0\x0c'+struct.pack('!HHIH',12,1,120,len(name))+name
        self.assertEqual(ptr_answers(packet),{owner:'MacBook.local'})
        self.assertEqual(ptr_answers(packet[:-5]),{})
        self.assertEqual(ptr_answers(b'\0'*12+b'\xc0\x0c'),{})

    def test_names_are_cleaned_without_inventing_unknowns(self):
        self.assertEqual(clean_name('工作电脑.local.'),'工作电脑')
        for value in ['unknown','localhost','*','bad\x00name','x'*101]:
            self.assertEqual(clean_name(value),'')
