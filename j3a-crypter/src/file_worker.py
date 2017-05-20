import codecs
import io
import json
import os
import sys

class FileWorker(object):
    """ File worker - easy file loading 
    There can be a problem with encoding, so we have to try open file as standard
    UTF-8 and as a UTF-8 with BOM.
    """

    def open_file(self, file):
        """ Open specified file """
        
        input_file = self.try_open_as_utf8(file)
        
        if input_file == None:
           input_file = self.try_open_as_utf8_bom(file)

        return input_file

    def open_json_file(self, file):
        """ Open specified file and load it as JSON object """

        input_json_file = None

        # First try open as standard UTF-8 (not BOM)
        try:
            input_file = self.try_open_as_utf8(file)
            input_json_file = json.load(input_file)
        except:
            input_json_file = None

        # Second try open as UTF-8 BOM if firt try fails
        if input_json_file == None:
            try:
                input_file = self.try_open_as_utf8_bom(file)
                input_json_file = json.load(input_file)
            except:
                input_json_file = None

        return input_json_file

    def try_open_as_utf8(self, file):
        """ Method tries open file in utf-8 encoding """
        
        try:
            input_file = codecs.open(file, 'r', 'utf-8')
        except:
            return None
        
        return input_file

    def try_open_as_utf8_bom(self, file):
        """ Method tries open file in utf-8 bom encoding """
        
        try:
            input_file = codecs.open(file, 'r', 'utf-8-sig')
        except:
            return None
        
        return input_file